#include "policy/http_front.hpp"

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "policy/affinity.hpp"
#include "policy/coarse_clock.hpp"
#include "policy/cycles.hpp"
#include "policy/engine.hpp"
#include "policy/imsi.hpp"
#include "policy/logging.hpp"

namespace policy {
namespace {

constexpr std::size_t kMaxConnectionsPerWorker = 4096;
constexpr std::size_t kRequestBufferBytes = 4096;
constexpr std::size_t kResponseBufferBytes = 1024;
constexpr int kIdleTimeoutMs = 30000;

constexpr std::string_view kEndpoint = "/v1/decide";

// Fast unsigned parse over a string_view, with no allocation and no locale.
[[nodiscard]] bool parse_u64_sv(std::string_view s, std::uint64_t& out) noexcept {
  if (s.empty() || s.size() > 20) return false;
  std::uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<std::uint64_t>(c - '0');
  }
  out = v;
  return true;
}

// Iterate `k=v` pairs. No percent-decoding: the decision endpoint's parameters
// are digits and short identifiers, and silently accepting an encoded value
// that the DNN table then fails to match would be worse than rejecting it.
template <typename Fn>
void for_each_param(std::string_view query, Fn&& fn) {
  std::size_t start = 0;
  while (start <= query.size()) {
    const auto amp = query.find('&', start);
    const std::string_view pair =
        query.substr(start, amp == std::string_view::npos ? std::string_view::npos : amp - start);
    if (!pair.empty()) {
      const auto eq = pair.find('=');
      if (eq == std::string_view::npos) {
        fn(pair, std::string_view{});
      } else {
        fn(pair.substr(0, eq), pair.substr(eq + 1));
      }
    }
    if (amp == std::string_view::npos) break;
    start = amp + 1;
  }
}

}  // namespace

std::size_t decision_to_json(const PolicyDecision& d, char* out, std::size_t cap) noexcept {
  // snprintf into a caller-owned buffer rather than building a std::string:
  // this runs once per request and must not allocate.
  const int n = std::snprintf(
      out, cap,
      "{\"verdict\":\"%s\",\"reason\":\"%s\",\"rule_id\":%u,\"policy_version\":%u,"
      "\"qos_5qi\":%u,\"arp\":%u,\"ambr_ul_kbps\":%u,\"ambr_dl_kbps\":%u,"
      "\"rating_group\":%u,\"quota_bytes\":%llu,\"quota_validity_s\":%u,"
      "\"flags\":%u,\"redirect_id\":%u}\n",
      verdict_name(static_cast<Verdict>(d.verdict)), reason_name(static_cast<Reason>(d.reason)),
      d.rule_id, d.policy_version, d.qos_5qi, d.arp, d.ambr_ul_kbps, d.ambr_dl_kbps,
      d.rating_group, static_cast<unsigned long long>(d.quota_bytes), d.quota_validity_s,
      d.flags, d.redirect_id);
  if (n < 0 || static_cast<std::size_t>(n) >= cap) return 0;
  return static_cast<std::size_t>(n);
}

bool parse_decide_query(const RuleSet& rs, std::string_view query, PolicyRequest& out,
                        std::string& error) {
  out = PolicyRequest{};
  out.magic_version = kMagicVersion;
  out.requested_5qi = 9;
  out.local_minute = 720;

  bool have_imsi = false;
  bool bad = false;
  std::string_view bad_key;

  for_each_param(query, [&](std::string_view key, std::string_view value) {
    if (bad) return;
    std::uint64_t n = 0;
    if (key == "imsi") {
      const auto imsi = parse_imsi(value);
      if (!imsi || *imsi == 0) { bad = true; bad_key = key; return; }
      out.imsi = *imsi;
      have_imsi = true;
    } else if (key == "imei") {
      const auto imei = parse_imei(value);
      if (!imei) { bad = true; bad_key = key; return; }
      out.imei = *imei;
    } else if (key == "plmn") {
      const auto plmn = parse_plmn(value);
      if (!plmn) { bad = true; bad_key = key; return; }
      out.plmn = *plmn;
    } else if (key == "dnn") {
      // Accept the name or the index. The name is what a developer writes; the
      // index is what a machine-generated client would send.
      const auto it = std::find(rs.dnn_names.begin(), rs.dnn_names.end(), value);
      if (it != rs.dnn_names.end()) {
        out.dnn_id = static_cast<std::uint8_t>(std::distance(rs.dnn_names.begin(), it));
      } else if (parse_u64_sv(value, n) && n < rs.dnn_names.size()) {
        out.dnn_id = static_cast<std::uint8_t>(n);
      } else {
        bad = true; bad_key = key;
      }
    } else if (key == "rat") {
      if (value == "LTE" || value == "lte" || value == "4G") out.rat_type = 0;
      else if (value == "NR" || value == "nr" || value == "5G") out.rat_type = 1;
      else if (value == "WLAN" || value == "wlan" || value == "wifi") out.rat_type = 2;
      else if (parse_u64_sv(value, n) && n < 3) out.rat_type = static_cast<std::uint8_t>(n);
      else { bad = true; bad_key = key; }
    } else if (key == "qos_5qi") {
      if (!parse_u64_sv(value, n) || n == 0 || n > 255) { bad = true; bad_key = key; return; }
      out.requested_5qi = static_cast<std::uint8_t>(n);
    } else if (key == "tac") {
      if (!parse_u64_sv(value, n) || n > 65535) { bad = true; bad_key = key; return; }
      out.tac = static_cast<std::uint16_t>(n);
    } else if (key == "minute") {
      if (!parse_u64_sv(value, n) || n > 1439) { bad = true; bad_key = key; return; }
      out.local_minute = static_cast<std::uint16_t>(n);
    } else if (key == "usage") {
      if (!parse_u64_sv(value, n)) { bad = true; bad_key = key; return; }
      out.bytes_used_period = n;
      out.flags |= kReqFlagUsageValid;
    } else if (key == "tethering") {
      if (value != "0" && value != "false") out.flags |= kReqFlagTetheringDetected;
    } else if (key == "emergency") {
      if (value != "0" && value != "false") out.flags |= kReqFlagEmergency;
    } else if (key == "seq") {
      if (parse_u64_sv(value, n)) out.seq = static_cast<std::uint32_t>(n);
    } else {
      bad = true;
      bad_key = key;
    }
  });

  if (bad) {
    error = "invalid or unknown parameter '" + std::string(bad_key) + "'";
    return false;
  }
  if (!have_imsi) {
    error = "imsi is required";
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------
namespace {

struct Connection {
  int fd = -1;
  std::size_t in_len = 0;
  std::size_t out_len = 0;
  std::size_t out_sent = 0;
  std::uint64_t last_active_ns = 0;
  bool close_after_write = false;
  std::vector<char> in;
  std::vector<char> out;

  Connection() : in(kRequestBufferBytes), out(kResponseBufferBytes) {}
};

}  // namespace

struct HttpFrontServer::Worker {
  Stats stats;
  std::vector<Connection> conns;
  std::vector<pollfd> pfds;
};

HttpFrontServer::HttpFrontServer(const ServerConfig& cfg, ServerDeps deps, std::string bind_address,
                                 std::uint16_t port)
    : cfg_(cfg), deps_(deps), bind_address_(std::move(bind_address)), port_(port) {}

HttpFrontServer::~HttpFrontServer() {
  request_stop();
  join();
}

std::string HttpFrontServer::description() const {
  std::string d = "HTTP/1.1 GET " + std::string(kEndpoint) + ", keep-alive, ";
  d += have_per_worker_sockets() ? "SO_REUSEPORT listener per worker" : "one shared listener";
  return d;
}

bool HttpFrontServer::start(std::string& error) {
  const std::size_t workers = cfg_.worker_threads;
  const std::size_t listener_count = have_per_worker_sockets() ? workers : 1;

  for (std::size_t i = 0; i < listener_count; ++i) {
    sockaddr_in addr{};
    if (!resolve_v4(bind_address_, port_, addr, error)) return false;

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      error = std::string("http front socket(): ") + std::strerror(errno);
      return false;
    }
    Socket sock(fd);

    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    if (have_per_worker_sockets()) ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
      error = "http front bind(" + bind_address_ + ":" + std::to_string(port_) + "): " +
              std::strerror(errno);
      return false;
    }
    if (::listen(fd, 1024) != 0) {
      error = std::string("http front listen(): ") + std::strerror(errno);
      return false;
    }

    if (bound_port_ == 0) {
      sockaddr_in bound{};
      socklen_t blen = sizeof(bound);
      if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
        bound_port_ = ntohs(bound.sin_port);
      }
      // Every worker must bind the SAME port, so a kernel-assigned one has to
      // be resolved before the remaining listeners are created.
      if (port_ == 0) port_ = bound_port_;
    }
    listeners_.push_back(std::move(sock));
  }

  stop_.store(false, std::memory_order_release);
  workers_.reserve(workers);
  for (std::size_t i = 0; i < workers; ++i) workers_.push_back(std::make_unique<Worker>());

  threads_.reserve(workers);
  for (std::size_t i = 0; i < workers; ++i) {
    const int fd = listeners_[have_per_worker_sockets() ? i : 0].fd();
    threads_.emplace_back([this, i, fd] { worker_loop(i, fd); });
  }
  return true;
}

void HttpFrontServer::request_stop() { stop_.store(true, std::memory_order_release); }

void HttpFrontServer::join() {
  for (auto& t : threads_) {
    if (t.joinable()) t.join();
  }
  threads_.clear();
  listeners_.clear();
}

HttpFrontServer::Stats HttpFrontServer::snapshot() const {
  Stats s;
  for (const auto& w : workers_) {
    s.connections_accepted += w->stats.connections_accepted;
    s.requests += w->stats.requests;
    s.bad_requests += w->stats.bad_requests;
    s.not_found += w->stats.not_found;
    s.connections_closed += w->stats.connections_closed;
    s.service_ns.add(w->stats.service_ns);
  }
  return s;
}

void HttpFrontServer::worker_loop(std::size_t index, int listen_fd) {
  name_current_thread("policy-h" + std::to_string(index));
  if (cfg_.pin_workers) {
    std::string detail;
    pin_current_thread(cfg_.first_core + static_cast<unsigned>(index), detail);
  }

  Worker& w = *workers_[index];
  w.conns.reserve(kMaxConnectionsPerWorker);
  w.pfds.reserve(kMaxConnectionsPerWorker + 1);

  RcuDomain<RuleSet>& rules = *deps_.rules;
  const SubscriberStore& store = *deps_.store;
  const std::size_t rcu_slot = rules.register_reader();
  if (rcu_slot == static_cast<std::size_t>(-1)) {
    LOG_ERROR("http front worker %zu could not claim an RCU reader slot", index);
    return;
  }

  // Swap-remove. The loop below walks connections downwards, so the element
  // moved into slot i has already been processed this round and cannot be
  // visited twice. Moved rather than copied: a Connection owns two buffers and
  // copying them would be five kilobytes per close for no reason.
  auto close_conn = [&](std::size_t i) {
    ::close(w.conns[i].fd);
    ++w.stats.connections_closed;
    w.conns[i] = std::move(w.conns.back());
    w.conns.pop_back();
  };

  while (!stop_.load(std::memory_order_relaxed)) {
    w.pfds.clear();
    pollfd lp{};
    lp.fd = listen_fd;
    lp.events = POLLIN;
    w.pfds.push_back(lp);
    for (const auto& c : w.conns) {
      pollfd p{};
      p.fd = c.fd;
      p.events = static_cast<short>(c.out_len > c.out_sent ? POLLOUT : POLLIN);
      w.pfds.push_back(p);
    }

    const int rc = ::poll(w.pfds.data(), static_cast<nfds_t>(w.pfds.size()), 100);
    if (rc < 0) {
      if (errno == EINTR) continue;
      LOG_WARN("http front worker %zu poll: %s", index, std::strerror(errno));
      continue;
    }

    // Accept whatever is pending. Bounded so one worker cannot monopolize the
    // backlog while its existing connections starve.
    if (rc > 0 && (w.pfds[0].revents & POLLIN) != 0) {
      for (int n = 0; n < 64 && w.conns.size() < kMaxConnectionsPerWorker; ++n) {
        const int client = ::accept(listen_fd, nullptr, nullptr);
        if (client < 0) break;
        int one = 1;
        ::setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        const int flags = ::fcntl(client, F_GETFL, 0);
        ::fcntl(client, F_SETFL, flags | O_NONBLOCK);
        w.conns.emplace_back();
        w.conns.back().fd = client;
        w.conns.back().last_active_ns = cycles_now_ns();
        ++w.stats.connections_accepted;
      }
    }

    const auto guard = rules.read(rcu_slot);
    const RuleSet* rs = guard.get();
    const std::uint64_t now_ns = cycles_now_ns();

    for (std::size_t i = w.conns.size(); i-- > 0;) {
      Connection& c = w.conns[i];
      const std::size_t pi = i + 1;
      if (pi >= w.pfds.size() || w.pfds[pi].fd != c.fd) continue;
      const short re = w.pfds[pi].revents;

      if ((re & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        close_conn(i);
        continue;
      }

      // --- flush a pending response ---
      if (c.out_len > c.out_sent) {
        if ((re & POLLOUT) == 0) {
          if (now_ns - c.last_active_ns > static_cast<std::uint64_t>(kIdleTimeoutMs) * 1'000'000ull) {
            close_conn(i);
          }
          continue;
        }
        const ssize_t n = ::send(c.fd, c.out.data() + c.out_sent, c.out_len - c.out_sent, 0);
        if (n <= 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
          close_conn(i);
          continue;
        }
        c.out_sent += static_cast<std::size_t>(n);
        c.last_active_ns = now_ns;
        if (c.out_sent >= c.out_len) {
          c.out_len = c.out_sent = 0;
          if (c.close_after_write) close_conn(i);
        }
        continue;
      }

      // --- read ---
      if ((re & POLLIN) == 0) {
        if (now_ns - c.last_active_ns > static_cast<std::uint64_t>(kIdleTimeoutMs) * 1'000'000ull) {
          close_conn(i);
        }
        continue;
      }

      const ssize_t n = ::recv(c.fd, c.in.data() + c.in_len, c.in.size() - c.in_len, 0);
      if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        close_conn(i);
        continue;
      }
      c.in_len += static_cast<std::size_t>(n);
      c.last_active_ns = now_ns;

      const std::string_view buf(c.in.data(), c.in_len);
      const auto head_end = buf.find("\r\n\r\n");
      if (head_end == std::string_view::npos) {
        if (c.in_len >= c.in.size()) {
          // A request bigger than the buffer is not one this endpoint serves.
          ++w.stats.bad_requests;
          close_conn(i);
        }
        continue;
      }

      // --- one request, start to finish ---
      const std::uint64_t t0 = rdcycles();

      const std::string_view head = buf.substr(0, head_end);
      const auto line_end = head.find("\r\n");
      const std::string_view request_line = head.substr(0, line_end);

      int status = 200;
      const char* status_text = "OK";
      std::size_t body_len = 0;
      char body[kResponseBufferBytes];

      const auto sp1 = request_line.find(' ');
      const auto sp2 = sp1 == std::string_view::npos
                           ? std::string_view::npos
                           : request_line.find(' ', sp1 + 1);
      if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
        status = 400;
        status_text = "Bad Request";
        body_len = static_cast<std::size_t>(
            std::snprintf(body, sizeof(body), "{\"error\":\"malformed request line\"}\n"));
        ++w.stats.bad_requests;
      } else {
        const std::string_view method = request_line.substr(0, sp1);
        const std::string_view target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
        const auto q = target.find('?');
        const std::string_view path = q == std::string_view::npos ? target : target.substr(0, q);
        const std::string_view query =
            q == std::string_view::npos ? std::string_view{} : target.substr(q + 1);

        if (path != kEndpoint) {
          status = 404;
          status_text = "Not Found";
          body_len = static_cast<std::size_t>(
              std::snprintf(body, sizeof(body), "{\"error\":\"no such endpoint\"}\n"));
          ++w.stats.not_found;
        } else if (method != "GET") {
          status = 405;
          status_text = "Method Not Allowed";
          body_len = static_cast<std::size_t>(
              std::snprintf(body, sizeof(body), "{\"error\":\"use GET\"}\n"));
          ++w.stats.bad_requests;
        } else if (rs == nullptr) {
          status = 503;
          status_text = "Service Unavailable";
          body_len = static_cast<std::size_t>(
              std::snprintf(body, sizeof(body), "{\"error\":\"no policy loaded\"}\n"));
        } else {
          PolicyRequest req;
          std::string parse_error;
          if (!parse_decide_query(*rs, query, req, parse_error)) {
            status = 400;
            status_text = "Bad Request";
            body_len = static_cast<std::size_t>(std::snprintf(
                body, sizeof(body), "{\"error\":\"%s\"}\n", parse_error.c_str()));
            ++w.stats.bad_requests;
          } else {
            const SubscriberRecord* rec = store.find(req.imsi);
            if (req.plmn == 0) req.plmn = rec != nullptr ? rec->home_plmn : 0;
            const PolicyDecision d = evaluate(*rs, req, rec);
            body_len = decision_to_json(d, body, sizeof(body));
            ++w.stats.requests;
          }
        }
      }

      const bool keep_alive = head.find("close") == std::string_view::npos;
      const int written = std::snprintf(
          c.out.data(), c.out.size(),
          "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
          "Connection: %s\r\n\r\n",
          status, status_text, body_len, keep_alive ? "keep-alive" : "close");
      if (written > 0 && static_cast<std::size_t>(written) + body_len < c.out.size()) {
        std::memcpy(c.out.data() + written, body, body_len);
        c.out_len = static_cast<std::size_t>(written) + body_len;
      } else {
        c.out_len = 0;
      }
      c.out_sent = 0;
      c.close_after_write = !keep_alive;

      w.stats.service_ns.record(cycles_to_ns_i(rdcycles() - t0));

      // Consume the request. Anything after it is the start of the next one
      // (a pipelined client), so it is kept rather than discarded.
      const std::size_t consumed = head_end + 4;
      c.in_len -= consumed;
      if (c.in_len > 0) std::memmove(c.in.data(), c.in.data() + consumed, c.in_len);

      // Write immediately rather than waiting for the next poll: with
      // TCP_NODELAY and a response that fits one segment this almost always
      // completes, and it removes a full poll cycle from the latency.
      if (c.out_len > 0) {
        const ssize_t s = ::send(c.fd, c.out.data(), c.out_len, 0);
        if (s > 0) {
          c.out_sent = static_cast<std::size_t>(s);
          if (c.out_sent >= c.out_len) {
            c.out_len = c.out_sent = 0;
            if (c.close_after_write) close_conn(i);
          }
        } else if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
          close_conn(i);
        }
      }
    }
  }

  for (const auto& c : w.conns) ::close(c.fd);
  w.conns.clear();
  rules.unregister_reader(rcu_slot);
  LOG_INFO("http front worker %zu stopped after %llu requests", index,
           static_cast<unsigned long long>(w.stats.requests));
}

}  // namespace policy
