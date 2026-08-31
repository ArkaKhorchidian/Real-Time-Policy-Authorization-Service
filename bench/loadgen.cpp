// Open-loop load generator.
//
// The measurement discipline here is the point of the project, so it is worth
// being explicit about what this does and why.
//
// COORDINATED OMISSION. A closed-loop client — send, wait for the reply, send
// the next — stops issuing work exactly when the server is slow. The requests
// it did not send are the ones that would have been slowest, so they never
// appear in the histogram, and the reported tail is a description of the
// client's backoff rather than the server's latency. This generator instead
// issues requests on a fixed schedule: at 100k QPS, one every 10 µs, whether or
// not previous replies have come back. Latency for each request is
//
//     recv_timestamp - SCHEDULED send time
//
// not `recv - actual send`. If the generator itself falls behind schedule, that
// delay is charged to the measurement, exactly as a real caller would
// experience it, and it is also reported separately as `send_lateness` so a run
// where the generator was the bottleneck is visible rather than silently wrong.
//
// `--closed-loop` runs the naive scheme on purpose, so the difference between
// the two can be shown as a number instead of asserted.
//
// LOSS. Percentiles are computed over replies actually received. A run that
// lost datagrams is reported as such and marked degraded — a p99 over a sample
// that is missing its slowest 2% is not a p99.
//
// PLACEMENT. The generator's threads are pinned to cores disjoint from the
// server's when both run on one box (see bench/run.sh). Sharing a core with the
// thing you are measuring produces a latency figure that is mostly scheduler.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <chrono>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "policy/affinity.hpp"
#include "policy/coarse_clock.hpp"
#include "policy/build_config.hpp"
#include "policy/cycles.hpp"
#include "policy/hdr_histogram.hpp"
#include "policy/imsi.hpp"
#include "policy/net.hpp"
#include "policy/request_gen.hpp"
#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"
#include "policy/wire.hpp"

namespace {

using namespace policy;

// Which wire protocol to drive. The binary UDP path is the one this project
// optimizes; the HTTP path exists so protocol overhead is a measured number
// rather than an assertion.
enum class Protocol { kUdpBinary, kHttpJson };

struct Options {
  std::string host = "127.0.0.1";
  std::uint16_t port = 9500;
  Protocol protocol = Protocol::kUdpBinary;
  // HTTP is request/response over a stream, so an open-loop client needs a pool
  // of connections: one request outstanding per connection. When every
  // connection is busy the schedule backs up, and because each request carries
  // its ORIGINAL scheduled time, that wait lands in the latency where it
  // belongs instead of disappearing.
  std::uint32_t connections = 64;
  std::uint64_t qps = 100000;
  std::uint32_t duration_s = 10;
  std::uint32_t warmup_s = 2;
  std::uint32_t threads = 1;
  std::uint32_t first_core = 0;
  bool pin = true;
  bool closed_loop = false;
  std::uint32_t timeout_ms = 200;
  std::uint32_t max_inflight = 1 << 16;  // per thread; power of two
  std::uint64_t seed = 0x5EED1234;
  std::string rules_path = "config/rules.yaml";
  std::string subscribers_path = "config/subscribers.csv";
  std::string out_prefix;   // empty = no files, summary to stderr only
  std::string tag;          // free-form label recorded in the CSV
  std::string summary_csv;  // appended one-line-per-run summary
  bool timeline = false;    // per-second CSV, for the hot-reload overlay
  std::uint32_t batch_recv = 32;
};

void usage(const char* argv0) {
  std::printf(
      "Open-loop load generator for policyd.\n"
      "\n"
      "Usage: %s [options]\n"
      "\n"
      "Target:\n"
      "  --server HOST:PORT     Server to drive (default 127.0.0.1:9500)\n"
      "  --protocol udp|http    Wire protocol (default udp). 'http' drives the HTTP front\n"
      "                         on its own port; the difference between the two is the\n"
      "                         protocol overhead, in microseconds.\n"
      "  --connections N        HTTP mode: persistent connections per thread (default 64)\n"
      "  --qps N                Total offered load, requests/second (default 100000)\n"
      "  --duration S           Measurement window in seconds (default 10)\n"
      "  --warmup S             Unmeasured warm-up before it (default 2)\n"
      "  --threads N            Generator threads; load is split evenly (default 1)\n"
      "  --first-core N         Core index for generator thread 0 (default 0)\n"
      "  --no-pin               Do not pin generator threads\n"
      "\n"
      "Method:\n"
      "  --closed-loop          Send-wait-send instead of a fixed schedule. Demonstrates\n"
      "                         coordinated omission; not a valid latency measurement.\n"
      "  --timeout-ms N         Treat a reply as lost after this long (default 200)\n"
      "  --max-inflight N       Per-thread outstanding-request table size (default 65536)\n"
      "  --batch-recv N         Replies to drain per receive pass (default 32)\n"
      "\n"
      "Traffic:\n"
      "  --rules PATH           Rules file, for the DNN table and IMEI blocklist\n"
      "  --subscribers PATH     Subscriber CSV, for the IMSI pool\n"
      "  --seed N               PRNG seed for the request mix\n"
      "\n"
      "Output:\n"
      "  --out-prefix PATH      Write PATH.hdr.csv and (with --timeline) PATH.timeline.csv\n"
      "  --summary-csv PATH     Append a one-line summary row to this file\n"
      "  --tag TEXT             Label recorded in the summary row\n"
      "  --timeline             Emit per-second latency and throughput\n"
      "  -h, --help             This message\n",
      argv0);
}

// Per-thread result. Merged after the run; never touched while running.
struct ThreadResult {
  HdrHistogram latency{1, 60'000'000'000LL, 3};   // ns, up to 60 s
  HdrHistogram send_lateness{1, 60'000'000'000LL, 3};
  std::uint64_t sent = 0;
  std::uint64_t received = 0;
  // Replies received inside the measurement window. Achieved throughput is
  // computed from this, not from `received`, which also counts the warm-up.
  std::uint64_t measured_received = 0;
  std::uint64_t lost = 0;
  std::uint64_t send_errors = 0;
  std::uint64_t bad_replies = 0;
  std::uint64_t stale_replies = 0;  // arrived after being written off as lost
  std::uint64_t denied = 0;
  std::uint64_t allowed = 0;
  std::uint64_t redirected = 0;
  std::uint64_t schedule_slips = 0;  // schedule fell more than one interval behind
  std::uint64_t max_slip_ns = 0;
  std::uint64_t connection_starved = 0;  // HTTP: a send was due but no connection was free
  std::uint64_t reconnects = 0;          // HTTP: a stream was reset after a timeout
  std::vector<std::uint64_t> per_second_count;
  std::vector<std::uint64_t> per_second_p99_ns;
};

// One outstanding request. `scheduled_ns` is the number that matters; the
// actual send time is kept only so lateness can be reported separately.
struct InFlight {
  std::uint64_t scheduled_ns = 0;
  std::uint64_t sent_ns = 0;
  bool live = false;
};

std::atomic<bool> g_stop{false};

// Read just the IMSI column. Loading the whole roster into a store would work
// but costs 64 bytes per subscriber in a process that only needs the keys.
std::vector<std::uint64_t> load_imsi_pool(const std::string& path, std::string& error) {
  std::vector<std::uint64_t> out;
  std::ifstream in(path);
  if (!in) {
    error = "cannot open " + path;
    return out;
  }
  std::string line;
  bool first = true;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    if (first) {
      first = false;
      if (line.compare(0, 4, "imsi") == 0) continue;
    }
    const auto comma = line.find(',');
    const auto imsi = parse_imsi(line.substr(0, comma == std::string::npos ? line.size() : comma));
    if (imsi && *imsi != 0) out.push_back(*imsi);
  }
  if (out.empty()) error = path + " contains no usable IMSIs";
  return out;
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------
//
// One outstanding request per connection, which is what HTTP/1.1 without
// pipelining allows. A pool of them gives the concurrency an open-loop client
// needs; when the pool is exhausted the schedule backs up rather than the
// requests being quietly dropped, and each request still carries the time it
// was SUPPOSED to be sent, so the wait shows up in the latency.
class HttpPool {
 public:
  struct Conn {
    int fd = -1;
    bool busy = false;
    std::uint32_t seq = 0;
    std::uint64_t scheduled_ns = 0;
    std::uint64_t issued_ns = 0;
    std::vector<char> in;
    std::size_t in_len = 0;
    std::size_t header_end = 0;   // index just past "\r\n\r\n", 0 = not yet seen
    std::size_t content_len = 0;

    Conn() : in(4096) {}
  };

  HttpPool(const sockaddr_in& target, std::uint32_t count) : target_(target), conns_(count) {}

  ~HttpPool() {
    for (auto& c : conns_) {
      if (c.fd >= 0) ::close(c.fd);
    }
  }

  bool open(std::string& error) {
    host_header_ = format_addr(target_);
    for (auto& c : conns_) {
      if (!connect_one(c, error)) return false;
    }
    return true;
  }

  [[nodiscard]] std::size_t size() const { return conns_.size(); }
  [[nodiscard]] Conn& at(std::size_t i) { return conns_[i]; }

  // Claim a free connection and issue `req` on it. Returns false when every
  // connection is busy, or when the socket would block.
  bool issue(const PolicyRequest& req, std::uint32_t seq, std::uint64_t scheduled_ns,
             std::uint64_t now_ns) {
    const std::size_t n = conns_.size();
    for (std::size_t k = 0; k < n; ++k) {
      Conn& c = conns_[cursor_];
      cursor_ = (cursor_ + 1) % n;
      if (c.busy || c.fd < 0) continue;

      // The cheapest form HTTP can take: a GET with query parameters, no body,
      // keep-alive. Anything richer (JSON body, protobuf, HTTP/2 framing) only
      // costs more, which is what makes this comparison a lower bound on
      // protocol overhead rather than a strawman.
      char buf[512];
      const int len = std::snprintf(
          buf, sizeof(buf),
          "GET /v1/decide?imsi=%015llu&imei=%015llu&plmn=%u&dnn=%u&rat=%u&qos_5qi=%u"
          "&tac=%u&minute=%u&seq=%u%s%s%s HTTP/1.1\r\nHost: %s\r\n\r\n",
          static_cast<unsigned long long>(req.imsi), static_cast<unsigned long long>(req.imei),
          req.plmn, req.dnn_id, req.rat_type, req.requested_5qi, req.tac, req.local_minute, seq,
          (req.flags & kReqFlagTetheringDetected) ? "&tethering=1" : "",
          (req.flags & kReqFlagEmergency) ? "&emergency=1" : "",
          (req.flags & kReqFlagUsageValid) ? usage_param(req.bytes_used_period) : "",
          host_header_.c_str());
      if (len <= 0 || static_cast<std::size_t>(len) >= sizeof(buf)) return false;

      const ssize_t sent = ::send(c.fd, buf, static_cast<std::size_t>(len), 0);
      if (sent != len) return false;

      c.busy = true;
      c.seq = seq;
      c.scheduled_ns = scheduled_ns;
      c.issued_ns = now_ns;
      c.in_len = 0;
      c.header_end = 0;
      c.content_len = 0;
      return true;
    }
    return false;
  }

  // Poll every busy connection and report the ones that completed.
  // `on_complete(conn)` is called for each; the caller frees the slot.
  template <typename Fn>
  int drain(Fn&& on_complete) {
    pfds_.clear();
    idx_.clear();
    for (std::size_t i = 0; i < conns_.size(); ++i) {
      if (!conns_[i].busy || conns_[i].fd < 0) continue;
      pollfd p{};
      p.fd = conns_[i].fd;
      p.events = POLLIN;
      pfds_.push_back(p);
      idx_.push_back(i);
    }
    if (pfds_.empty()) return 0;
    if (::poll(pfds_.data(), static_cast<nfds_t>(pfds_.size()), 0) <= 0) return 0;

    int completed = 0;
    for (std::size_t k = 0; k < pfds_.size(); ++k) {
      if ((pfds_[k].revents & POLLIN) == 0) continue;
      Conn& c = conns_[idx_[k]];
      const ssize_t n = ::recv(c.fd, c.in.data() + c.in_len, c.in.size() - c.in_len, 0);
      if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        c.busy = false;  // the peer closed; the caller counts it as loss
        ::close(c.fd);
        c.fd = -1;
        continue;
      }
      c.in_len += static_cast<std::size_t>(n);
      if (response_complete(c)) {
        on_complete(c);
        c.busy = false;
        c.in_len = 0;
        ++completed;
      } else if (c.in_len >= c.in.size()) {
        // A response that fills the buffer without completing is not one this
        // client understands, and continuing would hand recv() a zero-length
        // buffer forever. Drop the connection; the timeout sweep reopens it.
        ::close(c.fd);
        c.fd = -1;
        c.busy = false;
        c.in_len = 0;
      }
    }
    return completed;
  }

  // Recycle a connection whose response never arrived. The stream is out of
  // sync at that point, so it is closed and reopened rather than reused.
  bool recycle(Conn& c, std::string& error) {
    if (c.fd >= 0) ::close(c.fd);
    c.fd = -1;
    c.busy = false;
    c.in_len = 0;
    return connect_one(c, error);
  }

 private:
  static const char* usage_param(std::uint64_t bytes) {
    static thread_local char buf[40];
    std::snprintf(buf, sizeof(buf), "&usage=%llu", static_cast<unsigned long long>(bytes));
    return buf;
  }

  bool connect_one(Conn& c, std::string& error) {
    c.fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (c.fd < 0) {
      error = std::string("socket(): ") + std::strerror(errno);
      return false;
    }
    int one = 1;
    ::setsockopt(c.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (::connect(c.fd, reinterpret_cast<const sockaddr*>(&target_), sizeof(target_)) != 0) {
      error = std::string("connect(): ") + std::strerror(errno);
      ::close(c.fd);
      c.fd = -1;
      return false;
    }
    // Non-blocking only after the connect, so startup stays simple and the
    // measured path never blocks.
    const int flags = ::fcntl(c.fd, F_GETFL, 0);
    ::fcntl(c.fd, F_SETFL, flags | O_NONBLOCK);
    c.busy = false;
    c.in_len = 0;
    return true;
  }

  static bool response_complete(Conn& c) {
    const std::string_view buf(c.in.data(), c.in_len);
    if (c.header_end == 0) {
      const auto end = buf.find("\r\n\r\n");
      if (end == std::string_view::npos) return false;
      c.header_end = end + 4;
      const auto cl = buf.find("Content-Length: ");
      c.content_len = cl == std::string_view::npos
                          ? 0
                          : static_cast<std::size_t>(std::strtoul(c.in.data() + cl + 16, nullptr, 10));
    }
    return c.in_len >= c.header_end + c.content_len;
  }

  sockaddr_in target_;
  std::vector<Conn> conns_;
  std::vector<pollfd> pfds_;
  std::vector<std::size_t> idx_;
  std::size_t cursor_ = 0;
  std::string host_header_;
};

class Sender {
 public:
  Sender(const Options& opt, std::size_t index, const sockaddr_in& target,
         std::vector<std::uint64_t> imsis, std::vector<std::uint64_t> blocked,
         std::vector<std::uint32_t> visited, std::uint8_t dnn_count)
      : opt_(opt),
        index_(index),
        target_(target),
        gen_(opt.seed + index * 0x9E3779B9ull, std::move(imsis), std::move(blocked),
             std::move(visited), dnn_count),
        inflight_(opt.max_inflight),
        mask_(opt.max_inflight - 1) {
    if (opt.protocol == Protocol::kHttpJson) {
      http_ = std::make_unique<HttpPool>(target, std::max(1u, opt.connections));
    }
  }

  ThreadResult& result() { return result_; }

  bool open(std::string& error) {
    if (opt_.protocol == Protocol::kHttpJson) return http_->open(error);

    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
      error = std::string("socket(): ") + std::strerror(errno);
      return false;
    }
    // A generously sized receive buffer: a burst of replies that overflows it
    // becomes "loss" in the report, which would be the generator's fault.
    int buf = 8 << 20;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    ::setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));

    // connect() on a UDP socket: the kernel then knows the peer, so send() skips
    // the route lookup per datagram and the socket only accepts replies from the
    // server. Both matter at 100k+ datagrams per second per thread.
    if (::connect(fd_, reinterpret_cast<const sockaddr*>(&target_), sizeof(target_)) != 0) {
      error = std::string("connect(): ") + std::strerror(errno);
      return false;
    }
    const int flags = ::fcntl(fd_, F_GETFL, 0);
    ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
    return true;
  }

  void run() {
    name_current_thread("loadgen-" + std::to_string(index_));
    if (opt_.pin) {
      std::string detail;
      pin_current_thread(opt_.first_core + static_cast<unsigned>(index_), detail);
    }

    if (opt_.closed_loop) {
      run_closed_loop();
    } else {
      run_open_loop();
    }
    if (fd_ >= 0) ::close(fd_);
  }

 private:
  // Issue one request. Returns false when the transport has no capacity right
  // now, in which case the caller must NOT advance the schedule -- the slot
  // stays pending and the eventual send still carries its original scheduled
  // time, so the wait is charged to the latency rather than hidden.
  bool issue(const PolicyRequest& req, std::uint32_t seq, std::uint64_t scheduled_ns,
             std::uint64_t now_ns, char* tx) {
    if (opt_.protocol == Protocol::kHttpJson) {
      if (!http_->issue(req, seq, scheduled_ns, now_ns)) {
        ++result_.connection_starved;
        return false;
      }
      return true;
    }
    encode(req, tx);
    const ssize_t n = ::send(fd_, tx, kWireMsgSize, 0);
    if (n != static_cast<ssize_t>(kWireMsgSize)) {
      ++result_.send_errors;
      return false;
    }
    return true;
  }

  // --- open loop ---------------------------------------------------------
  void run_open_loop() {
    const double per_thread_qps = static_cast<double>(opt_.qps) / opt_.threads;
    const double interval_ns = 1e9 / per_thread_qps;

    const std::uint64_t start_ns = cycles_now_ns();
    const std::uint64_t warmup_end_ns = start_ns + opt_.warmup_s * 1'000'000'000ull;
    const std::uint64_t end_ns = warmup_end_ns + opt_.duration_s * 1'000'000'000ull;
    const std::uint64_t timeout_ns = opt_.timeout_ms * 1'000'000ull;

    result_.per_second_count.assign(opt_.duration_s + 1, 0);
    result_.per_second_p99_ns.assign(opt_.duration_s + 1, 0);
    std::vector<HdrHistogram> per_second;
    if (opt_.timeline) {
      per_second.reserve(opt_.duration_s + 1);
      for (std::uint32_t i = 0; i <= opt_.duration_s; ++i) {
        per_second.emplace_back(1, 60'000'000'000LL, 3);
      }
    }

    double next_send_ns = static_cast<double>(start_ns);
    std::uint64_t sweep_at_ns = start_ns + timeout_ns;
    std::uint32_t seq = 0;

    alignas(64) char tx[kWireMsgSize];
    alignas(64) char rx[kWireMsgSize];

    while (!g_stop.load(std::memory_order_relaxed)) {
      const std::uint64_t now = cycles_now_ns();
      if (now >= end_ns) break;
      const bool measuring = now >= warmup_end_ns;

      // A completed reply, from either transport. `scheduled_ns` is the number
      // that matters; `recv_ns` is when it came back.
      auto complete = [&](std::uint64_t scheduled_ns, std::uint64_t recv_ns, bool in_window) {
        ++result_.received;
        if (!in_window) return;
        ++result_.measured_received;
        const auto latency_ns = static_cast<std::int64_t>(recv_ns - scheduled_ns);
        result_.latency.record(latency_ns);
        if (opt_.timeline) {
          const auto sec = static_cast<std::size_t>((recv_ns - warmup_end_ns) / 1'000'000'000ull);
          if (sec < per_second.size()) {
            per_second[sec].record(latency_ns);
            ++result_.per_second_count[sec];
          }
        }
      };

      // 1. Send everything the schedule says is due. The loop is bounded so a
      //    long stall cannot turn into an unbounded burst that would itself
      //    distort the next measurement.
      std::uint32_t burst = 0;
      while (static_cast<double>(now) >= next_send_ns && burst < 256) {
        const auto scheduled = static_cast<std::uint64_t>(next_send_ns);
        const std::uint64_t slip = now - scheduled;
        if (slip > static_cast<std::uint64_t>(interval_ns)) {
          ++result_.schedule_slips;
          result_.max_slip_ns = std::max(result_.max_slip_ns, slip);
        }

        PolicyRequest req;
        gen_.fill(req);
        if (req.plmn == 0) req.plmn = 310260;  // resolved against the roster's home network
        req.seq = seq;
        req.client_ts_ns = scheduled;

        const std::uint64_t issue_at = cycles_now_ns();
        if (!issue(req, seq, scheduled, issue_at, tx)) {
          // No capacity right now. Leave the schedule where it is: the slot is
          // still owed, and when it does go out it will carry this scheduled
          // time, so the wait ends up in the latency instead of vanishing.
          break;
        }

        if (opt_.protocol == Protocol::kUdpBinary) {
          InFlight& slot = inflight_[seq & mask_];
          if (slot.live) ++result_.lost;  // wrapped over an unanswered request
          slot.scheduled_ns = scheduled;
          slot.sent_ns = issue_at;
          slot.live = true;
        }
        ++result_.sent;
        if (measuring) {
          result_.send_lateness.record(static_cast<std::int64_t>(issue_at - scheduled));
        }

        ++seq;
        next_send_ns += interval_ns;
        ++burst;
      }

      // 2. Drain replies.
      if (opt_.protocol == Protocol::kHttpJson) {
        http_->drain([&](HttpPool::Conn& c) {
          const std::uint64_t recv_ns = cycles_now_ns();
          // The body is small and fixed-shape; a full JSON parse would be the
          // client measuring itself. Checking the verdict field is enough to
          // confirm the server answered rather than errored.
          const std::string_view body(c.in.data() + c.header_end, c.content_len);
          if (body.find("\"verdict\":\"ALLOW\"") != std::string_view::npos) ++result_.allowed;
          else if (body.find("\"verdict\":\"DENY\"") != std::string_view::npos) ++result_.denied;
          else if (body.find("\"verdict\":\"REDIRECT\"") != std::string_view::npos) ++result_.redirected;
          else { ++result_.bad_replies; return; }
          complete(c.scheduled_ns, recv_ns, measuring);
        });
      } else {
        for (std::uint32_t i = 0; i < opt_.batch_recv; ++i) {
          const ssize_t n = ::recv(fd_, rx, sizeof(rx), MSG_DONTWAIT);
          if (n < 0) break;
          const std::uint64_t recv_ns = cycles_now_ns();
          PolicyDecision dec;
          if (n != static_cast<ssize_t>(kWireMsgSize) ||
              !decode(rx, static_cast<std::size_t>(n), dec)) {
            ++result_.bad_replies;
            continue;
          }
          InFlight& slot = inflight_[dec.seq & mask_];
          if (!slot.live || slot.scheduled_ns != dec.client_ts_ns) {
            // Either a duplicate, or a reply to a request already written off.
            ++result_.stale_replies;
            continue;
          }
          slot.live = false;
          note_verdict(dec);
          complete(slot.scheduled_ns, recv_ns, measuring);
        }
      }

      // 3. Retire requests that are past the timeout. Sweeping the whole table
      //    every timeout interval is O(table) but happens a handful of times a
      //    second, versus a priority queue touched on every send.
      //
      //    The sweep takes its own timestamp rather than reusing `now` from the
      //    top of the iteration: requests sent during step 1 carry a `sent_ns`
      //    LATER than that cached `now`, and the unsigned subtraction below
      //    would wrap to a colossal age and write them off as lost microseconds
      //    after they were sent. The explicit ordering check makes that
      //    impossible even if the timestamps ever go backwards.
      if (now >= sweep_at_ns) {
        const std::uint64_t sweep_now = cycles_now_ns();
        if (opt_.protocol == Protocol::kHttpJson) {
          // A stream whose response never arrived is out of sync, so the
          // connection is closed and reopened rather than reused for the next
          // request — otherwise one timeout would corrupt every reply after it.
          std::string err;
          for (std::size_t i = 0; i < http_->size(); ++i) {
            HttpPool::Conn& c = http_->at(i);
            if (c.fd < 0) {
              if (http_->recycle(c, err)) ++result_.reconnects;
              continue;
            }
            if (c.busy && sweep_now > c.issued_ns && sweep_now - c.issued_ns > timeout_ns) {
              ++result_.lost;
              if (http_->recycle(c, err)) ++result_.reconnects;
            }
          }
        } else {
          for (auto& slot : inflight_) {
            if (slot.live && sweep_now > slot.sent_ns && sweep_now - slot.sent_ns > timeout_ns) {
              slot.live = false;
              ++result_.lost;
            }
          }
        }
        sweep_at_ns = sweep_now + timeout_ns;
      }

      // 4. If the next send is far enough away, yield rather than spin. The
      //    threshold is deliberately small: sleeping for the full interval
      //    would introduce timer granularity into the schedule.
      const double slack = next_send_ns - static_cast<double>(cycles_now_ns());
      if (slack > 50'000.0) {
        if (opt_.protocol == Protocol::kUdpBinary) {
          // Wait for a reply or for the next send, whichever is first.
          pollfd pfd{};
          pfd.fd = fd_;
          pfd.events = POLLIN;
          ::poll(&pfd, 1, static_cast<int>(std::min(slack / 1e6, 5.0)));
        } else {
          // HTTP mode polls its own connection set inside drain(), so here it
          // only needs to stop spinning. A short sleep costs less accuracy than
          // the timer granularity a longer one would introduce.
          std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
      }
    }

    // Final drain: replies still in flight when the window closed are not
    // counted as latency samples (they would be truncated), but they are not
    // counted as loss either.
    drain_tail();

    if (opt_.timeline) {
      for (std::size_t i = 0; i < per_second.size(); ++i) {
        result_.per_second_p99_ns[i] = static_cast<std::uint64_t>(
            per_second[i].value_at_percentile(99.0));
      }
    }
  }

  // --- closed loop (for comparison only) ---------------------------------
  //
  // UDP only. The point of this mode is to demonstrate coordinated omission,
  // and one transport is enough to demonstrate it.
  void run_closed_loop() {
    const std::uint64_t start_ns = cycles_now_ns();
    const std::uint64_t warmup_end_ns = start_ns + opt_.warmup_s * 1'000'000'000ull;
    const std::uint64_t end_ns = warmup_end_ns + opt_.duration_s * 1'000'000'000ull;
    result_.per_second_count.assign(opt_.duration_s + 1, 0);
    result_.per_second_p99_ns.assign(opt_.duration_s + 1, 0);

    alignas(64) char tx[kWireMsgSize];
    alignas(64) char rx[kWireMsgSize];
    std::uint32_t seq = 0;

    while (!g_stop.load(std::memory_order_relaxed)) {
      const std::uint64_t now = cycles_now_ns();
      if (now >= end_ns) break;
      const bool measuring = now >= warmup_end_ns;

      PolicyRequest req;
      gen_.fill(req);
      if (req.plmn == 0) req.plmn = 310260;
      req.seq = seq++;
      req.client_ts_ns = now;
      encode(req, tx);

      const std::uint64_t send_ns = cycles_now_ns();
      if (::send(fd_, tx, kWireMsgSize, 0) != static_cast<ssize_t>(kWireMsgSize)) {
        ++result_.send_errors;
        continue;
      }
      ++result_.sent;

      // Block for the reply. This is precisely the behaviour that hides tail
      // latency: while we wait, no new requests are offered, so a server stall
      // reduces the offered load instead of showing up in the histogram.
      pollfd pfd{};
      pfd.fd = fd_;
      pfd.events = POLLIN;
      if (::poll(&pfd, 1, static_cast<int>(opt_.timeout_ms)) <= 0) {
        ++result_.lost;
        continue;
      }
      const ssize_t n = ::recv(fd_, rx, sizeof(rx), MSG_DONTWAIT);
      const std::uint64_t recv_ns = cycles_now_ns();
      PolicyDecision dec;
      if (n != static_cast<ssize_t>(kWireMsgSize) || !decode(rx, static_cast<std::size_t>(n), dec)) {
        ++result_.bad_replies;
        continue;
      }
      ++result_.received;
      note_verdict(dec);
      if (measuring) {
        ++result_.measured_received;
        result_.latency.record(static_cast<std::int64_t>(recv_ns - send_ns));
      }
    }
  }

  // Requests still in flight when the window closed are given the full timeout
  // to come back. Without this the last few microseconds of every run would be
  // reported as loss, which at short durations is a visible and entirely
  // artificial error rate.
  void drain_tail() {
    if (opt_.protocol == Protocol::kHttpJson) {
      const std::uint64_t deadline = cycles_now_ns() + opt_.timeout_ms * 1'000'000ull;
      while (cycles_now_ns() < deadline) {
        std::size_t busy = 0;
        for (std::size_t i = 0; i < http_->size(); ++i) {
          if (http_->at(i).busy) ++busy;
        }
        if (busy == 0) return;
        http_->drain([&](HttpPool::Conn&) { ++result_.received; });
        std::this_thread::sleep_for(std::chrono::microseconds(200));
      }
      for (std::size_t i = 0; i < http_->size(); ++i) {
        if (http_->at(i).busy) ++result_.lost;
      }
      return;
    }

    alignas(64) char rx[kWireMsgSize];
    const std::uint64_t deadline = cycles_now_ns() + opt_.timeout_ms * 1'000'000ull;
    while (cycles_now_ns() < deadline) {
      if (outstanding() == 0) break;
      const ssize_t n = ::recv(fd_, rx, sizeof(rx), MSG_DONTWAIT);
      if (n < 0) {
        pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLIN;
        if (::poll(&pfd, 1, 5) <= 0) continue;
        continue;
      }
      PolicyDecision dec;
      if (n == static_cast<ssize_t>(kWireMsgSize) && decode(rx, static_cast<std::size_t>(n), dec)) {
        InFlight& slot = inflight_[dec.seq & mask_];
        if (slot.live) {
          slot.live = false;
          ++result_.received;
          note_verdict(dec);
        }
      }
    }
    for (const auto& slot : inflight_) {
      if (slot.live) ++result_.lost;
    }
  }

  [[nodiscard]] std::size_t outstanding() const {
    std::size_t n = 0;
    for (const auto& slot : inflight_) {
      if (slot.live) ++n;
    }
    return n;
  }

  void note_verdict(const PolicyDecision& d) {
    switch (static_cast<Verdict>(d.verdict)) {
      case Verdict::kAllow: ++result_.allowed; break;
      case Verdict::kDeny: ++result_.denied; break;
      case Verdict::kRedirect: ++result_.redirected; break;
    }
  }

  const Options& opt_;
  std::size_t index_;
  sockaddr_in target_;
  RequestGenerator gen_;
  std::vector<InFlight> inflight_;
  std::uint32_t mask_;
  int fd_ = -1;
  std::unique_ptr<HttpPool> http_;
  ThreadResult result_;
};

std::string iso_now() {
  const auto t = static_cast<std::time_t>(real_now_unix_s());
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buf;
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else if (a == "--server") {
      if (const char* v = next()) {
        const std::string s = v;
        const auto colon = s.rfind(':');
        if (colon == std::string::npos) { opt.host = s; }
        else {
          opt.host = s.substr(0, colon);
          opt.port = static_cast<std::uint16_t>(std::strtoul(s.c_str() + colon + 1, nullptr, 10));
        }
      }
    }
    else if (a == "--protocol") {
      const char* v = next();
      if (v != nullptr) {
        if (std::strcmp(v, "udp") == 0 || std::strcmp(v, "binary") == 0) {
          opt.protocol = Protocol::kUdpBinary;
        } else if (std::strcmp(v, "http") == 0 || std::strcmp(v, "json") == 0) {
          opt.protocol = Protocol::kHttpJson;
        } else {
          std::fprintf(stderr, "unknown protocol '%s' (expected udp or http)\n", v);
          return 2;
        }
      }
    }
    else if (a == "--connections") { if (const char* v = next()) opt.connections = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--qps") { if (const char* v = next()) opt.qps = std::strtoull(v, nullptr, 10); }
    else if (a == "--duration") { if (const char* v = next()) opt.duration_s = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--warmup") { if (const char* v = next()) opt.warmup_s = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--threads") { if (const char* v = next()) opt.threads = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--first-core") { if (const char* v = next()) opt.first_core = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--no-pin") { opt.pin = false; }
    else if (a == "--closed-loop") { opt.closed_loop = true; }
    else if (a == "--timeout-ms") { if (const char* v = next()) opt.timeout_ms = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--max-inflight") { if (const char* v = next()) opt.max_inflight = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--batch-recv") { if (const char* v = next()) opt.batch_recv = static_cast<std::uint32_t>(std::strtoul(v, nullptr, 10)); }
    else if (a == "--rules") { if (const char* v = next()) opt.rules_path = v; }
    else if (a == "--subscribers") { if (const char* v = next()) opt.subscribers_path = v; }
    else if (a == "--seed") { if (const char* v = next()) opt.seed = std::strtoull(v, nullptr, 10); }
    else if (a == "--out-prefix") { if (const char* v = next()) opt.out_prefix = v; }
    else if (a == "--summary-csv") { if (const char* v = next()) opt.summary_csv = v; }
    else if (a == "--tag") { if (const char* v = next()) opt.tag = v; }
    else if (a == "--timeline") { opt.timeline = true; }
    else { std::fprintf(stderr, "unknown option '%s' (try --help)\n", a.c_str()); return 2; }
  }

  if (opt.threads == 0) opt.threads = 1;
  if (opt.qps == 0) { std::fprintf(stderr, "--qps must be non-zero\n"); return 2; }
  if (opt.closed_loop && opt.protocol == Protocol::kHttpJson) {
    // The closed-loop mode exists to demonstrate coordinated omission, and one
    // transport demonstrates it. Silently running something else would be a
    // strange thing for this program in particular to do.
    std::fprintf(stderr, "--closed-loop is only implemented for --protocol udp\n");
    return 2;
  }
  if (opt.protocol == Protocol::kHttpJson && opt.connections == 0) opt.connections = 1;
  // The in-flight table is indexed by sequence number, so it must be a power of
  // two, and large enough that it cannot wrap within one timeout window.
  opt.max_inflight = static_cast<std::uint32_t>(next_pow2(opt.max_inflight));
  {
    const double per_thread_qps = static_cast<double>(opt.qps) / opt.threads;
    const auto needed = static_cast<std::uint64_t>(per_thread_qps * opt.timeout_ms / 1000.0 * 2);
    if (opt.max_inflight < needed) {
      opt.max_inflight = static_cast<std::uint32_t>(next_pow2(needed));
      std::fprintf(stderr,
                   "note: raised --max-inflight to %u so the sequence table cannot wrap "
                   "within one %u ms timeout window\n",
                   opt.max_inflight, opt.timeout_ms);
    }
  }

  // Traffic shape comes from the same rules file the server loaded, so the
  // generator's DNN ids and blocked IMEIs mean what the server thinks they mean.
  auto compiled = compile_rules_from_file(opt.rules_path, 1);
  if (!compiled.ok()) {
    std::fprintf(stderr, "cannot compile %s: %s\n", opt.rules_path.c_str(),
                 compiled.error_summary().c_str());
    return 1;
  }
  std::string error;
  std::vector<std::uint64_t> imsis = load_imsi_pool(opt.subscribers_path, error);
  if (!error.empty()) {
    std::fprintf(stderr, "%s\n", error.c_str());
    return 1;
  }
  std::vector<std::uint64_t> blocked;
  compiled.rule_set->imei_blocklist.for_each([&](std::uint64_t k) { blocked.push_back(k); });
  std::vector<std::uint32_t> visited;
  compiled.rule_set->roaming_partners.for_each(
      [&](std::uint64_t k) { visited.push_back(static_cast<std::uint32_t>(k)); });
  visited.push_back(46000);  // a network that is not a partner

  sockaddr_in target{};
  if (!resolve_v4(opt.host, opt.port, target, error)) {
    std::fprintf(stderr, "%s\n", error.c_str());
    return 1;
  }

  std::fprintf(stderr,
               "loadgen -> %s:%u | %s | %s | %" PRIu64 " QPS offered across %u thread(s) | "
               "%u s warm-up + %u s measured | %zu IMSIs | clock %s @ %.0f MHz\n",
               opt.host.c_str(), opt.port,
               opt.protocol == Protocol::kHttpJson ? "HTTP/1.1 + JSON, keep-alive"
                                                   : "binary/UDP, 64 B",
               opt.closed_loop ? "CLOSED loop (not a valid tail measurement)"
                               : "OPEN loop (fixed schedule)",
               opt.qps, opt.threads, opt.warmup_s, opt.duration_s, imsis.size(),
               cycle_counter_name(), cycles_per_second() / 1e6);
  if (opt.protocol == Protocol::kHttpJson) {
    std::fprintf(stderr,
                 "  %u persistent connections per thread. HTTP here is a GET with query\n"
                 "  parameters and no body, which is the cheapest it can be -- so any\n"
                 "  overhead this shows against the binary path is a lower bound.\n",
                 opt.connections);
  }

  std::vector<std::unique_ptr<Sender>> senders;
  for (std::uint32_t i = 0; i < opt.threads; ++i) {
    senders.push_back(std::make_unique<Sender>(
        opt, i, target, imsis, blocked, visited,
        static_cast<std::uint8_t>(compiled.rule_set->dnn_names.size())));
    if (!senders.back()->open(error)) {
      std::fprintf(stderr, "thread %u: %s\n", i, error.c_str());
      return 1;
    }
  }

  const auto wall_start = std::chrono::steady_clock::now();
  std::vector<std::thread> threads;
  threads.reserve(opt.threads);
  for (auto& s : senders) threads.emplace_back([&s] { s->run(); });
  for (auto& t : threads) t.join();
  const double wall_s =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - wall_start).count();

  // --- merge ---------------------------------------------------------------
  ThreadResult total;
  for (const auto& s : senders) {
    const ThreadResult& r = s->result();
    total.latency.add(r.latency);
    total.send_lateness.add(r.send_lateness);
    total.sent += r.sent;
    total.received += r.received;
    total.measured_received += r.measured_received;
    total.lost += r.lost;
    total.send_errors += r.send_errors;
    total.bad_replies += r.bad_replies;
    total.stale_replies += r.stale_replies;
    total.allowed += r.allowed;
    total.denied += r.denied;
    total.redirected += r.redirected;
    total.schedule_slips += r.schedule_slips;
    total.max_slip_ns = std::max(total.max_slip_ns, r.max_slip_ns);
    total.connection_starved += r.connection_starved;
    total.reconnects += r.reconnects;
    if (total.per_second_count.size() < r.per_second_count.size()) {
      total.per_second_count.resize(r.per_second_count.size(), 0);
      total.per_second_p99_ns.resize(r.per_second_p99_ns.size(), 0);
    }
    for (std::size_t i = 0; i < r.per_second_count.size(); ++i) {
      total.per_second_count[i] += r.per_second_count[i];
      total.per_second_p99_ns[i] = std::max(total.per_second_p99_ns[i], r.per_second_p99_ns[i]);
    }
  }

  const double achieved_qps =
      opt.duration_s > 0 ? static_cast<double>(total.measured_received) / opt.duration_s : 0.0;
  const double loss_pct =
      total.sent > 0 ? 100.0 * static_cast<double>(total.lost) / static_cast<double>(total.sent) : 0.0;

  auto us = [&](double pct) {
    return static_cast<double>(total.latency.value_at_percentile(pct)) / 1000.0;
  };
  auto late_us = [&](double pct) {
    return static_cast<double>(total.send_lateness.value_at_percentile(pct)) / 1000.0;
  };

  std::fprintf(stderr,
               "\n"
               "  offered      %" PRIu64 " QPS   achieved %.0f QPS   (%.1f%% of offered)\n"
               "  sent         %" PRIu64 "\n"
               "  received     %" PRIu64 "\n"
               "  lost         %" PRIu64 " (%.4f%%)%s\n"
               "  send errors  %" PRIu64 "    bad replies %" PRIu64 "    stale %" PRIu64 "\n"
               "  verdicts     allow %" PRIu64 "  deny %" PRIu64 "  redirect %" PRIu64 "\n"
               "\n"
               "  latency (us, end to end, from the SCHEDULED send time)\n"
               "    p50    %8.1f\n"
               "    p90    %8.1f\n"
               "    p99    %8.1f\n"
               "    p99.9  %8.1f\n"
               "    p99.99 %8.1f\n"
               "    max    %8.1f\n"
               "    mean   %8.1f\n"
               "\n"
               "  generator send lateness (us) — how far behind schedule this process fell\n"
               "    p50 %.1f   p99 %.1f   max %.1f   slips %" PRIu64 " (max %.1f us)\n"
               "  connection starved %" PRIu64 "   reconnects %" PRIu64 "\n"
               "  wall clock %.2f s\n",
               opt.qps, achieved_qps, 100.0 * achieved_qps / static_cast<double>(opt.qps),
               total.sent, total.received, total.lost, loss_pct,
               loss_pct > 0.01 ? "   <-- DEGRADED: percentiles below are over received replies only"
                               : "",
               total.send_errors, total.bad_replies, total.stale_replies, total.allowed,
               total.denied, total.redirected, us(50), us(90), us(99), us(99.9), us(99.99),
               static_cast<double>(total.latency.max()) / 1000.0, total.latency.mean() / 1000.0,
               late_us(50), late_us(99),
               static_cast<double>(total.send_lateness.max()) / 1000.0, total.schedule_slips,
               static_cast<double>(total.max_slip_ns) / 1000.0, total.connection_starved,
               total.reconnects, wall_s);

  if (!opt.closed_loop && total.schedule_slips > total.sent / 100) {
    std::fprintf(stderr,
                 "\nWARNING: the generator missed its schedule on %.1f%% of sends. It could not "
                 "offer %" PRIu64 " QPS, so this run measures the generator, not the server. "
                 "Add threads or reduce --qps.\n",
                 100.0 * static_cast<double>(total.schedule_slips) / static_cast<double>(total.sent),
                 opt.qps);
  }

  // --- files ---------------------------------------------------------------
  if (!opt.out_prefix.empty()) {
    const std::string hdr_path = opt.out_prefix + ".hdr.csv";
    std::ofstream hdr(hdr_path);
    if (hdr) {
      hdr << "# policy-loadgen percentile distribution, latency in nanoseconds\n"
          << "# " << iso_now() << "  tag=" << opt.tag << "  offered_qps=" << opt.qps
          << "  threads=" << opt.threads << "  mode="
          << (opt.closed_loop ? "closed-loop" : "open-loop") << "  protocol="
          << (opt.protocol == Protocol::kHttpJson ? "http" : "udp") << "\n"
          << total.latency.percentile_csv();
      std::fprintf(stderr, "  wrote %s\n", hdr_path.c_str());
    }
    if (opt.timeline) {
      const std::string tl_path = opt.out_prefix + ".timeline.csv";
      std::ofstream tl(tl_path);
      if (tl) {
        tl << "second,replies,p99_us\n";
        for (std::size_t i = 0; i + 1 < total.per_second_count.size(); ++i) {
          tl << i << "," << total.per_second_count[i] << ","
             << static_cast<double>(total.per_second_p99_ns[i]) / 1000.0 << "\n";
        }
        std::fprintf(stderr, "  wrote %s\n", tl_path.c_str());
      }
    }
  }

  if (!opt.summary_csv.empty()) {
    const bool exists = std::ifstream(opt.summary_csv).good();
    std::ofstream out(opt.summary_csv, std::ios::app);
    if (out) {
      if (!exists) {
        out << "timestamp,tag,mode,protocol,offered_qps,achieved_qps,threads,sent,received,lost,"
               "loss_pct,p50_us,p90_us,p99_us,p999_us,p9999_us,max_us,mean_us,"
               "send_late_p99_us,schedule_slips,allow,deny,redirect,host,build\n";
      }
      out << iso_now() << "," << opt.tag << ","
          << (opt.closed_loop ? "closed-loop" : "open-loop") << ","
          << (opt.protocol == Protocol::kHttpJson ? "http" : "udp") << "," << opt.qps << ","
          << achieved_qps << "," << opt.threads << "," << total.sent << "," << total.received << ","
          << total.lost << "," << loss_pct << "," << us(50) << "," << us(90) << "," << us(99) << ","
          << us(99.9) << "," << us(99.99) << "," << static_cast<double>(total.latency.max()) / 1000.0
          << "," << total.latency.mean() / 1000.0 << ","
          << late_us(99) << "," << total.schedule_slips
          << "," << total.allowed << "," << total.denied << "," << total.redirected << ","
          << POLICY_SYSTEM_NAME "/" POLICY_SYSTEM_PROC << ","
          << POLICY_BUILD_TYPE " " POLICY_COMPILER_ID << "\n";
      std::fprintf(stderr, "  appended summary row to %s\n", opt.summary_csv.c_str());
    }
  }

  // A run that lost replies, or that could not keep to its schedule, is not a
  // valid latency measurement. Say so in the exit status so a sweep script can
  // notice without parsing the output.
  return (loss_pct > 0.01 || total.send_errors > 0) ? 3 : 0;
}
