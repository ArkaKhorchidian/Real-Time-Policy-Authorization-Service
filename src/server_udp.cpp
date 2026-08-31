#include <cerrno>
#include <cstring>

#include "policy/affinity.hpp"
#include "policy/cycles.hpp"
#include "policy/engine.hpp"
#include "policy/logging.hpp"
#include "policy/server.hpp"

namespace policy {

UdpServer::UdpServer(const ServerConfig& cfg, ServerDeps deps) : cfg_(cfg), deps_(deps) {}

UdpServer::~UdpServer() {
  request_stop();
  join();
}

std::string UdpServer::ingest_description() const {
  std::string d = "UDP/";
  d += BatchIo::per_syscall_batching() ? "recvmmsg+sendmmsg" : "recvfrom+sendto loop";
  d += have_per_worker_sockets() ? ", SO_REUSEPORT socket per worker"
                                 : ", one socket shared by all workers "
                                   "(SO_REUSEPORT does not load-balance on this platform)";
  return d;
}

bool UdpServer::start(std::string& error) {
  const std::size_t workers = cfg_.worker_threads;

  // Linux: one SO_REUSEPORT socket per worker, kernel-hashed. Elsewhere: one
  // socket, shared. See net.hpp for why.
  const std::size_t socket_count = have_per_worker_sockets() ? workers : 1;
  for (std::size_t i = 0; i < socket_count; ++i) {
    SocketOptions opts;
    opts.bind_address = cfg_.bind_address;
    opts.port = cfg_.port;
    opts.rcvbuf = cfg_.so_rcvbuf;
    opts.sndbuf = cfg_.so_sndbuf;
    opts.reuseport = have_per_worker_sockets();
    opts.nonblocking = true;

    Socket s = bind_udp(opts, error);
    if (!s.valid()) {
      sockets_.clear();
      return false;
    }
    sockets_.push_back(std::move(s));
  }

  if (!have_per_worker_sockets() && workers > 1) {
    LOG_WARN(
        "%zu workers share one socket: this platform's SO_REUSEPORT does not distribute "
        "datagrams. Scaling numbers from this build are not comparable to Linux.",
        workers);
  }

  stop_.store(false, std::memory_order_release);
  running_.store(true, std::memory_order_release);

  threads_.reserve(workers);
  for (std::size_t i = 0; i < workers; ++i) {
    const int fd = sockets_[have_per_worker_sockets() ? i : 0].fd();
    threads_.emplace_back([this, i, fd] { worker_loop(i, fd); });
  }
  return true;
}

void UdpServer::request_stop() { stop_.store(true, std::memory_order_release); }

void UdpServer::join() {
  for (auto& t : threads_) {
    if (t.joinable()) t.join();
  }
  threads_.clear();
  running_.store(false, std::memory_order_release);
  sockets_.clear();
}

void UdpServer::worker_loop(std::size_t worker_index, int fd) {
  name_current_thread("policy-w" + std::to_string(worker_index));

  if (cfg_.pin_workers) {
    std::string detail;
    const auto core = cfg_.first_core + static_cast<unsigned>(worker_index);
    switch (pin_current_thread(core, detail)) {
      case PinResult::kPinned:
        LOG_INFO("worker %zu pinned to %s", worker_index, detail.c_str());
        break;
      case PinResult::kUnsupported:
        LOG_WARN("worker %zu not pinned: %s", worker_index, detail.c_str());
        break;
      case PinResult::kFailed:
        LOG_ERROR("worker %zu pinning failed: %s", worker_index, detail.c_str());
        break;
    }
  }

  WorkerMetrics& m = deps_.metrics->worker(worker_index);
  const SubscriberStore& store = *deps_.store;
  RcuDomain<RuleSet>& rules = *deps_.rules;

  const std::size_t rcu_slot = rules.register_reader();
  if (rcu_slot == static_cast<std::size_t>(-1)) {
    LOG_ERROR("worker %zu could not claim an RCU reader slot; exiting", worker_index);
    return;
  }

  BatchIo io(fd, cfg_.batch_size);
  const double cps = cycles_per_second();
  const std::uint64_t busy_poll_cycles =
      static_cast<std::uint64_t>(static_cast<double>(cfg_.busy_poll_us) * cps / 1e6);

  std::uint64_t idle_since = rdcycles();

  while (!stop_.load(std::memory_order_relaxed)) {
    const int received = io.recv_batch();

    if (received < 0) {
      ++m.recv_errors;
      LOG_WARN("worker %zu recv error: %s", worker_index, std::strerror(errno));
      continue;
    }

    if (received == 0) {
      ++m.idle_spins;
      // Spin for the configured budget, then park. Busy-polling removes the
      // wake-up path (scheduler + IPI, a few microseconds) from the latency of
      // the first request after an idle gap; parking afterwards means an idle
      // server does not burn a core.
      if (busy_poll_cycles == 0 || rdcycles() - idle_since > busy_poll_cycles) {
        ++m.blocking_waits;
        (void)io.wait_readable(1000);
        idle_since = rdcycles();
      }
      continue;
    }

    idle_since = rdcycles();
    const auto n = static_cast<std::uint32_t>(received);
    ++m.batches;
    m.batch_datagrams += n;
    if (n == io.batch_size()) ++m.full_batches;

    // One RCU acquisition per batch rather than per request. Two reasons: it
    // amortizes the epoch store, and it guarantees every request in a batch is
    // decided against the same policy version — a batch that straddled a reload
    // would be harder to reason about in an audit for no benefit.
    const auto guard = rules.read(rcu_slot);
    const RuleSet* rs = guard.get();
    if (rs == nullptr) continue;  // no rules loaded yet

    std::uint32_t out = 0;
    for (std::uint32_t i = 0; i < n; ++i) {
      const std::size_t len = io.payload_len(i);
      if (len != kWireMsgSize) {
        // Not our protocol. Drop without replying: replying to arbitrary
        // datagrams would make this an amplification-free but still pointless
        // reflector, and scanners are not worth a syscall.
        ++m.short_datagrams;
        continue;
      }

      // Service time brackets exactly the compute path: decode, lookup,
      // evaluate, encode. The syscalls on either side are deliberately outside
      // it, so the difference between this and the loadgen's end-to-end number
      // is the I/O cost and nothing else.
      const std::uint64_t t0 = rdcycles();

      PolicyRequest req;
      PolicyDecision dec;
      if (!decode(io.payload(i), len, req)) {
        // Right size, wrong magic: a real client with a version mismatch. It
        // gets an answer so it fails loudly instead of timing out.
        ++m.bad_magic;
        std::memcpy(&req, io.payload(i), kWireMsgSize);
        dec = malformed_decision(req.seq, req.client_ts_ns, rs->version);
      } else {
        const SubscriberRecord* rec = store.find(req.imsi);
        if (rec == nullptr) ++m.unknown_subscriber;
        dec = evaluate(*rs, req, rec);
        ++m.requests;
      }
      dec.server_ts_ns = cycles_now_ns();

      alignas(64) char reply[kWireMsgSize];
      encode(dec, reply);
      io.stage_reply(out, i, reply);
      ++out;

      m.service_ns.record(cycles_to_ns_i(rdcycles() - t0));
      m.note(dec);
    }

    if (out == 0) continue;
    const int sent = io.send_batch(out);
    if (sent < 0) {
      m.send_failures += out;
      LOG_WARN("worker %zu send error: %s", worker_index, std::strerror(errno));
    } else {
      m.replies_sent += static_cast<std::uint64_t>(sent);
      m.send_failures += out - static_cast<std::uint32_t>(sent);
    }
  }

  rules.unregister_reader(rcu_slot);
  LOG_INFO("worker %zu stopped after %llu requests", worker_index,
           static_cast<unsigned long long>(m.requests));
}

}  // namespace policy
