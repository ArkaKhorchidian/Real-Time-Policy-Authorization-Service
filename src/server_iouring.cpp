// io_uring ingest backend.
//
// The point of this file is to put a number on the syscall cost. The socket
// backend pays two syscalls per batch (recvmmsg + sendmmsg); io_uring pays
// close to zero in steady state, because completions are reaped from a shared
// ring and submissions are batched into the same enter() call that waits.
//
// Shape of the loop, per worker:
//
//   * `batch` recvmsg operations are kept armed at all times. A completed recv
//     is processed and immediately re-armed, so the ring never runs dry and the
//     kernel always has somewhere to put the next datagram.
//   * Replies are prepped as sendmsg SQEs against a separate slot pool with a
//     free list; their completions only return the slot.
//   * One io_uring_submit_and_wait() per iteration submits every SQE queued
//     this round and blocks for at least one completion — so an idle worker
//     costs nothing, and a busy worker's submit is free because it rides along
//     with the wait it was going to do anyway.
//
// Not used here, deliberately: SQPOLL (a kernel poll thread per ring is a whole
// core per worker, which changes what "100k QPS per core" means) and registered
// buffers (they help for large payloads; at 64 bytes the copy is one cache
// line and the bookkeeping costs more than it saves). Both are noted in the
// README as the next rungs on the ladder.
#include <memory>
#include <string>

#include "policy/build_config.hpp"
#include "policy/logging.hpp"
#include "policy/server.hpp"

#if POLICY_HAVE_IO_URING

#include <liburing.h>

#include <cerrno>
#include <cstring>
#include <vector>

#include "policy/affinity.hpp"
#include "policy/cycles.hpp"
#include "policy/engine.hpp"
#include "policy/net.hpp"

namespace policy {
namespace {

constexpr std::uint64_t kOpRecv = 0;
constexpr std::uint64_t kOpSend = 1;

constexpr std::uint64_t make_user_data(std::uint64_t op, std::uint64_t idx) {
  return (op << 32) | idx;
}
constexpr std::uint64_t user_data_op(std::uint64_t ud) { return ud >> 32; }
constexpr std::uint64_t user_data_idx(std::uint64_t ud) { return ud & 0xFFFFFFFFull; }

// A recv or send slot. Each owns its own msghdr/iovec/address so a submission
// stays valid until its completion arrives.
struct alignas(64) IoSlot {
  msghdr hdr{};
  iovec iov{};
  sockaddr_in addr{};
  char buf[kWireMsgSize]{};

  void init() {
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    hdr.msg_name = &addr;
    hdr.msg_namelen = sizeof(addr);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
  }
};

}  // namespace

class IoUringServer final : public IngestServer {
 public:
  IoUringServer(const ServerConfig& cfg, ServerDeps deps) : cfg_(cfg), deps_(deps) {}

  ~IoUringServer() override {
    request_stop();
    join();
  }

  bool start(std::string& error) override {
    const std::size_t socket_count = have_per_worker_sockets() ? cfg_.worker_threads : 1;
    for (std::size_t i = 0; i < socket_count; ++i) {
      SocketOptions opts;
      opts.bind_address = cfg_.bind_address;
      opts.port = cfg_.port;
      opts.rcvbuf = cfg_.so_rcvbuf;
      opts.sndbuf = cfg_.so_sndbuf;
      opts.reuseport = have_per_worker_sockets();
      // io_uring operations are asynchronous regardless of the fd's blocking
      // mode; leaving the socket blocking avoids the kernel taking a
      // fast-path-then-retry route for every operation.
      opts.nonblocking = false;

      Socket s = bind_udp(opts, error);
      if (!s.valid()) {
        sockets_.clear();
        return false;
      }
      sockets_.push_back(std::move(s));
    }

    stop_.store(false, std::memory_order_release);
    running_.store(true, std::memory_order_release);
    threads_.reserve(cfg_.worker_threads);
    for (std::size_t i = 0; i < cfg_.worker_threads; ++i) {
      const int fd = sockets_[have_per_worker_sockets() ? i : 0].fd();
      threads_.emplace_back([this, i, fd] { worker_loop(i, fd); });
    }
    return true;
  }

  void request_stop() override { stop_.store(true, std::memory_order_release); }

  void join() override {
    for (auto& t : threads_) {
      if (t.joinable()) t.join();
    }
    threads_.clear();
    running_.store(false, std::memory_order_release);
    sockets_.clear();
  }

  [[nodiscard]] bool running() const override { return running_.load(std::memory_order_acquire); }

  [[nodiscard]] std::string ingest_description() const override {
    std::string d = "io_uring (submit_and_wait, " + std::to_string(cfg_.batch_size) +
                    " recvmsg in flight)";
    d += have_per_worker_sockets() ? ", SO_REUSEPORT socket per worker" : ", shared socket";
    return d;
  }

 private:
  void worker_loop(std::size_t worker_index, int fd) {
    name_current_thread("policy-u" + std::to_string(worker_index));

    if (cfg_.pin_workers) {
      std::string detail;
      const auto core = cfg_.first_core + static_cast<unsigned>(worker_index);
      if (pin_current_thread(core, detail) == PinResult::kPinned) {
        LOG_INFO("io_uring worker %zu pinned to %s", worker_index, detail.c_str());
      }
    }

    const std::uint32_t batch = cfg_.batch_size;
    // Room for every recv and send in flight at once, plus headroom so a full
    // round of re-arms never finds the submission queue full.
    const unsigned entries = static_cast<unsigned>(next_pow2(batch * 4));

    io_uring ring{};
    io_uring_params params{};
    if (const int rc = io_uring_queue_init_params(entries, &ring, &params); rc < 0) {
      LOG_ERROR("io_uring_queue_init failed for worker %zu: %s; this worker will not run",
                worker_index, std::strerror(-rc));
      return;
    }

    std::vector<IoSlot> recv_slots(batch);
    std::vector<IoSlot> send_slots(batch * 2);
    std::vector<std::uint32_t> free_send;
    free_send.reserve(send_slots.size());
    for (auto& s : recv_slots) s.init();
    for (std::uint32_t i = 0; i < send_slots.size(); ++i) {
      send_slots[i].init();
      free_send.push_back(static_cast<std::uint32_t>(send_slots.size() - 1 - i));
    }

    auto arm_recv = [&](std::uint32_t i) {
      io_uring_sqe* sqe = io_uring_get_sqe(&ring);
      if (sqe == nullptr) return false;
      recv_slots[i].hdr.msg_namelen = sizeof(sockaddr_in);
      recv_slots[i].iov.iov_len = sizeof(recv_slots[i].buf);
      io_uring_prep_recvmsg(sqe, fd, &recv_slots[i].hdr, 0);
      io_uring_sqe_set_data64(sqe, make_user_data(kOpRecv, i));
      return true;
    };

    for (std::uint32_t i = 0; i < batch; ++i) {
      if (!arm_recv(i)) break;
    }

    WorkerMetrics& m = deps_.metrics->worker(worker_index);
    const SubscriberStore& store = *deps_.store;
    RcuDomain<RuleSet>& rules = *deps_.rules;
    const std::size_t rcu_slot = rules.register_reader();
    if (rcu_slot == static_cast<std::size_t>(-1)) {
      LOG_ERROR("io_uring worker %zu could not claim an RCU reader slot", worker_index);
      io_uring_queue_exit(&ring);
      return;
    }

    // A short timeout on the wait so a stop request is noticed promptly even
    // when no traffic is arriving.
    __kernel_timespec wait_ts{};
    wait_ts.tv_sec = 0;
    wait_ts.tv_nsec = 50'000'000;  // 50 ms

    while (!stop_.load(std::memory_order_relaxed)) {
      io_uring_cqe* cqe = nullptr;
      const int rc = io_uring_submit_and_wait_timeout(&ring, &cqe, 1, &wait_ts, nullptr);
      if (rc < 0 && rc != -ETIME && rc != -EINTR && rc != -EAGAIN) {
        LOG_WARN("io_uring worker %zu submit_and_wait: %s", worker_index, std::strerror(-rc));
        continue;
      }

      const auto guard = rules.read(rcu_slot);
      const RuleSet* rs = guard.get();

      unsigned head = 0;
      unsigned reaped = 0;
      std::uint32_t processed = 0;

      io_uring_for_each_cqe(&ring, head, cqe) {
        ++reaped;
        const std::uint64_t ud = io_uring_cqe_get_data64(cqe);
        const std::uint64_t idx = user_data_idx(ud);
        const int res = cqe->res;

        if (user_data_op(ud) == kOpSend) {
          if (res < 0) {
            ++m.send_failures;
            if (res == -ENOBUFS) ++m.send_nobufs;
            else if (res == -EAGAIN) ++m.send_wouldblock;
            else ++m.send_errors;
          } else {
            ++m.replies_sent;
          }
          free_send.push_back(static_cast<std::uint32_t>(idx));
          continue;
        }

        // A recv completion.
        if (res < 0) {
          if (res != -EAGAIN && res != -EINTR) ++m.recv_errors;
          arm_recv(static_cast<std::uint32_t>(idx));
          continue;
        }
        if (res != static_cast<int>(kWireMsgSize) || rs == nullptr) {
          if (res != static_cast<int>(kWireMsgSize)) ++m.short_datagrams;
          arm_recv(static_cast<std::uint32_t>(idx));
          continue;
        }

        IoSlot& in = recv_slots[idx];
        const std::uint64_t t0 = rdcycles();

        PolicyRequest req;
        PolicyDecision dec;
        if (!decode(in.buf, kWireMsgSize, req)) {
          ++m.bad_magic;
          std::memcpy(&req, in.buf, kWireMsgSize);
          dec = malformed_decision(req.seq, req.client_ts_ns, rs->version);
        } else {
          const SubscriberRecord* rec = store.find(req.imsi);
          if (rec == nullptr) ++m.unknown_subscriber;
          dec = evaluate(*rs, req, rec);
          ++m.requests;
        }
        dec.server_ts_ns = cycles_now_ns();

        if (!free_send.empty()) {
          const std::uint32_t s = free_send.back();
          IoSlot& out = send_slots[s];
          encode(dec, out.buf);
          out.addr = in.addr;
          out.hdr.msg_namelen = sizeof(sockaddr_in);
          out.iov.iov_len = kWireMsgSize;
          if (io_uring_sqe* sqe = io_uring_get_sqe(&ring); sqe != nullptr) {
            io_uring_prep_sendmsg(sqe, fd, &out.hdr, 0);
            io_uring_sqe_set_data64(sqe, make_user_data(kOpSend, s));
            free_send.pop_back();
          } else {
            ++m.send_failures;
            ++m.send_wouldblock;
          }
        } else {
          // Every send slot is in flight: the kernel is behind. Dropping is the
          // right answer for a datagram service under overload.
          ++m.send_failures;
          ++m.send_wouldblock;
        }

        m.service_ns.record(cycles_to_ns_i(rdcycles() - t0));
        m.note(dec);
        ++processed;
        arm_recv(static_cast<std::uint32_t>(idx));
      }

      io_uring_cq_advance(&ring, reaped);
      if (processed > 0) {
        ++m.batches;
        m.batch_datagrams += processed;
        if (processed >= batch) ++m.full_batches;
      } else {
        ++m.idle_spins;
        ++m.blocking_waits;
      }
    }

    rules.unregister_reader(rcu_slot);
    io_uring_queue_exit(&ring);
    LOG_INFO("io_uring worker %zu stopped after %llu requests", worker_index,
             static_cast<unsigned long long>(m.requests));
  }

  ServerConfig cfg_;
  ServerDeps deps_;
  std::vector<Socket> sockets_;
  std::vector<std::thread> threads_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> running_{false};
};

bool io_uring_available() {
  // Compiling against liburing is not enough: the kernel may be too old, or
  // io_uring may be disabled by seccomp or by kernel.io_uring_disabled. Probe
  // once by actually creating a ring.
  static const bool ok = [] {
    io_uring ring{};
    if (io_uring_queue_init(8, &ring, 0) < 0) return false;
    io_uring_queue_exit(&ring);
    return true;
  }();
  return ok;
}

std::unique_ptr<IngestServer> make_server(const ServerConfig& cfg, ServerDeps deps,
                                          std::string& error) {
  if (cfg.backend == IngestBackend::kIoUring) {
    if (io_uring_available()) {
      return std::make_unique<IoUringServer>(cfg, deps);
    }
    LOG_WARN("io_uring requested but unavailable at runtime; falling back to the socket backend");
  }
  (void)error;
  return std::make_unique<UdpServer>(cfg, deps);
}

}  // namespace policy

#else  // !POLICY_HAVE_IO_URING

namespace policy {

bool io_uring_available() { return false; }

std::unique_ptr<IngestServer> make_server(const ServerConfig& cfg, ServerDeps deps,
                                          std::string& error) {
  if (cfg.backend == IngestBackend::kIoUring) {
    LOG_WARN(
        "this binary has no io_uring backend (needs Linux and liburing at build time); "
        "falling back to the socket backend");
  }
  (void)error;
  return std::make_unique<UdpServer>(cfg, deps);
}

}  // namespace policy

#endif
