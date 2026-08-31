// Socket setup and batched datagram I/O.
//
// Two platform stories, and it matters which one produced a number:
//
//  Linux — each worker owns its own UDP socket bound to the same port with
//    SO_REUSEPORT. The kernel hashes the 4-tuple across the socket group, so a
//    worker never shares a socket, a lock or a cache line with another worker.
//    Batching uses recvmmsg/sendmmsg: one syscall per batch in each direction.
//
//  Anything else (macOS, BSD) — SO_REUSEPORT exists but does not load-balance;
//    BSD delivers a datagram to a single socket in the group, and there is no
//    SO_REUSEPORT_LB on macOS. So the portable path gives every worker the same
//    socket and lets the kernel wake one of them, and there is no recvmmsg, so
//    a "batch" is a loop of recvfrom calls. That still works and still measures
//    something real, but it is one socket lock and N syscalls per batch, and
//    multi-core scaling figures from it are not comparable to Linux.
//
// `BatchIo::per_syscall_batching()` reports which path is live so the benchmark
// harness can record it alongside the numbers instead of leaving the reader to
// guess.
#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <string>
#include <vector>

#include "policy/build_config.hpp"
#include "policy/wire.hpp"

namespace policy {

struct SocketOptions {
  std::string bind_address = "0.0.0.0";
  std::uint16_t port = 9500;
  std::uint32_t rcvbuf = 4 << 20;
  std::uint32_t sndbuf = 4 << 20;
  bool reuseport = true;
  bool nonblocking = true;
};

// Owns a file descriptor. Move-only; closing is not optional.
class Socket {
 public:
  Socket() = default;
  explicit Socket(int fd) : fd_(fd) {}
  ~Socket();

  Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  Socket& operator=(Socket&& o) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  [[nodiscard]] int fd() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  void reset();

 private:
  int fd_ = -1;
};

// Create and bind a UDP socket. `error` is set and an invalid Socket returned
// on failure.
Socket bind_udp(const SocketOptions& opts, std::string& error);

// Resolve "host:port" or "host" into a sockaddr. IPv4 only — the wire format
// and the benchmark harness are both v4, and pretending otherwise without
// testing it would be worse than the limitation.
bool resolve_v4(const std::string& host, std::uint16_t port, sockaddr_in& out, std::string& error);

std::string format_addr(const sockaddr_in& addr);

// True when this build can give each worker its own kernel-balanced socket.
[[nodiscard]] constexpr bool have_per_worker_sockets() {
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

// True when a batch costs one syscall rather than N.
[[nodiscard]] constexpr bool have_batched_syscalls() { return POLICY_HAVE_MMSG != 0; }

// ---------------------------------------------------------------------------
// BatchIo
// ---------------------------------------------------------------------------
//
// Receives up to `batch` datagrams, lets the caller stage a reply for any
// subset of them, and sends the staged replies. Buffers are allocated once at
// construction; nothing here allocates while running.
class BatchIo {
 public:
  BatchIo(int fd, std::uint32_t batch);
  ~BatchIo();

  BatchIo(const BatchIo&) = delete;
  BatchIo& operator=(const BatchIo&) = delete;

  // Returns the number of datagrams received, 0 if none were ready, or -1 on a
  // real error (errno is left set). EAGAIN/EWOULDBLOCK/EINTR return 0.
  [[nodiscard]] int recv_batch();

  [[nodiscard]] const void* payload(std::uint32_t i) const { return recv_buf_.data() + i * kSlotSize; }
  [[nodiscard]] std::size_t payload_len(std::uint32_t i) const { return recv_len_[i]; }

  // Copy a 64-byte reply into send slot `out`, addressed to the source of
  // receive slot `src`.
  void stage_reply(std::uint32_t out, std::uint32_t src, const void* reply64);

  // Send the first `count` staged replies. Returns the number actually sent,
  // or -1. When it sends fewer than asked, `*out_errno` (if given) receives the
  // errno that stopped it — the difference between a full socket buffer
  // (EAGAIN), an overflowing interface queue (ENOBUFS) and a real error matters
  // enough to a person debugging a drop rate that it must not be discarded.
  [[nodiscard]] int send_batch(std::uint32_t count, int* out_errno = nullptr);

  // Block until the socket is readable or `timeout_us` elapses. Returns true if
  // readable. Used after the busy-poll budget is spent.
  [[nodiscard]] bool wait_readable(int timeout_us) const;

  [[nodiscard]] std::uint32_t batch_size() const noexcept { return batch_; }
  [[nodiscard]] static constexpr bool per_syscall_batching() { return have_batched_syscalls(); }

 private:
  // Receive slots are one wire message each. A datagram larger than this is
  // truncated, which makes its length != 64 and gets it dropped — exactly the
  // behaviour we want for anything that is not our protocol.
  static constexpr std::size_t kSlotSize = kWireMsgSize;

  int fd_;
  std::uint32_t batch_;

  std::vector<char> recv_buf_;   // batch_ * kSlotSize
  std::vector<char> send_buf_;   // batch_ * kSlotSize
  std::vector<std::uint32_t> recv_len_;
  std::vector<sockaddr_in> recv_addr_;
  std::vector<sockaddr_in> send_addr_;

#if POLICY_HAVE_MMSG
  std::vector<struct mmsghdr> recv_msgs_;
  std::vector<struct mmsghdr> send_msgs_;
  std::vector<struct iovec> recv_iov_;
  std::vector<struct iovec> send_iov_;
#endif
};

}  // namespace policy
