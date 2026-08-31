#include "policy/net.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "policy/logging.hpp"

namespace policy {

Socket::~Socket() { reset(); }

Socket& Socket::operator=(Socket&& o) noexcept {
  if (this != &o) {
    reset();
    fd_ = o.fd_;
    o.fd_ = -1;
  }
  return *this;
}

void Socket::reset() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

bool resolve_v4(const std::string& host, std::uint16_t port, sockaddr_in& out, std::string& error) {
  std::memset(&out, 0, sizeof(out));
  out.sin_family = AF_INET;
  out.sin_port = htons(port);

  if (host.empty() || host == "*") {
    out.sin_addr.s_addr = INADDR_ANY;
    return true;
  }
  if (::inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1) return true;

  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo* res = nullptr;
  const int rc = ::getaddrinfo(host.c_str(), nullptr, &hints, &res);
  if (rc != 0 || res == nullptr) {
    error = "cannot resolve '" + host + "': " + ::gai_strerror(rc);
    return false;
  }
  out.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
  ::freeaddrinfo(res);
  return true;
}

std::string format_addr(const sockaddr_in& addr) {
  char buf[INET_ADDRSTRLEN] = {};
  ::inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
  return std::string(buf) + ":" + std::to_string(ntohs(addr.sin_port));
}

namespace {

// Ask for a socket buffer and report what the kernel actually gave us. Silently
// accepting a smaller buffer is how a load test ends up measuring drops instead
// of latency.
void set_buf_size(int fd, int optname, std::uint32_t want, const char* name) {
  auto v = static_cast<int>(want);
  if (::setsockopt(fd, SOL_SOCKET, optname, &v, sizeof(v)) != 0) {
    LOG_WARN("setsockopt(%s, %u) failed: %s", name, want, std::strerror(errno));
    return;
  }
  int got = 0;
  socklen_t len = sizeof(got);
  if (::getsockopt(fd, SOL_SOCKET, optname, &got, &len) == 0) {
    // Linux reports double the requested size (it accounts for bookkeeping).
    const auto effective = static_cast<std::uint32_t>(got);
    if (effective < want) {
      LOG_WARN("%s capped at %u bytes (asked for %u); raise net.core.rmem_max", name, effective,
               want);
    }
  }
}

}  // namespace

Socket bind_udp(const SocketOptions& opts, std::string& error) {
  sockaddr_in addr{};
  if (!resolve_v4(opts.bind_address, opts.port, addr, error)) return Socket{};

  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    error = std::string("socket(): ") + std::strerror(errno);
    return Socket{};
  }
  Socket sock(fd);

  int one = 1;
  if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
    error = std::string("SO_REUSEADDR: ") + std::strerror(errno);
    return Socket{};
  }
#ifdef SO_REUSEPORT
  if (opts.reuseport) {
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0) {
      error = std::string("SO_REUSEPORT: ") + std::strerror(errno);
      return Socket{};
    }
  }
#endif

  set_buf_size(fd, SO_RCVBUF, opts.rcvbuf, "SO_RCVBUF");
  set_buf_size(fd, SO_SNDBUF, opts.sndbuf, "SO_SNDBUF");

  if (opts.nonblocking) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
      error = std::string("O_NONBLOCK: ") + std::strerror(errno);
      return Socket{};
    }
  }

  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    error = "bind(" + opts.bind_address + ":" + std::to_string(opts.port) + "): " +
            std::strerror(errno);
    return Socket{};
  }

  return sock;
}

// ---------------------------------------------------------------------------
// BatchIo
// ---------------------------------------------------------------------------

BatchIo::BatchIo(int fd, std::uint32_t batch) : fd_(fd), batch_(batch == 0 ? 1 : batch) {
  recv_buf_.resize(batch_ * kSlotSize);
  send_buf_.resize(batch_ * kSlotSize);
  recv_len_.resize(batch_, 0);
  recv_addr_.resize(batch_);
  send_addr_.resize(batch_);

#if POLICY_HAVE_MMSG
  recv_msgs_.resize(batch_);
  send_msgs_.resize(batch_);
  recv_iov_.resize(batch_);
  send_iov_.resize(batch_);
  for (std::uint32_t i = 0; i < batch_; ++i) {
    recv_iov_[i].iov_base = recv_buf_.data() + i * kSlotSize;
    recv_iov_[i].iov_len = kSlotSize;
    std::memset(&recv_msgs_[i], 0, sizeof(recv_msgs_[i]));
    recv_msgs_[i].msg_hdr.msg_iov = &recv_iov_[i];
    recv_msgs_[i].msg_hdr.msg_iovlen = 1;
    recv_msgs_[i].msg_hdr.msg_name = &recv_addr_[i];
    recv_msgs_[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);

    send_iov_[i].iov_base = send_buf_.data() + i * kSlotSize;
    send_iov_[i].iov_len = kSlotSize;
    std::memset(&send_msgs_[i], 0, sizeof(send_msgs_[i]));
    send_msgs_[i].msg_hdr.msg_iov = &send_iov_[i];
    send_msgs_[i].msg_hdr.msg_iovlen = 1;
    send_msgs_[i].msg_hdr.msg_name = &send_addr_[i];
    send_msgs_[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
  }
#endif
}

BatchIo::~BatchIo() = default;

int BatchIo::recv_batch() {
#if POLICY_HAVE_MMSG
  // One syscall for the whole batch. MSG_DONTWAIT rather than relying on the
  // socket flag so this works on a blocking fd too.
  for (std::uint32_t i = 0; i < batch_; ++i) {
    recv_msgs_[i].msg_hdr.msg_namelen = sizeof(sockaddr_in);
    recv_msgs_[i].msg_len = 0;
  }
  const int n = ::recvmmsg(fd_, recv_msgs_.data(), batch_, MSG_DONTWAIT, nullptr);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    return -1;
  }
  for (int i = 0; i < n; ++i) {
    recv_len_[static_cast<std::size_t>(i)] = recv_msgs_[static_cast<std::size_t>(i)].msg_len;
  }
  return n;
#else
  // Portable path: a loop of recvfrom. Stops at the first would-block so a
  // partially-full batch is processed immediately rather than waiting for the
  // batch to fill — waiting would be coordinated omission on the server side.
  std::uint32_t n = 0;
  while (n < batch_) {
    socklen_t alen = sizeof(sockaddr_in);
    const ssize_t r = ::recvfrom(fd_, recv_buf_.data() + n * kSlotSize, kSlotSize, MSG_DONTWAIT,
                                 reinterpret_cast<sockaddr*>(&recv_addr_[n]), &alen);
    if (r < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
      return n > 0 ? static_cast<int>(n) : -1;
    }
    recv_len_[n] = static_cast<std::uint32_t>(r);
    ++n;
  }
  return static_cast<int>(n);
#endif
}

void BatchIo::stage_reply(std::uint32_t out, std::uint32_t src, const void* reply64) {
  std::memcpy(send_buf_.data() + out * kSlotSize, reply64, kWireMsgSize);
  send_addr_[out] = recv_addr_[src];
}

int BatchIo::send_batch(std::uint32_t count, int* out_errno) {
  if (out_errno != nullptr) *out_errno = 0;
  if (count == 0) return 0;

  // Three transient conditions stop a send early and all three mean "drop the
  // rest of this batch", which is the correct response for a datagram service
  // under overload: blocking here would back-pressure into receive and turn a
  // send-side problem into a latency spike for every request in the batch.
  //
  //   EAGAIN/EWOULDBLOCK — the socket send buffer is full.
  //   ENOBUFS            — the interface queue is full. On loopback this is the
  //                        usual one, and it is what limits multiple threads
  //                        sharing a socket on macOS.
  //
  // They are reported separately rather than lumped together, because a drop
  // rate is only diagnosable if you know which one it was.
  auto transient = [](int e) {
    return e == EAGAIN || e == EWOULDBLOCK || e == ENOBUFS;
  };

#if POLICY_HAVE_MMSG
  std::uint32_t sent = 0;
  while (sent < count) {
    const int n = ::sendmmsg(fd_, send_msgs_.data() + sent, count - sent, MSG_DONTWAIT);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (out_errno != nullptr) *out_errno = errno;
      if (transient(errno)) break;
      return sent > 0 ? static_cast<int>(sent) : -1;
    }
    sent += static_cast<std::uint32_t>(n);
  }
  return static_cast<int>(sent);
#else
  std::uint32_t sent = 0;
  while (sent < count) {
    const ssize_t r = ::sendto(fd_, send_buf_.data() + sent * kSlotSize, kWireMsgSize, MSG_DONTWAIT,
                               reinterpret_cast<sockaddr*>(&send_addr_[sent]), sizeof(sockaddr_in));
    if (r < 0) {
      if (errno == EINTR) continue;
      if (out_errno != nullptr) *out_errno = errno;
      if (transient(errno)) break;
      return sent > 0 ? static_cast<int>(sent) : -1;
    }
    ++sent;
  }
  return static_cast<int>(sent);
#endif
}

bool BatchIo::wait_readable(int timeout_us) const {
  pollfd pfd{};
  pfd.fd = fd_;
  pfd.events = POLLIN;
  const int ms = timeout_us <= 0 ? 0 : (timeout_us + 999) / 1000;
  const int rc = ::poll(&pfd, 1, ms);
  return rc > 0 && (pfd.revents & POLLIN) != 0;
}

}  // namespace policy
