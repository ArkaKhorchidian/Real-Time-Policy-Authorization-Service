#include "policy/admin_http.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstring>

#include "policy/affinity.hpp"
#include "policy/logging.hpp"

namespace policy {
namespace {

// Caps so a malformed or hostile request cannot make the control plane
// allocate without bound. The admin API's largest legitimate body is a rules
// file, and 8 MiB is far past any realistic one.
constexpr std::size_t kMaxHeaderBytes = 64 * 1024;
constexpr std::size_t kMaxBodyBytes = 8 * 1024 * 1024;
constexpr int kConnectionTimeoutMs = 5000;

std::string to_lower(std::string_view s) {
  std::string out(s);
  for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

const char* status_text(int status) {
  switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 422: return "Unprocessable Entity";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "Unknown";
  }
}

bool write_all(int fd, const char* data, std::size_t len) {
  while (len > 0) {
    const ssize_t n = ::send(fd, data, len, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    data += n;
    len -= static_cast<std::size_t>(n);
  }
  return true;
}

}  // namespace

std::string url_decode(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '+') {
      out += ' ';
    } else if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
               std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
      const auto hex = std::string(s.substr(i + 1, 2));
      out += static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
      i += 2;
    } else {
      out += s[i];
    }
  }
  return out;
}

AdminHttpServer::AdminHttpServer(std::string bind_address, std::uint16_t port)
    : bind_address_(std::move(bind_address)), port_(port) {}

AdminHttpServer::~AdminHttpServer() { stop(); }

void AdminHttpServer::route(const std::string& method, const std::string& path, Handler h) {
  routes_[method + " " + path] = std::move(h);
}

void AdminHttpServer::route_prefix(const std::string& method, const std::string& prefix, Handler h) {
  prefix_routes_.emplace_back(method + " " + prefix, std::move(h));
}

bool AdminHttpServer::start(std::string& error) {
  sockaddr_in addr{};
  if (!resolve_v4(bind_address_, port_, addr, error)) return false;

  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    error = std::string("admin socket(): ") + std::strerror(errno);
    return false;
  }
  listen_socket_ = Socket(fd);

  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    error = "admin bind(" + bind_address_ + ":" + std::to_string(port_) + "): " +
            std::strerror(errno);
    return false;
  }
  if (::listen(fd, 32) != 0) {
    error = std::string("admin listen(): ") + std::strerror(errno);
    return false;
  }

  // Report the port actually bound, so --admin-port 0 works for tests.
  sockaddr_in bound{};
  socklen_t blen = sizeof(bound);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
    bound_port_ = ntohs(bound.sin_port);
  }

  stop_.store(false, std::memory_order_release);
  thread_ = std::thread([this] { serve(); });
  return true;
}

void AdminHttpServer::stop() {
  if (!thread_.joinable()) return;
  stop_.store(true, std::memory_order_release);
  // Shutting the listening socket down wakes the accept loop; closing alone can
  // leave it blocked on some platforms.
  if (listen_socket_.valid()) ::shutdown(listen_socket_.fd(), SHUT_RDWR);
  thread_.join();
  listen_socket_.reset();
}

void AdminHttpServer::serve() {
  name_current_thread("policy-admin");
  while (!stop_.load(std::memory_order_acquire)) {
    pollfd pfd{};
    pfd.fd = listen_socket_.fd();
    pfd.events = POLLIN;
    const int rc = ::poll(&pfd, 1, 200);
    if (rc <= 0) continue;

    const int client = ::accept(listen_socket_.fd(), nullptr, nullptr);
    if (client < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      if (stop_.load(std::memory_order_acquire)) break;
      LOG_WARN("admin accept: %s", std::strerror(errno));
      continue;
    }
    handle_connection(client);
    ::close(client);
  }
}

void AdminHttpServer::handle_connection(int client_fd) {
  int one = 1;
  ::setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

  std::string buf;
  buf.reserve(4096);
  char chunk[4096];

  auto read_more = [&]() -> bool {
    pollfd pfd{};
    pfd.fd = client_fd;
    pfd.events = POLLIN;
    if (::poll(&pfd, 1, kConnectionTimeoutMs) <= 0) return false;
    const ssize_t n = ::recv(client_fd, chunk, sizeof(chunk), 0);
    if (n <= 0) return false;
    buf.append(chunk, static_cast<std::size_t>(n));
    return true;
  };

  // Headers.
  std::size_t header_end = std::string::npos;
  while ((header_end = buf.find("\r\n\r\n")) == std::string::npos) {
    if (buf.size() > kMaxHeaderBytes || !read_more()) {
      const auto resp = HttpResponse::error(400, "malformed or oversized request");
      const std::string out = "HTTP/1.1 400 Bad Request\r\nContent-Length: " +
                              std::to_string(resp.body.size()) + "\r\nConnection: close\r\n\r\n" +
                              resp.body;
      write_all(client_fd, out.data(), out.size());
      return;
    }
  }

  HttpRequest req;
  const std::string head = buf.substr(0, header_end);
  std::size_t pos = head.find("\r\n");
  const std::string request_line = head.substr(0, pos == std::string::npos ? head.size() : pos);

  {
    const auto sp1 = request_line.find(' ');
    const auto sp2 = sp1 == std::string::npos ? std::string::npos : request_line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
      const std::string out = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
      write_all(client_fd, out.data(), out.size());
      return;
    }
    req.method = request_line.substr(0, sp1);
    std::string target = request_line.substr(sp1 + 1, sp2 - sp1 - 1);

    const auto q = target.find('?');
    if (q != std::string::npos) {
      const std::string query = target.substr(q + 1);
      target = target.substr(0, q);
      std::size_t start = 0;
      while (start <= query.size()) {
        const auto amp = query.find('&', start);
        const std::string pair =
            query.substr(start, amp == std::string::npos ? std::string::npos : amp - start);
        if (!pair.empty()) {
          const auto eq = pair.find('=');
          if (eq == std::string::npos) {
            req.query[url_decode(pair)] = "";
          } else {
            req.query[url_decode(pair.substr(0, eq))] = url_decode(pair.substr(eq + 1));
          }
        }
        if (amp == std::string::npos) break;
        start = amp + 1;
      }
    }
    req.path = url_decode(target);
  }

  while (pos != std::string::npos && pos + 2 < head.size()) {
    const auto line_end = head.find("\r\n", pos + 2);
    const std::string line =
        head.substr(pos + 2, line_end == std::string::npos ? std::string::npos : line_end - pos - 2);
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
      std::string value = line.substr(colon + 1);
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(0, 1);
      req.headers[to_lower(line.substr(0, colon))] = value;
    }
    if (line_end == std::string::npos) break;
    pos = line_end;
  }

  std::size_t content_length = 0;
  if (const auto it = req.headers.find("content-length"); it != req.headers.end()) {
    content_length = static_cast<std::size_t>(std::strtoull(it->second.c_str(), nullptr, 10));
  }

  HttpResponse resp;
  if (content_length > kMaxBodyBytes) {
    resp = HttpResponse::error(413, "request body too large");
  } else {
    const std::size_t body_start = header_end + 4;
    while (buf.size() - body_start < content_length) {
      if (!read_more()) break;
    }
    req.body = buf.substr(body_start, content_length);
    resp = dispatch(req);
  }

  std::string out = "HTTP/1.1 " + std::to_string(resp.status) + " " + status_text(resp.status) +
                    "\r\nContent-Type: " + resp.content_type +
                    "\r\nContent-Length: " + std::to_string(resp.body.size()) +
                    "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n" + resp.body;
  write_all(client_fd, out.data(), out.size());
}

HttpResponse AdminHttpServer::dispatch(const HttpRequest& req) const {
  const std::string key = req.method + " " + req.path;
  if (const auto it = routes_.find(key); it != routes_.end()) return it->second(req);

  // Longest matching prefix wins, so /subscriber/ and /subscriber/x/y can
  // coexist without ordering surprises.
  const Handler* best = nullptr;
  std::size_t best_len = 0;
  for (const auto& [prefix, handler] : prefix_routes_) {
    if (key.size() >= prefix.size() && key.compare(0, prefix.size(), prefix) == 0 &&
        prefix.size() > best_len) {
      best = &handler;
      best_len = prefix.size();
    }
  }
  if (best != nullptr) return (*best)(req);

  // Distinguish "no such path" from "wrong method on a real path", which is
  // the difference between a typo and a client bug.
  for (const auto& [k, _] : routes_) {
    if (k.size() > req.path.size() && k.compare(k.size() - req.path.size(), req.path.size(), req.path) == 0) {
      return HttpResponse::error(405, "method not allowed for " + req.path);
    }
  }
  return HttpResponse::error(404, "no such endpoint: " + req.path);
}

}  // namespace policy
