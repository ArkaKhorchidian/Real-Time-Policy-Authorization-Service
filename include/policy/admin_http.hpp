// Admin HTTP server for the control plane.
//
// Deliberately minimal and deliberately not on the request path: it runs on its
// own thread, handles one connection at a time, and never touches a worker's
// data except through the same RCU snapshot workers use. An admin request
// cannot slow a decision down.
//
// It binds to 127.0.0.1 by default and has no authentication, because adding a
// half-measure would invite someone to expose it. Put it behind the same thing
// that fronts everything else in the cluster.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "policy/net.hpp"

namespace policy {

struct HttpRequest {
  std::string method;
  std::string path;                             // path only, query stripped
  std::map<std::string, std::string> query;     // decoded query parameters
  std::map<std::string, std::string> headers;   // lower-cased names
  std::string body;

  [[nodiscard]] const std::string* param(const std::string& key) const {
    const auto it = query.find(key);
    return it == query.end() ? nullptr : &it->second;
  }
};

struct HttpResponse {
  int status = 200;
  std::string content_type = "text/plain; charset=utf-8";
  std::string body;

  static HttpResponse text(std::string b) { return {200, "text/plain; charset=utf-8", std::move(b)}; }
  static HttpResponse json(std::string b) { return {200, "application/json", std::move(b)}; }
  static HttpResponse error(int status, const std::string& message) {
    return {status, "application/json", "{\"error\":\"" + message + "\"}\n"};
  }
};

class AdminHttpServer {
 public:
  using Handler = std::function<HttpResponse(const HttpRequest&)>;

  AdminHttpServer(std::string bind_address, std::uint16_t port);
  ~AdminHttpServer();

  AdminHttpServer(const AdminHttpServer&) = delete;
  AdminHttpServer& operator=(const AdminHttpServer&) = delete;

  // Exact-path routing; `METHOD /path`. No wildcards — routes that need a path
  // parameter (e.g. /subscriber/{imsi}) register a prefix with route_prefix().
  void route(const std::string& method, const std::string& path, Handler h);
  void route_prefix(const std::string& method, const std::string& prefix, Handler h);

  [[nodiscard]] bool start(std::string& error);
  void stop();

  [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_; }

 private:
  void serve();
  void handle_connection(int client_fd);
  [[nodiscard]] HttpResponse dispatch(const HttpRequest& req) const;

  std::string bind_address_;
  std::uint16_t port_;
  std::uint16_t bound_port_ = 0;
  Socket listen_socket_;
  std::thread thread_;
  std::atomic<bool> stop_{false};

  std::map<std::string, Handler> routes_;
  std::vector<std::pair<std::string, Handler>> prefix_routes_;
};

// Percent-decoding for query strings and path segments.
std::string url_decode(std::string_view s);

}  // namespace policy
