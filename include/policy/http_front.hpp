// HTTP/1.1 front for the decision path.
//
// Two reasons this exists.
//
// 1. **Protocol overhead becomes a number.** The binary UDP path is the thing
//    this project optimizes; the obvious question is what a normal, ergonomic
//    API costs on top of the same decision. Running both against the same
//    engine on the same host answers it in microseconds instead of hand-waving.
//
//    The comparison is deliberately generous to HTTP: the request is a GET with
//    query parameters, so there is no body to parse, no JSON to decode, and
//    connections are kept alive. That is the cheapest HTTP can possibly be, so
//    whatever overhead it shows is a *lower bound*. A gRPC or Npcf front with
//    protobuf framing and HTTP/2 flow control would cost more, not less.
//
// 2. **A developer-facing policy API is the product surface.** A carrier built
//    for developers exposes policy programmatically, and this is what that
//    looks like sitting directly on top of the same compiled rule table.
//
// The implementation is thread-per-core with keep-alive connections, an
// SO_REUSEPORT listener per worker on Linux, and no allocation per request on
// the response path. It is not a general-purpose HTTP server: it speaks the
// subset needed for one endpoint, and rejects everything else. That is the
// point — an unoptimized front would make the comparison meaningless in the
// other direction.
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "policy/config.hpp"
#include "policy/metrics.hpp"
#include "policy/net.hpp"
#include "policy/rcu.hpp"
#include "policy/rules.hpp"
#include "policy/server.hpp"
#include "policy/subscriber_store.hpp"

namespace policy {

// Render a decision as compact JSON into `out`. Returns the number of bytes
// written, or 0 if the buffer was too small. No allocation: this is on the
// request path for the HTTP front.
std::size_t decision_to_json(const PolicyDecision& d, char* out, std::size_t cap) noexcept;

// Parse the query string of a decision request into a PolicyRequest. Returns
// false with `error` set for anything malformed, so a client gets a 400 that
// says what was wrong rather than a plausible decision built from defaults.
bool parse_decide_query(const RuleSet& rs, std::string_view query, PolicyRequest& out,
                        std::string& error);

class HttpFrontServer {
 public:
  HttpFrontServer(const ServerConfig& cfg, ServerDeps deps, std::string bind_address,
                  std::uint16_t port);
  ~HttpFrontServer();

  HttpFrontServer(const HttpFrontServer&) = delete;
  HttpFrontServer& operator=(const HttpFrontServer&) = delete;

  [[nodiscard]] bool start(std::string& error);
  void request_stop();
  void join();

  [[nodiscard]] std::uint16_t bound_port() const noexcept { return bound_port_; }
  [[nodiscard]] std::string description() const;

  // Counters, kept separate from the UDP path's so the two can be compared.
  struct Stats {
    std::uint64_t connections_accepted = 0;
    std::uint64_t requests = 0;
    std::uint64_t bad_requests = 0;
    std::uint64_t not_found = 0;
    std::uint64_t connections_closed = 0;
    HdrHistogram service_ns{1, 10'000'000, 3};
  };
  [[nodiscard]] Stats snapshot() const;

 private:
  struct Worker;
  void worker_loop(std::size_t index, int listen_fd);

  ServerConfig cfg_;
  ServerDeps deps_;
  std::string bind_address_;
  std::uint16_t port_;
  std::uint16_t bound_port_ = 0;

  std::vector<Socket> listeners_;
  std::vector<std::thread> threads_;
  std::vector<std::unique_ptr<Worker>> workers_;
  std::atomic<bool> stop_{false};
};

}  // namespace policy
