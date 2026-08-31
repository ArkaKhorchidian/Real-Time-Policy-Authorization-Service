// The control plane.
//
// Owns everything the workers read and nothing they write: the RCU domain
// holding the current RuleSet, the subscriber store, the metrics registry, the
// rules-file watcher and the admin HTTP server. It runs off the request path
// entirely — by design, a control-plane stall cannot delay a decision, and the
// only interaction with workers is an atomic pointer swap plus a grace period.
#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "policy/admin_http.hpp"
#include "policy/coarse_clock.hpp"
#include "policy/config.hpp"
#include "policy/metrics.hpp"
#include "policy/rcu.hpp"
#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"

namespace policy {

struct ReloadStats {
  std::uint64_t attempts = 0;
  std::uint64_t successes = 0;
  std::uint64_t failures = 0;
  std::uint64_t compile_us = 0;      // last compile duration
  std::uint64_t grace_period_us = 0; // last RCU grace period
  std::uint64_t last_success_unix_s = 0;
  std::uint32_t current_version = 0;
  std::string last_error;
};

class ControlPlane {
 public:
  explicit ControlPlane(const ServerConfig& cfg);
  ~ControlPlane();

  ControlPlane(const ControlPlane&) = delete;
  ControlPlane& operator=(const ControlPlane&) = delete;

  // Compile the rules, load the subscribers, publish version 1. Fails loudly:
  // a server that starts with no policy would answer every request with the
  // default action, which is worse than not starting.
  [[nodiscard]] bool initialize(std::string& error);

  // Start the admin server and, if configured, the rules-file watcher.
  [[nodiscard]] bool start(std::string& error);
  void stop();

  [[nodiscard]] RcuDomain<RuleSet>& rules() noexcept { return rules_; }
  [[nodiscard]] SubscriberStore& store() noexcept { return store_; }
  [[nodiscard]] MetricsRegistry& metrics() noexcept { return metrics_; }
  [[nodiscard]] const ReloadStats& reload_stats() const noexcept { return reload_stats_; }
  [[nodiscard]] std::uint16_t admin_port() const;

  // Compile the rules file and swap it in. Safe to call from any thread; the
  // internal mutex serializes reloads against each other, never against
  // workers. Returns false and leaves the current rule set in place on any
  // compile error — a bad edit must never take the policy offline.
  bool reload_rules(std::string& error);

  // Description of the running system, for the banner, /stats and benchmark
  // metadata.
  [[nodiscard]] std::string describe(const std::string& ingest_description) const;

  // Wire up the admin routes onto an already-constructed server. Exposed so
  // tests can drive the handlers without opening a socket.
  void register_routes(AdminHttpServer& http, const std::string& ingest_description);

  // Record which ingest backend actually started, so /stats and the banner
  // report the backend in use rather than the one that was requested.
  void set_ingest_description(std::string d) { ingest_description_ = std::move(d); }

 private:
  void watch_loop();
  [[nodiscard]] std::uint64_t rules_file_mtime() const;

  // Handlers.
  [[nodiscard]] HttpResponse handle_metrics(const HttpRequest& req) const;
  [[nodiscard]] HttpResponse handle_stats(const HttpRequest& req) const;
  [[nodiscard]] HttpResponse handle_rules(const HttpRequest& req) const;
  [[nodiscard]] HttpResponse handle_reload(const HttpRequest& req);
  [[nodiscard]] HttpResponse handle_subscriber(const HttpRequest& req) const;
  [[nodiscard]] HttpResponse handle_explain(const HttpRequest& req) const;

  ServerConfig cfg_;
  RcuDomain<RuleSet> rules_;
  SubscriberStore store_;
  MetricsRegistry metrics_;
  CoarseClockTicker clock_ticker_;

  std::unique_ptr<AdminHttpServer> http_;
  std::thread watcher_;
  std::atomic<bool> stop_{false};

  std::mutex reload_mutex_;
  ReloadStats reload_stats_;
  std::atomic<std::uint32_t> next_version_{1};
  std::uint64_t last_seen_mtime_ = 0;
  std::uint64_t started_unix_s_ = 0;
  std::string ingest_description_;
};

}  // namespace policy
