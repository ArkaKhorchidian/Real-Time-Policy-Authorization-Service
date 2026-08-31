// policyd — real-time policy / authorization decision service.
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string_view>
#include <thread>

#include "policy/control_plane.hpp"
#include "policy/http_front.hpp"
#include "policy/logging.hpp"
#include "policy/server.hpp"

namespace {

volatile std::sig_atomic_t g_signal = 0;

void on_signal(int sig) { g_signal = sig; }

}  // namespace

int main(int argc, char** argv) {
  auto parsed = policy::parse_server_args(argc, argv);
  if (parsed.help_requested) {
    if (argc > 1 && (std::string_view(argv[1]) == "-h" || std::string_view(argv[1]) == "--help")) {
      policy::print_server_usage(argv[0]);
    }
    return 0;
  }
  if (!parsed.ok) {
    std::fprintf(stderr, "policyd: %s\n", parsed.error.c_str());
    return 2;
  }

  policy::ServerConfig& cfg = parsed.config;
  policy::set_log_level(cfg.log_level);

  if (const std::string problem = policy::validate_config(cfg); !problem.empty()) {
    std::fprintf(stderr, "policyd: %s\n", problem.c_str());
    return 2;
  }

  policy::ControlPlane control(cfg);
  std::string error;
  if (!control.initialize(error)) {
    std::fprintf(stderr, "policyd: %s\n", error.c_str());
    return 1;
  }

  policy::ServerDeps deps;
  deps.rules = &control.rules();
  deps.store = &control.store();
  deps.metrics = &control.metrics();

  std::unique_ptr<policy::IngestServer> server = policy::make_server(cfg, deps, error);
  if (!server) {
    std::fprintf(stderr, "policyd: %s\n", error.c_str());
    return 1;
  }

  // Record the backend before the admin server starts, so /stats names the one
  // that is actually running rather than the one that was requested — they
  // differ whenever io_uring falls back.
  control.set_ingest_description(server->ingest_description());

  if (!server->start(error)) {
    std::fprintf(stderr, "policyd: %s\n", error.c_str());
    return 1;
  }

  // Optional HTTP front, over the same decision path and the same RCU snapshot.
  std::unique_ptr<policy::HttpFrontServer> http_front;
  if (cfg.http_port != 0) {
    http_front = std::make_unique<policy::HttpFrontServer>(cfg, deps, cfg.http_bind_address,
                                                           cfg.http_port);
    if (!http_front->start(error)) {
      std::fprintf(stderr, "policyd: %s\n", error.c_str());
      server->request_stop();
      server->join();
      return 1;
    }
    LOG_INFO("HTTP front on http://%s:%u/v1/decide — %s", cfg.http_bind_address.c_str(),
             http_front->bound_port(), http_front->description().c_str());
  }
  if (!control.start(error)) {
    std::fprintf(stderr, "policyd: %s\n", error.c_str());
    server->request_stop();
    server->join();
    return 1;
  }

  std::fputs(control.describe(server->ingest_description()).c_str(), stderr);

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  // A client that disappears mid-reply must not take the process down.
  std::signal(SIGPIPE, SIG_IGN);

  LOG_INFO("ready");

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.run_seconds);
  while (g_signal == 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (cfg.run_seconds != 0 && std::chrono::steady_clock::now() >= deadline) break;
  }

  if (g_signal != 0) LOG_INFO("signal %d received, shutting down", static_cast<int>(g_signal));
  server->request_stop();
  server->join();
  if (http_front) {
    http_front->request_stop();
    http_front->join();
  }
  control.stop();

  if (http_front) {
    const auto hs = http_front->snapshot();
    LOG_INFO("HTTP front served %llu requests over %llu connection(s); service time %s",
             static_cast<unsigned long long>(hs.requests),
             static_cast<unsigned long long>(hs.connections_accepted),
             hs.service_ns.summary_line("ns").c_str());
  }

  const auto snap = control.metrics().snapshot();
  LOG_INFO("served %llu requests, %llu replies, %llu unknown subscribers; service time %s",
           static_cast<unsigned long long>(snap.requests),
           static_cast<unsigned long long>(snap.replies_sent),
           static_cast<unsigned long long>(snap.unknown_subscriber),
           snap.service_ns.summary_line("ns").c_str());
  return 0;
}
