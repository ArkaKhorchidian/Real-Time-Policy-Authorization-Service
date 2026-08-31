#include "policy/config.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string_view>
#include <thread>

#include "policy/build_config.hpp"

namespace policy {

bool parse_ingest_backend(std::string_view s, IngestBackend& out) {
  if (s == "udp" || s == "socket") { out = IngestBackend::kUdp; return true; }
  if (s == "io_uring" || s == "iouring" || s == "uring") { out = IngestBackend::kIoUring; return true; }
  return false;
}

const char* ingest_backend_name(IngestBackend b) {
  return b == IngestBackend::kIoUring ? "io_uring" : "udp";
}

namespace {

bool file_exists(const std::string& p) {
  std::ifstream f(p);
  return f.good();
}

bool parse_u64_arg(const char* s, std::uint64_t& out) {
  char* end = nullptr;
  const unsigned long long v = std::strtoull(s, &end, 10);
  if (end == s || *end != '\0') return false;
  out = v;
  return true;
}

}  // namespace

void print_server_usage(const char* argv0) {
  std::printf(
      "policyd " POLICY_VERSION_STRING " — real-time policy / authorization decision service\n"
      "\n"
      "Usage: %s [options]\n"
      "\n"
      "Listener:\n"
      "  --bind ADDR              Bind address for the decision socket (default 0.0.0.0)\n"
      "  --port N                 UDP port (default 9500)\n"
      "  --workers N              Worker threads, one SO_REUSEPORT socket each (default 1)\n"
      "  --batch N                recvmmsg/sendmmsg batch cap (default 32)\n"
      "  --backend udp|io_uring   Ingest backend (default udp)\n"
      "  --busy-poll-us N         Spin this long before blocking; 0 disables (default 50)\n"
      "  --rcvbuf BYTES           SO_RCVBUF per worker socket (default 4 MiB)\n"
      "  --sndbuf BYTES           SO_SNDBUF per worker socket (default 4 MiB)\n"
      "\n"
      "CPU placement:\n"
      "  --pin / --no-pin         Pin workers to cores (default: pin)\n"
      "  --first-core N           Core index for worker 0 (default 0)\n"
      "  --control-core N         Pin the control plane to this core (default: unpinned)\n"
      "\n"
      "Data:\n"
      "  --rules PATH             Rules file (default config/rules.yaml)\n"
      "  --subscribers PATH       Subscriber CSV (default config/subscribers.csv)\n"
      "  --expect-subscribers N   Pre-size the store for N subscribers\n"
      "\n"
      "Control plane:\n"
      "  --admin-bind ADDR        Admin HTTP bind address (default 127.0.0.1)\n"
      "  --admin-port N           Admin HTTP port, 0 disables (default 9501)\n"
      "  --no-watch               Do not watch the rules file for changes\n"
      "  --reload-poll-ms N       Rules file poll interval (default 500)\n"
      "\n"
      "Misc:\n"
      "  --log-level LEVEL        trace|debug|info|warn|error|off (default info)\n"
      "  --run-seconds N          Exit after N seconds (default: run until signalled)\n"
      "  --version                Print version and build configuration\n"
      "  -h, --help               This message\n",
      argv0);
}

ConfigParseResult parse_server_args(int argc, char** argv) {
  ConfigParseResult res;
  ServerConfig& c = res.config;

  auto need_value = [&](int& i) -> const char* {
    if (i + 1 >= argc) {
      res.ok = false;
      res.error = std::string("option ") + argv[i] + " requires a value";
      return nullptr;
    }
    return argv[++i];
  };

  auto u64_opt = [&](int& i, std::uint64_t& dst) {
    const char* v = need_value(i);
    if (v == nullptr) return;
    if (!parse_u64_arg(v, dst)) {
      res.ok = false;
      res.error = std::string("option ") + argv[i - 1] + " expects a number, got '" + v + "'";
    }
  };

  for (int i = 1; i < argc && res.ok; ++i) {
    const std::string_view a = argv[i];
    std::uint64_t n = 0;

    if (a == "-h" || a == "--help") {
      res.help_requested = true;
      return res;
    } else if (a == "--version") {
      // Printed so a benchmark result can never be attributed to a fast path
      // that was not actually compiled in.
      std::printf("policyd " POLICY_VERSION_STRING " (" POLICY_BUILD_TYPE ", " POLICY_COMPILER_ID
                  " " POLICY_COMPILER_VER ", " POLICY_SYSTEM_NAME "/" POLICY_SYSTEM_PROC ")\n"
                  "  batched syscalls (recvmmsg/sendmmsg): %s\n"
                  "  CPU affinity:                         %s\n"
                  "  io_uring backend:                     %s\n"
                  "  SO_REUSEPORT load balancing:          %s\n",
                  POLICY_HAVE_MMSG ? "yes" : "no", POLICY_HAVE_AFFINITY ? "yes" : "no",
                  POLICY_HAVE_IO_URING ? "yes" : "no",
#if defined(__linux__)
                  "yes"
#else
                  "no"
#endif
      );
      res.help_requested = true;
      return res;
    } else if (a == "--bind") {
      if (const char* v = need_value(i)) c.bind_address = v;
    } else if (a == "--port") {
      u64_opt(i, n); c.port = static_cast<std::uint16_t>(n);
    } else if (a == "--workers") {
      u64_opt(i, n); c.worker_threads = static_cast<std::uint32_t>(n);
    } else if (a == "--batch") {
      u64_opt(i, n); c.batch_size = static_cast<std::uint32_t>(n);
    } else if (a == "--backend") {
      const char* v = need_value(i);
      if (v != nullptr && !parse_ingest_backend(v, c.backend)) {
        res.ok = false;
        res.error = std::string("unknown backend '") + v + "' (expected udp or io_uring)";
      }
    } else if (a == "--busy-poll-us") {
      u64_opt(i, n); c.busy_poll_us = static_cast<std::uint32_t>(n);
    } else if (a == "--rcvbuf") {
      u64_opt(i, n); c.so_rcvbuf = static_cast<std::uint32_t>(n);
    } else if (a == "--sndbuf") {
      u64_opt(i, n); c.so_sndbuf = static_cast<std::uint32_t>(n);
    } else if (a == "--pin") {
      c.pin_workers = true;
    } else if (a == "--no-pin") {
      c.pin_workers = false;
    } else if (a == "--first-core") {
      u64_opt(i, n); c.first_core = static_cast<std::uint32_t>(n);
    } else if (a == "--control-core") {
      u64_opt(i, n); c.control_plane_core = static_cast<int>(n);
    } else if (a == "--rules") {
      if (const char* v = need_value(i)) c.rules_path = v;
    } else if (a == "--subscribers") {
      if (const char* v = need_value(i)) c.subscribers_path = v;
    } else if (a == "--expect-subscribers") {
      u64_opt(i, n); c.expected_subscribers = static_cast<std::size_t>(n);
    } else if (a == "--admin-bind") {
      if (const char* v = need_value(i)) c.admin_bind_address = v;
    } else if (a == "--admin-port") {
      u64_opt(i, n); c.admin_port = static_cast<std::uint16_t>(n);
    } else if (a == "--no-watch") {
      c.watch_rules_file = false;
    } else if (a == "--reload-poll-ms") {
      u64_opt(i, n); c.reload_poll_ms = static_cast<std::uint32_t>(n);
    } else if (a == "--log-level") {
      const char* v = need_value(i);
      if (v != nullptr && !parse_log_level(v, c.log_level)) {
        res.ok = false;
        res.error = std::string("unknown log level '") + v + "'";
      }
    } else if (a == "--run-seconds") {
      u64_opt(i, n); c.run_seconds = static_cast<std::uint32_t>(n);
    } else {
      res.ok = false;
      res.error = "unknown option '" + std::string(a) + "' (try --help)";
    }
  }

  return res;
}

std::string validate_config(const ServerConfig& cfg) {
  if (cfg.port == 0) return "--port must be non-zero";
  if (cfg.worker_threads == 0) return "--workers must be at least 1";

  const auto hw = std::max(1u, std::thread::hardware_concurrency());
  if (cfg.worker_threads > hw) {
    // Not fatal — oversubscribing is a legitimate experiment — but it
    // invalidates any latency number produced under it, so say so loudly.
    std::fprintf(stderr,
                 "WARNING: %u workers on %u hardware threads: cores are oversubscribed and "
                 "tail latency figures from this run are not meaningful\n",
                 cfg.worker_threads, hw);
  }
  if (cfg.pin_workers && cfg.first_core + cfg.worker_threads > hw) {
    return "worker cores " + std::to_string(cfg.first_core) + ".." +
           std::to_string(cfg.first_core + cfg.worker_threads - 1) + " exceed the " +
           std::to_string(hw) + " available hardware threads";
  }
  if (cfg.batch_size == 0 || cfg.batch_size > 1024) return "--batch must be 1..1024";
  if (!file_exists(cfg.rules_path)) return "rules file not found: " + cfg.rules_path;
  if (!cfg.subscribers_path.empty() && !file_exists(cfg.subscribers_path)) {
    return "subscriber file not found: " + cfg.subscribers_path;
  }
  if (cfg.backend == IngestBackend::kIoUring && !POLICY_HAVE_IO_URING) {
    return "this binary was built without the io_uring backend (needs Linux + liburing)";
  }
  return {};
}

}  // namespace policy
