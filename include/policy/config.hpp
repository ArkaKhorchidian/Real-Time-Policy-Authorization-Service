// Server configuration and command-line parsing.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "policy/logging.hpp"

namespace policy {

enum class IngestBackend { kUdp, kIoUring };

bool parse_ingest_backend(std::string_view s, IngestBackend& out);
const char* ingest_backend_name(IngestBackend b);

struct ServerConfig {
  // --- Listener ---
  std::string bind_address = "0.0.0.0";
  std::uint16_t port = 9500;
  std::uint32_t worker_threads = 1;

  // Batch cap for recvmmsg/sendmmsg. This is the single most important latency
  // knob: a larger batch amortizes the syscall over more requests (throughput)
  // but the first request in a batch waits for the whole batch to be gathered
  // (tail latency). bench/results/batch_sweep.csv is the tradeoff curve.
  std::uint32_t batch_size = 32;

  // Socket buffer sizes. Undersized receive buffers turn a load spike into
  // silent drops, which look like latency in the client's histogram.
  std::uint32_t so_rcvbuf = 4 << 20;
  std::uint32_t so_sndbuf = 4 << 20;

  IngestBackend backend = IngestBackend::kUdp;

  // Spin before falling back to a blocking wait. Busy-polling removes the
  // wake-up latency (a few microseconds of scheduler and IPI cost) at the price
  // of a core burning at 100%. Zero disables it.
  std::uint32_t busy_poll_us = 50;

  // --- CPU placement ---
  bool pin_workers = true;
  std::uint32_t first_core = 0;
  int control_plane_core = -1;  // -1 = do not pin

  // --- Data ---
  std::string rules_path = "config/rules.yaml";
  std::string subscribers_path = "config/subscribers.csv";
  std::size_t expected_subscribers = 0;  // 0 = size from the file

  // --- Control plane ---
  std::string admin_bind_address = "127.0.0.1";
  std::uint16_t admin_port = 9501;
  std::uint32_t reload_poll_ms = 500;
  bool watch_rules_file = true;

  LogLevel log_level = LogLevel::kInfo;

  // Exit after this many seconds. Used by the benchmark harness so a run cannot
  // leave a server behind; 0 means run until signalled.
  std::uint32_t run_seconds = 0;
};

struct ConfigParseResult {
  ServerConfig config;
  bool ok = true;
  bool help_requested = false;
  std::string error;
};

ConfigParseResult parse_server_args(int argc, char** argv);
void print_server_usage(const char* argv0);

// Validate a fully-populated config: ranges, core counts, file existence.
// Returns an empty string when the config is usable.
std::string validate_config(const ServerConfig& cfg);

}  // namespace policy
