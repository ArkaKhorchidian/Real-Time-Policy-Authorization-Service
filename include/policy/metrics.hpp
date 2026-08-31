// Per-worker metrics.
//
// Every counter a worker touches lives in that worker's own cache-line-aligned
// block. Nothing on the request path writes a line another core reads — a
// shared std::atomic counter incremented at 100k QPS per core is a contended
// line and would show up directly in the p99.
//
// The control plane sums the blocks when someone asks. The sum is not atomic
// across workers and does not need to be: these are monotonic counters read for
// rates and ratios, not for exact accounting.
#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "policy/hdr_histogram.hpp"
#include "policy/rcu.hpp"  // kCacheLine
#include "policy/wire.hpp"

namespace policy {

struct alignas(kCacheLine) WorkerMetrics {
  // --- request path ---
  std::uint64_t requests = 0;         // datagrams that decoded into a request
  std::uint64_t replies_sent = 0;
  std::uint64_t short_datagrams = 0;  // wrong length; dropped without a reply
  std::uint64_t bad_magic = 0;        // right length, unknown magic/version
  std::uint64_t unknown_subscriber = 0;
  std::uint64_t send_failures = 0;    // staged but the kernel would not take it
  std::uint64_t recv_errors = 0;

  // --- loop shape ---
  std::uint64_t batches = 0;
  std::uint64_t batch_datagrams = 0;  // /batches gives the mean realized batch
  std::uint64_t full_batches = 0;     // hit the batch cap: the loop is saturated
  std::uint64_t idle_spins = 0;
  std::uint64_t blocking_waits = 0;
  std::uint64_t rule_versions_seen = 0;

  std::uint64_t verdicts[3] = {0, 0, 0};
  std::uint64_t reasons[static_cast<std::size_t>(Reason::kCount)] = {};

  // Service time: decode -> lookup -> evaluate -> encode, in nanoseconds. This
  // is the compute path only; it excludes the syscalls on either side, which is
  // the point — the loadgen measures end-to-end and the difference between the
  // two is the I/O cost.
  HdrHistogram service_ns{1, 10'000'000, 3};

  void note(const PolicyDecision& d) noexcept {
    if (d.verdict < 3) ++verdicts[d.verdict];
    if (d.reason < static_cast<std::uint8_t>(Reason::kCount)) ++reasons[d.reason];
  }
};

// Aggregated snapshot. Plain struct, built on demand by the control plane.
struct MetricsSnapshot {
  std::uint64_t requests = 0;
  std::uint64_t replies_sent = 0;
  std::uint64_t short_datagrams = 0;
  std::uint64_t bad_magic = 0;
  std::uint64_t unknown_subscriber = 0;
  std::uint64_t send_failures = 0;
  std::uint64_t recv_errors = 0;
  std::uint64_t batches = 0;
  std::uint64_t batch_datagrams = 0;
  std::uint64_t full_batches = 0;
  std::uint64_t idle_spins = 0;
  std::uint64_t blocking_waits = 0;
  std::uint64_t verdicts[3] = {0, 0, 0};
  std::uint64_t reasons[static_cast<std::size_t>(Reason::kCount)] = {};
  HdrHistogram service_ns{1, 10'000'000, 3};

  [[nodiscard]] double mean_batch() const {
    return batches ? static_cast<double>(batch_datagrams) / static_cast<double>(batches) : 0.0;
  }
};

class MetricsRegistry {
 public:
  explicit MetricsRegistry(std::size_t workers) {
    blocks_.reserve(workers);
    for (std::size_t i = 0; i < workers; ++i) blocks_.push_back(std::make_unique<WorkerMetrics>());
  }

  [[nodiscard]] WorkerMetrics& worker(std::size_t i) { return *blocks_[i]; }
  [[nodiscard]] const WorkerMetrics& worker(std::size_t i) const { return *blocks_[i]; }
  [[nodiscard]] std::size_t worker_count() const noexcept { return blocks_.size(); }

  // Sum every block. Reads counters other threads are writing, without
  // synchronization, on purpose: a torn 64-bit read is not possible on the
  // platforms this runs on, and a counter that is a few hundred requests stale
  // costs nothing at the reporting layer while a fence would cost every worker.
  [[nodiscard]] MetricsSnapshot snapshot() const;

 private:
  std::vector<std::unique_ptr<WorkerMetrics>> blocks_;
};

}  // namespace policy
