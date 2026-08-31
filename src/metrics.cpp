#include "policy/metrics.hpp"

namespace policy {

MetricsSnapshot MetricsRegistry::snapshot() const {
  MetricsSnapshot s;
  for (const auto& b : blocks_) {
    const WorkerMetrics& w = *b;
    s.requests += w.requests;
    s.replies_sent += w.replies_sent;
    s.short_datagrams += w.short_datagrams;
    s.bad_magic += w.bad_magic;
    s.unknown_subscriber += w.unknown_subscriber;
    s.send_failures += w.send_failures;
    s.recv_errors += w.recv_errors;
    s.batches += w.batches;
    s.batch_datagrams += w.batch_datagrams;
    s.full_batches += w.full_batches;
    s.idle_spins += w.idle_spins;
    s.blocking_waits += w.blocking_waits;
    for (std::size_t i = 0; i < 3; ++i) s.verdicts[i] += w.verdicts[i];
    for (std::size_t i = 0; i < static_cast<std::size_t>(Reason::kCount); ++i) {
      s.reasons[i] += w.reasons[i];
    }
    // Merging histograms copies counts out of a block a worker is still
    // writing. The result can be internally inconsistent by a handful of
    // samples; for a percentile over millions of samples that is noise, and
    // the alternative — locking the worker's histogram — is not.
    s.service_ns.add(w.service_ns);
  }
  return s;
}

}  // namespace policy
