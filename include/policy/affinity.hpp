// CPU pinning.
//
// Pinning matters here for two reasons: a worker that migrates loses its L1/L2
// working set (the rule table and the hot part of the subscriber store), and a
// worker that shares a core with another worker inherits its scheduling
// latency — which shows up as exactly the p99.9 spike this project is trying to
// characterize.
//
// Linux gets real pinning via sched_setaffinity. macOS does not: thread affinity
// policy is advisory on Intel and ignored entirely on Apple Silicon, where the
// scheduler owns P/E core placement. Rather than pretend, `pin_current_thread()`
// reports what it actually did, and the server logs it so a benchmark run's
// provenance records whether pinning was in effect.
#pragma once

#include <cstdint>
#include <string>

namespace policy {

enum class PinResult {
  kPinned,       // the thread is bound to the requested core
  kUnsupported,  // this platform cannot pin; the thread runs wherever
  kFailed,       // the platform supports pinning and it failed
};

PinResult pin_current_thread(unsigned core, std::string& detail);

// Name the calling thread, so `top -H` and perf output are readable.
void name_current_thread(const std::string& name);

unsigned hardware_thread_count();

// A one-line description of the platform's pinning support, for the run banner
// and for bench metadata.
const char* affinity_support_description();

}  // namespace policy
