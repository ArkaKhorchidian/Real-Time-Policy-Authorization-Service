#include "policy/affinity.hpp"

#include <cstring>
#include <thread>

#if defined(__linux__)
#include <pthread.h>
#include <sched.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#include <pthread.h>
#include <sys/qos.h>
#endif

namespace policy {

unsigned hardware_thread_count() {
  const unsigned n = std::thread::hardware_concurrency();
  return n == 0 ? 1 : n;
}

const char* affinity_support_description() {
#if defined(__linux__)
  return "sched_setaffinity (hard pinning)";
#elif defined(__APPLE__)
  return "none — macOS has no sched_setaffinity; threads request "
         "QOS_CLASS_USER_INTERACTIVE instead, which buys performance-core "
         "eligibility but not placement";
#else
  return "none — unsupported platform";
#endif
}

PinResult pin_current_thread([[maybe_unused]] unsigned core, std::string& detail) {
#if defined(__linux__)
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(core, &set);
  const int rc = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
  if (rc != 0) {
    detail = std::string("pthread_setaffinity_np: ") + std::strerror(rc);
    return PinResult::kFailed;
  }
  detail = "core " + std::to_string(core);
  return PinResult::kPinned;

#elif defined(__APPLE__)
  // macOS has no equivalent of sched_setaffinity. THREAD_AFFINITY_POLICY is a
  // hint that groups threads sharing an L2; it is advisory on Intel and does
  // nothing at all on Apple Silicon, where the scheduler owns P/E core
  // placement.
  //
  // What macOS does offer, and what actually matters for a latency-sensitive
  // thread here, is the QoS class: it is what decides whether a thread is
  // eligible for a performance core or gets parked on an efficiency one. A
  // busy-polling worker left at the default class can land on an E-core
  // mid-run, and the resulting step change shows up as exactly the kind of
  // tail this project is trying to characterize. USER_INTERACTIVE is the
  // honest request for "this thread is latency-critical".
  //
  // It is still not pinning, and the return value says so, because a benchmark
  // that reported "pinned" here would be lying about its own conditions.
  thread_affinity_policy_data_t policy = {static_cast<integer_t>(core) + 1};
  thread_policy_set(pthread_mach_thread_np(pthread_self()), THREAD_AFFINITY_POLICY,
                    reinterpret_cast<thread_policy_t>(&policy), THREAD_AFFINITY_POLICY_COUNT);

  const int qos_rc = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
  detail = qos_rc == 0
               ? "QoS set to USER_INTERACTIVE (performance cores); macOS has no true pinning"
               : "macOS has no true pinning, and the QoS request failed";
  return PinResult::kUnsupported;

#else
  detail = "not supported on this platform";
  return PinResult::kUnsupported;
#endif
}

void name_current_thread(const std::string& name) {
  // Both platforms cap thread names at 16 bytes including the terminator.
  const std::string truncated = name.substr(0, 15);
#if defined(__linux__)
  pthread_setname_np(pthread_self(), truncated.c_str());
#elif defined(__APPLE__)
  pthread_setname_np(truncated.c_str());
#else
  (void)truncated;
#endif
}

}  // namespace policy
