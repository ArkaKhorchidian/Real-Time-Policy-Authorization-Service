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
  return "none — macOS affinity tags are advisory and ignored on Apple Silicon";
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
  // THREAD_AFFINITY_POLICY is a hint that groups threads sharing an L2; it is
  // not a binding, and on Apple Silicon the call succeeds while changing
  // nothing. Issue it anyway (it is harmless and helps on Intel Macs) but
  // report the truth to the caller.
  thread_affinity_policy_data_t policy = {static_cast<integer_t>(core) + 1};
  thread_policy_set(pthread_mach_thread_np(pthread_self()), THREAD_AFFINITY_POLICY,
                    reinterpret_cast<thread_policy_t>(&policy), THREAD_AFFINITY_POLICY_COUNT);
  detail = "affinity tag " + std::to_string(core + 1) + " set, but macOS does not honour it";
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
