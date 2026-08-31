// Coarse wall clock.
//
// The decision path needs "roughly what time is it" for one thing only:
// deciding whether a subscriber's metering period has rolled over. Calling
// clock_gettime(CLOCK_REALTIME) for that costs ~20-25 ns through the vDSO,
// which is a real fraction of a sub-microsecond budget and, worse, it is a
// fraction that varies with what the rest of the machine is doing.
//
// So the server ticks a coarse clock on the control-plane thread and the
// request path reads one relaxed atomic. Resolution is the tick interval
// (default 100 ms), which is four orders of magnitude finer than the thing
// being decided (a billing period boundary).
//
// Nothing here is on the hot path except `coarse_now_unix_s()`, which compiles
// to a single load.
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

namespace policy {

// Fixed instant used by the golden corpus. Period-expiry decisions depend on
// wall-clock time; pinning it here is what keeps the committed golden file from
// changing with the calendar. 2026-09-01T00:00:00Z.
inline constexpr std::uint64_t kGoldenClockUnixS = 1787788800ull;

namespace detail {
inline std::atomic<std::uint64_t> g_coarse_unix_s{0};
}

// One relaxed load. Returns 0 only if no ticker has ever run and no fallback
// has been primed; callers treat 0 as "period boundary unknown, do not expire".
[[nodiscard]] inline std::uint64_t coarse_now_unix_s() noexcept {
  return detail::g_coarse_unix_s.load(std::memory_order_relaxed);
}

inline void set_coarse_now_unix_s(std::uint64_t v) noexcept {
  detail::g_coarse_unix_s.store(v, std::memory_order_relaxed);
}

[[nodiscard]] inline std::uint64_t real_now_unix_s() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// Monotonic nanoseconds, used for latency measurement and for the reply's
// server_ts_ns. steady_clock is CLOCK_MONOTONIC and is not affected by NTP
// slew, which matters when a benchmark runs for minutes.
[[nodiscard]] inline std::uint64_t mono_now_ns() noexcept {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

// Ticks the coarse clock on its own thread. Started by the server; tests and
// tools construct one when they care about period expiry.
class CoarseClockTicker {
 public:
  explicit CoarseClockTicker(std::chrono::milliseconds interval = std::chrono::milliseconds(100))
      : interval_(interval) {
    set_coarse_now_unix_s(real_now_unix_s());
    thread_ = std::thread([this] {
      while (!stop_.load(std::memory_order_acquire)) {
        set_coarse_now_unix_s(real_now_unix_s());
        // Sleep in short slices so shutdown is prompt regardless of interval.
        for (auto slept = std::chrono::milliseconds(0);
             slept < interval_ && !stop_.load(std::memory_order_acquire);
             slept += std::chrono::milliseconds(10)) {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
      }
    });
  }

  ~CoarseClockTicker() {
    stop_.store(true, std::memory_order_release);
    if (thread_.joinable()) thread_.join();
  }

  CoarseClockTicker(const CoarseClockTicker&) = delete;
  CoarseClockTicker& operator=(const CoarseClockTicker&) = delete;

 private:
  std::chrono::milliseconds interval_;
  std::atomic<bool> stop_{false};
  std::thread thread_;
};

}  // namespace policy
