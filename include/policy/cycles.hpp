// Cheap cycle counter, for measuring the decision path from inside the server.
//
// Timing a sub-microsecond operation with clock_gettime costs ~20-25 ns per
// call — two calls is a tenth of the thing being measured, and the vDSO's own
// variance lands in the tail you are trying to characterize. The invariant TSC
// (x86-64) and the virtual counter (AArch64) are 2-6 ns reads with no memory
// ordering requirement, which is cheap enough to leave enabled in production.
//
// Both counters are wall-clock-rate, not core-clock-rate, so frequency scaling
// does not distort them. The AArch64 counter reports its own frequency; on
// x86-64 the TSC frequency is not architecturally discoverable, so it is
// calibrated against CLOCK_MONOTONIC at startup.
#pragma once

#include <chrono>
#include <cstdint>
#include <thread>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

namespace policy {

[[nodiscard]] inline std::uint64_t rdcycles() noexcept {
#if defined(__aarch64__)
  std::uint64_t v;
  // CNTVCT_EL0 is the virtual count register: monotonic, fixed frequency,
  // readable from EL0. The isb() that a strict serializing read would need is
  // deliberately omitted — it costs more than the measurement is worth, and
  // the resulting few-cycle skew is far below the histogram's resolution.
  asm volatile("mrs %0, cntvct_el0" : "=r"(v));
  return v;
#elif defined(__x86_64__) || defined(__i386__)
  return __rdtsc();
#else
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
#endif
}

// Ticks per second for the counter above.
[[nodiscard]] inline double cycles_per_second() {
  static const double freq = [] {
#if defined(__aarch64__)
    std::uint64_t f;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(f));
    return static_cast<double>(f);
#elif defined(__x86_64__) || defined(__i386__)
    // Calibrate against the monotonic clock. 20 ms is long enough for sub-0.1%
    // error and short enough not to be noticed at startup.
    const auto t0 = std::chrono::steady_clock::now();
    const std::uint64_t c0 = rdcycles();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const std::uint64_t c1 = rdcycles();
    const auto t1 = std::chrono::steady_clock::now();
    const double elapsed_s =
        std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    return static_cast<double>(c1 - c0) / elapsed_s;
#else
    return 1e9;  // the fallback above already returns nanoseconds
#endif
  }();
  return freq;
}

[[nodiscard]] inline double cycles_to_ns(std::uint64_t cycles) {
  return static_cast<double>(cycles) * 1e9 / cycles_per_second();
}

[[nodiscard]] inline std::int64_t cycles_to_ns_i(std::uint64_t cycles) {
  return static_cast<std::int64_t>(cycles_to_ns(cycles));
}

// Monotonic nanoseconds derived from the cycle counter. One multiply and an
// add, versus ~20 ns for clock_gettime. The anchor is captured once, so this
// tracks CLOCK_MONOTONIC to within the counter's drift over a benchmark run.
[[nodiscard]] inline std::uint64_t cycles_now_ns() noexcept {
  struct Anchor {
    std::uint64_t cycles;
    std::uint64_t ns;
    double ns_per_cycle;
  };
  static const Anchor a = [] {
    const double cps = cycles_per_second();
    return Anchor{rdcycles(),
                  static_cast<std::uint64_t>(
                      std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count()),
                  1e9 / cps};
  }();
  return a.ns + static_cast<std::uint64_t>(static_cast<double>(rdcycles() - a.cycles) *
                                           a.ns_per_cycle);
}

// Cost of a single counter read, measured once at startup. Any service time
// this instrument reports includes two of these, so the figure belongs next to
// the numbers rather than hidden. Reported, never subtracted: silently
// correcting a measurement by an estimate is how instruments start lying.
[[nodiscard]] inline double cycle_read_overhead_ns() {
  static const double ns = [] {
    std::uint64_t smallest = ~std::uint64_t{0};
    for (int i = 0; i < 200000; ++i) {
      const std::uint64_t a = rdcycles();
      const std::uint64_t b = rdcycles();
      const std::uint64_t d = b - a;
      if (d != 0 && d < smallest) smallest = d;
    }
    return smallest == ~std::uint64_t{0} ? 0.0 : cycles_to_ns(smallest);
  }();
  return ns;
}

// Name of the counter in use, for benchmark provenance.
[[nodiscard]] inline const char* cycle_counter_name() {
#if defined(__aarch64__)
  return "cntvct_el0";
#elif defined(__x86_64__) || defined(__i386__)
  return "rdtsc";
#else
  return "steady_clock";
#endif
}

}  // namespace policy
