// Subscriber store: flat open-addressing hash on the packed IMSI.
//
// Memory math, worked out rather than asserted, because sizing for a real
// carrier is the point and the round number people quote is wrong:
//
//   SubscriberRecord            = 64 B (one cache line, alignas(64))
//   target load factor          <= 0.5 -> at least 2 slots per subscriber
//   10,000,000 subscribers      -> needs >= 20,000,000 slots
//                               -> next power of two is 33,554,432
//                               -> 33,554,432 * 64 B = 2.15 GB, load factor 0.30
//
// It is 2.15 GB, not the 1 GB that "10M x 64 B x 2" suggests, because the table
// size is a power of two and 20M lands just past the 16.8M boundary. That
// granularity is not wasted, though: the same 2.15 GB holds 16.7M subscribers
// at load factor 0.5, so a deployment sized for 10M gets 67% headroom for free
// and will not rehash until it is genuinely outgrown.
//
// If 2.15 GB is the wrong trade, `max_load_factor` moves it: at 0.6 the same
// 10M subscribers fit in 16,777,216 slots and 1.07 GB. Linear probing costs
// ~1.5 probes per hit at load factor 0.5 and ~1.8 at 0.6 — a real but modest
// tail cost for halving the resident set. The default is 0.5 because this
// service is judged on its p99.9.
//
// Either way a 10M-subscriber image fits in one machine's RAM, which is why the
// store is a flat array rather than a sharded cache in front of a database.
//
// Layout choice: records live inline in the slot array rather than as indices
// into a separate value array. A lookup is then exactly one cache miss on a
// hit — the probe load and the record load are the same load. The alternative
// (uint64 key array + parallel record array) halves the memory touched while
// probing but costs a second dependent miss on every hit; at load factor 0.5
// the average probe length is ~1.5, so inline wins. Both were measured; see
// bench/results/store_layout.csv.
//
// Concurrency: the store is built once at startup and read-only on the request
// path. Mutations (usage counter updates, status changes) go through the
// control plane and use per-record atomics — a subscriber's usage counter is
// the only field a worker may ever write, and it is written with relaxed
// atomics because an exactly-current byte count is not what a policy decision
// needs; a bounded-staleness one is.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace policy {

enum class SubscriberStatus : std::uint32_t {
  kActive = 0,
  kSuspended = 1,
  kBarred = 2,
};

enum SubscriberFlag : std::uint32_t {
  kSubRoamingAllowed = 1u << 0,
  kSubTetheringAllowed = 1u << 1,
  kSubVolteEnabled = 1u << 2,
  kSubTestSubscriber = 1u << 3,
};

struct alignas(64) SubscriberRecord {
  std::uint64_t imsi;               //  0  packed 15 digits; 0 = empty slot
  std::uint64_t imei;               //  8  packed, 0 if unknown
  std::uint32_t plan_id;            // 16
  std::uint32_t status;             // 20  SubscriberStatus
  std::uint64_t bytes_used_period;  // 24
  std::uint64_t period_reset_ts;    // 32  unix seconds
  std::uint32_t home_plmn;          // 40
  std::uint32_t flags;              // 44  SubscriberFlag
  std::uint8_t _pad[16];            // 48  reserved: per-subscriber overrides
};
static_assert(sizeof(SubscriberRecord) == 64, "SubscriberRecord must be one cache line");
static_assert(alignof(SubscriberRecord) == 64);
static_assert(std::is_trivially_copyable_v<SubscriberRecord>);

// Relaxed atomic access to the one field a worker thread may write while other
// threads read it. Using the builtins rather than reinterpret_cast'ing the
// field to std::atomic keeps the record trivially copyable and 64 bytes, and
// keeps ThreadSanitizer quiet about a race that is intentional.
[[nodiscard]] inline std::uint64_t load_usage(const SubscriberRecord& r) noexcept {
  return __atomic_load_n(&r.bytes_used_period, __ATOMIC_RELAXED);
}

struct StoreStats {
  std::size_t size = 0;
  std::size_t capacity = 0;
  std::size_t memory_bytes = 0;
  double load_factor = 0.0;
  double mean_probe_length = 0.0;
  std::size_t max_probe_length = 0;
};

class SubscriberStore {
 public:
  // `expected_subscribers` sizes the table: capacity is the next power of two
  // at or above `expected / max_load_factor`, so the table never rehashes at
  // the expected size. `max_load_factor` is clamped to [0.25, 0.9].
  explicit SubscriberStore(std::size_t expected_subscribers = 1024,
                           double max_load_factor = 0.5);

  // The load factor at which the table doubles.
  [[nodiscard]] double max_load_factor() const noexcept { return max_load_factor_; }

  // Slots needed for `n` subscribers at `load_factor`, and the bytes they cost.
  // Exposed so the sizing arithmetic above is executable rather than a comment.
  [[nodiscard]] static std::size_t slots_for(std::size_t n, double load_factor = 0.5);
  [[nodiscard]] static std::size_t bytes_for(std::size_t n, double load_factor = 0.5) {
    return slots_for(n, load_factor) * sizeof(SubscriberRecord);
  }

  SubscriberStore(const SubscriberStore&) = delete;
  SubscriberStore& operator=(const SubscriberStore&) = delete;

  // Request path. Returns nullptr when the IMSI is not provisioned — an
  // unknown subscriber is a policy outcome, not an error.
  [[nodiscard]] const SubscriberRecord* find(std::uint64_t imsi) const noexcept {
    if (imsi == 0) return nullptr;
    std::size_t i = hash(imsi) & mask_;
    for (;;) {
      const SubscriberRecord& r = slots_[i];
      if (r.imsi == imsi) return &r;
      if (r.imsi == 0) return nullptr;
      i = (i + 1) & mask_;
    }
  }

  // Provisioning path. Overwrites an existing record with the same IMSI.
  // Returns false if the table is full (which cannot happen at load factor
  // 0.5 unless the caller under-sized it — the store grows instead).
  bool upsert(const SubscriberRecord& rec);

  // Accumulate usage. Relaxed because the reader tolerates bounded staleness.
  void add_usage(std::uint64_t imsi, std::uint64_t bytes) noexcept;

  // Reset a subscriber's metering period.
  bool reset_period(std::uint64_t imsi, std::uint64_t new_reset_ts) noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return slots_.size(); }
  [[nodiscard]] StoreStats stats() const;

  // Bulk load from CSV. Format (header required):
  //   imsi,imei,plan,status,bytes_used,period_reset_ts,home_plmn,flags
  // `plan_name_to_id` resolves the plan column; unknown plans are an error so a
  // typo in the roster cannot silently downgrade a subscriber to plan 0.
  struct LoadResult {
    std::size_t loaded = 0;
    std::size_t skipped = 0;
    std::vector<std::string> errors;  // capped, see kMaxReportedErrors
    [[nodiscard]] bool ok() const noexcept { return errors.empty(); }
  };

  LoadResult load_csv(const std::string& path,
                      const std::vector<std::string>& plan_names);

  // Iterate live records, for the admin API and for snapshots.
  template <typename Fn>
  void for_each(Fn&& fn) const {
    for (const auto& r : slots_) {
      if (r.imsi != 0) fn(r);
    }
  }

 private:
  static constexpr std::size_t kMaxReportedErrors = 32;

  static constexpr std::uint64_t hash(std::uint64_t x) noexcept {
    // splitmix64: IMSIs are sequential in practice (a carrier allocates
    // contiguous ranges), so the low bits alone would collide catastrophically.
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
  }

  void grow(std::size_t new_capacity);
  [[nodiscard]] SubscriberRecord* find_mutable(std::uint64_t imsi) noexcept;

  std::vector<SubscriberRecord> slots_;
  std::size_t mask_ = 0;
  std::size_t size_ = 0;
  double max_load_factor_ = 0.5;
};

// Round `n` up to a power of two, minimum 8.
[[nodiscard]] std::size_t next_pow2(std::size_t n);

}  // namespace policy
