// Open-addressing set of uint64 keys, used for the IMEI blocklist and the
// roaming-partner PLMN table.
//
// Both are read on the request path and written only by the control plane, so
// the set is built once, immutable afterwards, and lives inside the RuleSet
// snapshot. Linear probing over a power-of-two table gives one cache miss for a
// hit and, at the load factor used here (<= 0.5), one for a miss too.
//
// Key 0 is the empty sentinel. That is safe for both users: IMEI 0 means "not
// reported" and is never looked up, and PLMN 0 is not a valid network.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace policy {

class FlatSet64 {
 public:
  FlatSet64() = default;

  // Build from a key list. Duplicates and zeros are dropped.
  explicit FlatSet64(const std::vector<std::uint64_t>& keys) { rebuild(keys); }

  void rebuild(const std::vector<std::uint64_t>& keys) {
    size_ = 0;
    if (keys.empty()) {
      slots_.clear();
      mask_ = 0;
      return;
    }
    // Keep load factor <= 0.5 so probe chains stay short.
    std::size_t cap = 8;
    while (cap < keys.size() * 2) cap <<= 1;
    slots_.assign(cap, 0);
    mask_ = cap - 1;
    for (const std::uint64_t k : keys) insert(k);
  }

  // Hot path. Marked noexcept and kept branch-light on purpose.
  [[nodiscard]] bool contains(std::uint64_t key) const noexcept {
    if (slots_.empty() || key == 0) return false;
    std::size_t i = hash(key) & mask_;
    for (;;) {
      const std::uint64_t s = slots_[i];
      if (s == key) return true;
      if (s == 0) return false;
      i = (i + 1) & mask_;
    }
  }

  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] std::size_t capacity() const noexcept { return slots_.size(); }
  [[nodiscard]] std::size_t memory_bytes() const noexcept {
    return slots_.size() * sizeof(std::uint64_t);
  }

  // Iterate the live keys, for the admin API. Order is unspecified.
  template <typename Fn>
  void for_each(Fn&& fn) const {
    for (const std::uint64_t s : slots_) {
      if (s != 0) fn(s);
    }
  }

 private:
  void insert(std::uint64_t key) {
    if (key == 0) return;
    std::size_t i = hash(key) & mask_;
    for (;;) {
      if (slots_[i] == key) return;  // duplicate
      if (slots_[i] == 0) {
        slots_[i] = key;
        ++size_;
        return;
      }
      i = (i + 1) & mask_;
    }
  }

  // splitmix64 finalizer. IMSIs and IMEIs are dense decimal integers whose low
  // bits are far from uniform, so the identity hash would cluster badly.
  static constexpr std::uint64_t hash(std::uint64_t x) noexcept {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
  }

  std::vector<std::uint64_t> slots_;
  std::size_t mask_ = 0;
  std::size_t size_ = 0;
};

}  // namespace policy
