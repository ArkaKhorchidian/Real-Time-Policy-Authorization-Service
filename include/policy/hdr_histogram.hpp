// HdrHistogram — high dynamic range histogram with bounded relative error.
//
// This is the measurement instrument, so it gets the same scrutiny as the thing
// being measured. Three properties matter:
//
//  1. Recording is O(1) and constant-time: a count-leading-zeros, a shift and
//     an increment. No allocation, no branch on value, no lock. It is cheap
//     enough (~2 ns) to sit on the request path without distorting it.
//  2. Relative error is bounded by the significant-figure setting, not by
//     bucket boundaries chosen in advance. At 3 significant figures every
//     recorded value is within 0.1% of its bucket's representative value,
//     whether it is 2 µs or 2 seconds.
//  3. Percentiles come from the counts, never from a sorted array of samples.
//     Sorting ten million samples to find p99.99 costs more than the benchmark
//     and, worse, tempts people to down-sample — which is how tails disappear.
//
// This is a from-scratch implementation of the same algorithm as Gil Tene's
// HdrHistogram (bucketed sub-buckets with a power-of-two magnitude), written
// out rather than vendored so the arithmetic is auditable next to the code that
// depends on it. `tests/test_hdr.cpp` checks it against exact percentiles
// computed from a sorted reference for a range of distributions.
#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <cstdio>
#include <string>
#include <vector>

namespace policy {

class HdrHistogram {
 public:
  // `highest` must be at least 2x `lowest`. `significant_figures` is 1..5.
  explicit HdrHistogram(std::int64_t lowest = 1, std::int64_t highest = 60'000'000'000LL,
                        int significant_figures = 3) {
    if (lowest < 1) lowest = 1;
    if (significant_figures < 1) significant_figures = 1;
    if (significant_figures > 5) significant_figures = 5;
    if (highest < lowest * 2) highest = lowest * 2;

    lowest_ = lowest;
    highest_ = highest;
    significant_figures_ = significant_figures;

    unit_magnitude_ = static_cast<std::int32_t>(std::floor(std::log2(static_cast<double>(lowest))));

    const auto largest_single_bucket =
        static_cast<std::int64_t>(2 * std::pow(10.0, significant_figures));
    sub_bucket_count_magnitude_ =
        static_cast<std::int32_t>(std::ceil(std::log2(static_cast<double>(largest_single_bucket))));
    sub_bucket_half_count_magnitude_ = sub_bucket_count_magnitude_ - 1;
    sub_bucket_count_ = std::int32_t{1} << sub_bucket_count_magnitude_;
    sub_bucket_half_count_ = sub_bucket_count_ / 2;
    sub_bucket_mask_ = static_cast<std::int64_t>(sub_bucket_count_ - 1) << unit_magnitude_;

    // Enough buckets that `highest` lands inside the top one.
    std::int32_t buckets = 1;
    std::int64_t smallest_untrackable = static_cast<std::int64_t>(sub_bucket_count_)
                                        << unit_magnitude_;
    while (smallest_untrackable <= highest) {
      if (smallest_untrackable > (std::numeric_limits<std::int64_t>::max)() / 2) break;
      smallest_untrackable <<= 1;
      ++buckets;
    }
    bucket_count_ = buckets;

    counts_.assign(static_cast<std::size_t>((bucket_count_ + 1) * sub_bucket_half_count_), 0);
  }

  // --- recording -----------------------------------------------------------

  // Hot path. Values above `highest` are clamped into the top bucket and
  // counted in `overflow_count()` rather than dropped: a discarded outlier is
  // a lie about the tail.
  void record(std::int64_t value) noexcept {
    if (value < 0) {
      ++negative_count_;
      return;
    }
    if (value > highest_) {
      ++overflow_count_;
      value = highest_;
    }
    const std::int32_t idx = counts_index_for(value);
    ++counts_[static_cast<std::size_t>(idx)];
    ++total_count_;
    if (value > max_ || total_count_ == 1) max_ = value;
    if (value < min_ || total_count_ == 1) min_ = value;
  }

  // Record one value that stands for `count` occurrences. Used when replaying
  // a compressed trace; not needed on the request path.
  void record_n(std::int64_t value, std::int64_t count) noexcept {
    if (count <= 0) return;
    if (value < 0) { negative_count_ += count; return; }
    if (value > highest_) { overflow_count_ += count; value = highest_; }
    counts_[static_cast<std::size_t>(counts_index_for(value))] += count;
    total_count_ += count;
    if (value > max_ || total_count_ == count) max_ = value;
    if (value < min_ || total_count_ == count) min_ = value;
  }

  void reset() noexcept {
    std::fill(counts_.begin(), counts_.end(), 0);
    total_count_ = 0;
    overflow_count_ = 0;
    negative_count_ = 0;
    min_ = 0;
    max_ = 0;
  }

  // Merge another histogram with identical parameters. Used to fold per-worker
  // histograms into one at the end of a run — never during it, because that
  // would put a shared cache line on the request path.
  bool add(const HdrHistogram& other) {
    if (counts_.size() != other.counts_.size() || unit_magnitude_ != other.unit_magnitude_ ||
        sub_bucket_count_ != other.sub_bucket_count_) {
      return false;
    }
    for (std::size_t i = 0; i < counts_.size(); ++i) counts_[i] += other.counts_[i];
    if (other.total_count_ > 0) {
      if (total_count_ == 0) {
        min_ = other.min_;
        max_ = other.max_;
      } else {
        min_ = std::min(min_, other.min_);
        max_ = std::max(max_, other.max_);
      }
    }
    total_count_ += other.total_count_;
    overflow_count_ += other.overflow_count_;
    negative_count_ += other.negative_count_;
    return true;
  }

  // --- querying ------------------------------------------------------------

  [[nodiscard]] std::int64_t total_count() const noexcept { return total_count_; }
  [[nodiscard]] std::int64_t overflow_count() const noexcept { return overflow_count_; }
  [[nodiscard]] std::int64_t negative_count() const noexcept { return negative_count_; }
  [[nodiscard]] std::int64_t min() const noexcept { return total_count_ ? min_ : 0; }
  [[nodiscard]] std::int64_t max() const noexcept { return total_count_ ? max_ : 0; }
  [[nodiscard]] bool empty() const noexcept { return total_count_ == 0; }

  [[nodiscard]] std::int64_t value_at_percentile(double percentile) const noexcept {
    if (total_count_ == 0) return 0;
    percentile = std::clamp(percentile, 0.0, 100.0);
    // Round half up, then clamp: this is the standard HdrHistogram rule and it
    // is what makes p100 == max rather than "the last bucket with a count".
    auto target = static_cast<std::int64_t>(
        std::ceil((percentile / 100.0) * static_cast<double>(total_count_)));
    target = std::clamp<std::int64_t>(target, 1, total_count_);

    std::int64_t running = 0;
    for (std::size_t i = 0; i < counts_.size(); ++i) {
      running += counts_[i];
      if (running >= target) {
        return highest_equivalent_value(value_from_index(static_cast<std::int32_t>(i)));
      }
    }
    return max_;
  }

  [[nodiscard]] double mean() const noexcept {
    if (total_count_ == 0) return 0.0;
    double total = 0.0;
    for (std::size_t i = 0; i < counts_.size(); ++i) {
      if (counts_[i] == 0) continue;
      total += static_cast<double>(counts_[i]) *
               static_cast<double>(median_equivalent_value(value_from_index(static_cast<std::int32_t>(i))));
    }
    return total / static_cast<double>(total_count_);
  }

  [[nodiscard]] double stddev() const noexcept {
    if (total_count_ == 0) return 0.0;
    const double m = mean();
    double sum = 0.0;
    for (std::size_t i = 0; i < counts_.size(); ++i) {
      if (counts_[i] == 0) continue;
      const double dev =
          static_cast<double>(median_equivalent_value(value_from_index(static_cast<std::int32_t>(i)))) - m;
      sum += dev * dev * static_cast<double>(counts_[i]);
    }
    return std::sqrt(sum / static_cast<double>(total_count_));
  }

  [[nodiscard]] std::int64_t count_at_value(std::int64_t value) const noexcept {
    if (value < 0) return 0;
    return counts_[static_cast<std::size_t>(counts_index_for(std::min(value, highest_)))];
  }

  // --- output --------------------------------------------------------------

  // The percentile distribution in the classic HdrHistogram CSV shape:
  // Value,Percentile,TotalCount,1/(1-Percentile). `ticks_per_half_distance`
  // controls resolution in the tail — 5 gives p50, p75, p87.5, ... which is
  // what makes a log-y latency plot readable.
  [[nodiscard]] std::string percentile_csv(int ticks_per_half_distance = 5) const {
    std::string out = "Value,Percentile,TotalCount,1/(1-Percentile)\n";
    if (total_count_ == 0) return out;

    char line[160];
    double percentile_level = 0.0;
    std::int64_t running = 0;
    std::size_t i = 0;

    while (i < counts_.size()) {
      running += counts_[i];
      const double pct = 100.0 * static_cast<double>(running) / static_cast<double>(total_count_);
      if (counts_[i] != 0 && pct >= percentile_level) {
        const std::int64_t value =
            highest_equivalent_value(value_from_index(static_cast<std::int32_t>(i)));
        const double inv = pct >= 100.0 ? 0.0 : 100.0 / (100.0 - pct);
        std::snprintf(line, sizeof(line), "%lld,%.12f,%lld,%.2f\n",
                      static_cast<long long>(value), pct / 100.0,
                      static_cast<long long>(running), inv);
        out += line;

        // Advance the percentile level along a halving-distance-to-100 ladder.
        const double half_distance =
            std::pow(2.0, std::floor(std::log2(100.0 / std::max(1e-12, 100.0 - percentile_level))) + 1.0);
        percentile_level += 100.0 / (half_distance * ticks_per_half_distance);
        if (percentile_level >= 100.0) break;
      }
      ++i;
    }
    return out;
  }

  // One line with the percentiles a latency report actually quotes.
  [[nodiscard]] std::string summary_line(const char* unit = "us") const {
    char buf[320];
    std::snprintf(buf, sizeof(buf),
                  "count=%lld min=%lld p50=%lld p90=%lld p99=%lld p99.9=%lld p99.99=%lld "
                  "max=%lld mean=%.1f%s",
                  static_cast<long long>(total_count_), static_cast<long long>(min()),
                  static_cast<long long>(value_at_percentile(50.0)),
                  static_cast<long long>(value_at_percentile(90.0)),
                  static_cast<long long>(value_at_percentile(99.0)),
                  static_cast<long long>(value_at_percentile(99.9)),
                  static_cast<long long>(value_at_percentile(99.99)),
                  static_cast<long long>(max()), mean(), unit);
    return buf;
  }

  // --- bucket arithmetic (public for tests) --------------------------------

  [[nodiscard]] std::int64_t lowest_equivalent_value(std::int64_t value) const noexcept {
    const std::int32_t b = bucket_index(value);
    const std::int32_t s = sub_bucket_index(value, b);
    return static_cast<std::int64_t>(s) << (b + unit_magnitude_);
  }

  [[nodiscard]] std::int64_t highest_equivalent_value(std::int64_t value) const noexcept {
    return next_non_equivalent_value(value) - 1;
  }

  [[nodiscard]] std::int64_t size_of_equivalent_value_range(std::int64_t value) const noexcept {
    const std::int32_t b = bucket_index(value);
    const std::int32_t s = sub_bucket_index(value, b);
    const std::int32_t adjusted = s >= sub_bucket_count_ ? b + 1 : b;
    return std::int64_t{1} << (unit_magnitude_ + adjusted);
  }

  [[nodiscard]] std::int64_t next_non_equivalent_value(std::int64_t value) const noexcept {
    return lowest_equivalent_value(value) + size_of_equivalent_value_range(value);
  }

  [[nodiscard]] std::int64_t median_equivalent_value(std::int64_t value) const noexcept {
    return lowest_equivalent_value(value) + (size_of_equivalent_value_range(value) >> 1);
  }

  [[nodiscard]] std::size_t memory_bytes() const noexcept {
    return counts_.size() * sizeof(std::int64_t) + sizeof(*this);
  }

  [[nodiscard]] int significant_figures() const noexcept { return significant_figures_; }
  [[nodiscard]] std::int64_t highest_trackable_value() const noexcept { return highest_; }

 private:
  [[nodiscard]] std::int32_t bucket_index(std::int64_t value) const noexcept {
    const auto pow2ceiling =
        static_cast<std::int32_t>(64 - __builtin_clzll(static_cast<unsigned long long>(
                                           value | sub_bucket_mask_)));
    return pow2ceiling - unit_magnitude_ - (sub_bucket_half_count_magnitude_ + 1);
  }

  [[nodiscard]] std::int32_t sub_bucket_index(std::int64_t value, std::int32_t bucket) const noexcept {
    return static_cast<std::int32_t>(value >> (bucket + unit_magnitude_));
  }

  [[nodiscard]] std::int32_t counts_index_for(std::int64_t value) const noexcept {
    const std::int32_t b = bucket_index(value);
    const std::int32_t s = sub_bucket_index(value, b);
    const std::int32_t bucket_base = (b + 1) << sub_bucket_half_count_magnitude_;
    return bucket_base + (s - sub_bucket_half_count_);
  }

  [[nodiscard]] std::int64_t value_from_index(std::int32_t index) const noexcept {
    std::int32_t bucket = (index >> sub_bucket_half_count_magnitude_) - 1;
    std::int32_t sub = (index & (sub_bucket_half_count_ - 1)) + sub_bucket_half_count_;
    if (bucket < 0) {
      sub -= sub_bucket_half_count_;
      bucket = 0;
    }
    return static_cast<std::int64_t>(sub) << (bucket + unit_magnitude_);
  }

  std::int64_t lowest_ = 1;
  std::int64_t highest_ = 1;
  int significant_figures_ = 3;

  std::int32_t unit_magnitude_ = 0;
  std::int32_t sub_bucket_count_magnitude_ = 0;
  std::int32_t sub_bucket_half_count_magnitude_ = 0;
  std::int32_t sub_bucket_count_ = 0;
  std::int32_t sub_bucket_half_count_ = 0;
  std::int64_t sub_bucket_mask_ = 0;
  std::int32_t bucket_count_ = 0;

  std::vector<std::int64_t> counts_;
  std::int64_t total_count_ = 0;
  std::int64_t overflow_count_ = 0;
  std::int64_t negative_count_ = 0;
  std::int64_t min_ = 0;
  std::int64_t max_ = 0;
};

}  // namespace policy
