// The histogram is the measurement instrument, so it is checked against exact
// percentiles computed from sorted reference data.
#include <algorithm>
#include <cmath>
#include <random>
#include <vector>

#include "policy/hdr_histogram.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

// The definition HdrHistogram implements: the smallest value at or below which
// at least `p`% of the samples fall.
std::int64_t exact_percentile(std::vector<std::int64_t> sorted, double p) {
  if (sorted.empty()) return 0;
  auto rank = static_cast<std::size_t>(
      std::ceil((p / 100.0) * static_cast<double>(sorted.size())));
  if (rank == 0) rank = 1;
  if (rank > sorted.size()) rank = sorted.size();
  return sorted[rank - 1];
}

void check_against_reference(const std::vector<std::int64_t>& samples, int sig_figs,
                             const char* label) {
  HdrHistogram h(1, 60'000'000'000LL, sig_figs);
  for (const std::int64_t v : samples) h.record(v);

  std::vector<std::int64_t> sorted = samples;
  std::sort(sorted.begin(), sorted.end());

  CHECK_EQ(h.total_count(), static_cast<std::int64_t>(samples.size()));
  CHECK_EQ(h.min(), sorted.front());
  CHECK_EQ(h.max(), sorted.back());
  // p0 and p100 bracket the true extremes from the bucket-top side.
  CHECK_GE(h.value_at_percentile(100.0), sorted.back());
  CHECK_LE(h.value_at_percentile(0.0), h.highest_equivalent_value(sorted.front()));

  // The guarantee is relative, not absolute: every reported value is within
  // 10^-sig_figs of the true one.
  const double tolerance = std::pow(10.0, -sig_figs) * 2.0;
  for (const double p : {0.0, 25.0, 50.0, 90.0, 99.0, 99.9, 99.99, 100.0}) {
    const std::int64_t want = exact_percentile(sorted, p);
    const std::int64_t got = h.value_at_percentile(p);
    const double rel = want == 0 ? 0.0
                                 : std::fabs(static_cast<double>(got - want)) /
                                       static_cast<double>(want);
    CHECK_MSG(rel <= tolerance, std::string(label) + " p" + std::to_string(p) + ": want " +
                                    std::to_string(want) + " got " + std::to_string(got) +
                                    " (relative error " + std::to_string(rel) + ")");
  }
}

}  // namespace

TEST(Hdr, EmptyHistogram) {
  HdrHistogram h;
  CHECK(h.empty());
  CHECK_EQ(h.total_count(), std::int64_t{0});
  CHECK_EQ(h.value_at_percentile(50.0), std::int64_t{0});
  CHECK_EQ(h.min(), std::int64_t{0});
  CHECK_EQ(h.max(), std::int64_t{0});
  CHECK_EQ(h.mean(), 0.0);
}

TEST(Hdr, SingleValue) {
  HdrHistogram h;
  h.record(1000);
  CHECK_EQ(h.total_count(), std::int64_t{1});
  CHECK_EQ(h.min(), std::int64_t{1000});
  CHECK_EQ(h.max(), std::int64_t{1000});
  CHECK_EQ(h.value_at_percentile(0.0), h.highest_equivalent_value(1000));
  CHECK_EQ(h.value_at_percentile(50.0), h.highest_equivalent_value(1000));
  CHECK_EQ(h.value_at_percentile(100.0), h.highest_equivalent_value(1000));
}

TEST(Hdr, UniformDistributionMatchesReference) {
  std::mt19937_64 rng(1);
  std::uniform_int_distribution<std::int64_t> dist(1, 1'000'000);
  std::vector<std::int64_t> samples;
  samples.reserve(100000);
  for (int i = 0; i < 100000; ++i) samples.push_back(dist(rng));
  check_against_reference(samples, 3, "uniform");
}

TEST(Hdr, LogNormalWithALongTailMatchesReference) {
  // This is the shape latency actually has: a tight body and a tail several
  // orders of magnitude out. It is the case a fixed-bucket histogram gets wrong.
  std::mt19937_64 rng(2);
  std::lognormal_distribution<double> dist(9.0, 1.2);
  std::vector<std::int64_t> samples;
  samples.reserve(200000);
  for (int i = 0; i < 200000; ++i) {
    samples.push_back(std::max<std::int64_t>(1, static_cast<std::int64_t>(dist(rng))));
  }
  // Plant a few genuine outliers four orders of magnitude out.
  for (int i = 0; i < 5; ++i) samples.push_back(2'000'000'000LL);
  check_against_reference(samples, 3, "lognormal");
}

TEST(Hdr, BimodalDistributionMatchesReference) {
  // A fast path and a slow path — a cache hit and a cache miss, say.
  std::mt19937_64 rng(3);
  std::normal_distribution<double> fast(500.0, 50.0);
  std::normal_distribution<double> slow(50000.0, 5000.0);
  std::vector<std::int64_t> samples;
  for (int i = 0; i < 100000; ++i) {
    const double v = (i % 100 < 98) ? fast(rng) : slow(rng);
    samples.push_back(std::max<std::int64_t>(1, static_cast<std::int64_t>(v)));
  }
  check_against_reference(samples, 3, "bimodal");
}

TEST(Hdr, RelativeErrorIsBoundedBySignificantFigures) {
  for (const int sig : {1, 2, 3, 4}) {
    HdrHistogram h(1, 60'000'000'000LL, sig);
    const double tolerance = std::pow(10.0, -sig);
    for (std::int64_t v = 1; v < 10'000'000'000LL; v = static_cast<std::int64_t>(static_cast<double>(v) * 1.37) + 1) {
      const std::int64_t reported = h.highest_equivalent_value(v);
      const double rel = std::fabs(static_cast<double>(reported - v)) / static_cast<double>(v);
      CHECK_MSG(rel <= tolerance,
                "sig=" + std::to_string(sig) + " value=" + std::to_string(v) + " reported=" +
                    std::to_string(reported) + " rel=" + std::to_string(rel));
    }
  }
}

TEST(Hdr, ValuesAboveTheRangeAreClampedAndCounted) {
  // Discarding an outlier is a lie about the tail; silently dropping it is
  // worse. It is clamped into the top bucket and counted separately.
  HdrHistogram h(1, 1'000'000, 3);
  for (int i = 0; i < 100; ++i) h.record(500);
  h.record(999'999'999);
  CHECK_EQ(h.overflow_count(), std::int64_t{1});
  CHECK_EQ(h.total_count(), std::int64_t{101});
  CHECK_GE(h.max(), std::int64_t{1'000'000});
  // p100 is reported as the top of the bucket the maximum fell in, so it is at
  // or above max() and within one bucket width of it.
  CHECK_GE(h.value_at_percentile(100.0), h.max());
  CHECK_LE(h.value_at_percentile(100.0), h.highest_equivalent_value(h.max()));
}

TEST(Hdr, NegativeValuesAreCountedNotRecorded) {
  HdrHistogram h;
  h.record(-1);
  CHECK_EQ(h.negative_count(), std::int64_t{1});
  CHECK_EQ(h.total_count(), std::int64_t{0});
}

TEST(Hdr, AddMergesCounts) {
  HdrHistogram a(1, 1'000'000, 3);
  HdrHistogram b(1, 1'000'000, 3);
  for (int i = 1; i <= 1000; ++i) a.record(i);
  for (int i = 1001; i <= 2000; ++i) b.record(i);

  HdrHistogram merged(1, 1'000'000, 3);
  CHECK(merged.add(a));
  CHECK(merged.add(b));
  CHECK_EQ(merged.total_count(), std::int64_t{2000});
  CHECK_EQ(merged.min(), std::int64_t{1});
  CHECK_GE(merged.max(), std::int64_t{2000});
  CHECK_LE(std::abs(merged.value_at_percentile(50.0) - 1000), std::int64_t{5});

  // Merging incompatible histograms must fail rather than produce nonsense.
  HdrHistogram other(1, 1'000'000, 2);
  CHECK(!merged.add(other));
}

TEST(Hdr, RecordNIsEquivalentToRepeatedRecord) {
  HdrHistogram a(1, 1'000'000, 3);
  HdrHistogram b(1, 1'000'000, 3);
  for (int i = 0; i < 1000; ++i) a.record(12345);
  b.record_n(12345, 1000);
  CHECK_EQ(a.total_count(), b.total_count());
  CHECK_EQ(a.value_at_percentile(50.0), b.value_at_percentile(50.0));
  CHECK_EQ(a.min(), b.min());
  CHECK_EQ(a.max(), b.max());
}

TEST(Hdr, ResetClearsEverything) {
  HdrHistogram h;
  for (int i = 0; i < 1000; ++i) h.record(i + 1);
  h.reset();
  CHECK(h.empty());
  CHECK_EQ(h.total_count(), std::int64_t{0});
  CHECK_EQ(h.value_at_percentile(99.0), std::int64_t{0});
}

TEST(Hdr, PercentileCsvIsWellFormedAndMonotonic) {
  HdrHistogram h;
  std::mt19937_64 rng(4);
  std::lognormal_distribution<double> dist(8.0, 1.0);
  for (int i = 0; i < 50000; ++i) {
    h.record(std::max<std::int64_t>(1, static_cast<std::int64_t>(dist(rng))));
  }
  const std::string csv = h.percentile_csv();
  CHECK_MSG(csv.rfind("Value,Percentile,TotalCount,1/(1-Percentile)\n", 0) == 0,
            "unexpected CSV header");

  // Values and cumulative counts must both be non-decreasing down the file.
  std::int64_t prev_value = -1, prev_count = -1;
  std::size_t pos = csv.find('\n') + 1;
  int rows = 0;
  while (pos < csv.size()) {
    const auto eol = csv.find('\n', pos);
    if (eol == std::string::npos) break;
    const std::string row = csv.substr(pos, eol - pos);
    pos = eol + 1;
    const auto c1 = row.find(',');
    const auto c2 = row.find(',', c1 + 1);
    const auto c3 = row.find(',', c2 + 1);
    if (c3 == std::string::npos) continue;
    const std::int64_t value = std::stoll(row.substr(0, c1));
    const std::int64_t count = std::stoll(row.substr(c2 + 1, c3 - c2 - 1));
    CHECK_GE(value, prev_value);
    CHECK_GE(count, prev_count);
    prev_value = value;
    prev_count = count;
    ++rows;
  }
  CHECK_GT(rows, 20);
}

TEST(Hdr, MemoryFootprintIsSmallEnoughForOnePerWorker) {
  // One of these lives in every worker's metrics block; if it were megabytes,
  // it would evict the rule table it sits next to.
  const HdrHistogram h(1, 10'000'000, 3);
  CHECK_LT(h.memory_bytes(), std::size_t{256 * 1024});
}
