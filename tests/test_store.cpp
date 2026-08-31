// Subscriber store: correctness of the open-addressing table, the CSV loader,
// and the probe-length properties the latency argument depends on.
#include <random>
#include <set>

#include "policy/imsi.hpp"
#include "policy/subscriber_store.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

SubscriberRecord make_record(std::uint64_t imsi, std::uint32_t plan = 0) {
  SubscriberRecord r{};
  r.imsi = imsi;
  r.imei = 350000000000000ull + imsi % 1000000;
  r.plan_id = plan;
  r.status = static_cast<std::uint32_t>(SubscriberStatus::kActive);
  r.home_plmn = 310260;
  return r;
}

}  // namespace

TEST(Store, RecordIsOneCacheLine) {
  CHECK_EQ(sizeof(SubscriberRecord), std::size_t{64});
  CHECK_EQ(alignof(SubscriberRecord), std::size_t{64});
}

TEST(Store, InsertAndFind) {
  SubscriberStore store(1024);
  for (std::uint64_t i = 1; i <= 500; ++i) store.upsert(make_record(310260000000000ull + i));

  CHECK_EQ(store.size(), std::size_t{500});
  for (std::uint64_t i = 1; i <= 500; ++i) {
    const auto* r = store.find(310260000000000ull + i);
    REQUIRE(r != nullptr);
    CHECK_EQ(r->imsi, 310260000000000ull + i);
  }
  CHECK(store.find(310260000000501ull) == nullptr);
  // IMSI 0 is the empty-slot sentinel and must never be findable.
  CHECK(store.find(0) == nullptr);
}

TEST(Store, UpsertReplacesInPlace) {
  SubscriberStore store(64);
  store.upsert(make_record(123456789012345ull, 1));
  store.upsert(make_record(123456789012345ull, 3));
  CHECK_EQ(store.size(), std::size_t{1});
  const auto* r = store.find(123456789012345ull);
  REQUIRE(r != nullptr);
  CHECK_EQ(r->plan_id, 3u);
}

TEST(Store, GrowsAndKeepsEverything) {
  // Start deliberately undersized so the table has to rehash several times.
  SubscriberStore store(8);
  std::set<std::uint64_t> expected;
  std::mt19937_64 rng(999);
  for (int i = 0; i < 5000; ++i) {
    const std::uint64_t imsi = 100000000000000ull + rng() % 899999999999999ull;
    store.upsert(make_record(imsi));
    expected.insert(imsi);
  }
  CHECK_EQ(store.size(), expected.size());
  for (const std::uint64_t imsi : expected) {
    CHECK_MSG(store.find(imsi) != nullptr, "lost IMSI " + format_imsi(imsi) + " across a rehash");
  }
}

TEST(Store, LoadFactorStaysAtOrBelowHalf) {
  // The whole "one cache miss per lookup" claim rests on this. At load factor
  // 0.5, linear probing averages ~1.5 probes; at 0.9 it is ~5.5.
  for (const std::size_t n : {100u, 1000u, 10000u, 50000u}) {
    SubscriberStore store(16, 0.5);
    for (std::size_t i = 1; i <= n; ++i) store.upsert(make_record(310260000000000ull + i));
    const auto st = store.stats();
    CHECK_MSG(st.load_factor <= 0.5,
              "load factor " + std::to_string(st.load_factor) + " at n=" + std::to_string(n));
  }
}

TEST(Store, SequentialImsisDoNotClusterCatastrophically) {
  // Carriers allocate IMSIs in contiguous blocks. An identity hash over the low
  // bits would turn that into one enormous probe chain; the splitmix64
  // finalizer is what prevents it, and this is the test that would catch its
  // removal.
  SubscriberStore store(200000);
  for (std::uint64_t i = 0; i < 100000; ++i) store.upsert(make_record(310260100000000ull + i));

  const auto st = store.stats();
  CHECK_LT(st.mean_probe_length, 2.0);
  CHECK_LT(st.max_probe_length, std::size_t{64});
}

TEST(Store, UsageAccumulatesAndPeriodResets) {
  SubscriberStore store(64);
  const std::uint64_t imsi = 310260100000001ull;
  store.upsert(make_record(imsi));

  store.add_usage(imsi, 1000);
  store.add_usage(imsi, 2500);
  const auto* r = store.find(imsi);
  REQUIRE(r != nullptr);
  CHECK_EQ(load_usage(*r), std::uint64_t{3500});

  CHECK(store.reset_period(imsi, 1790000000ull));
  CHECK_EQ(load_usage(*r), std::uint64_t{0});
  CHECK_EQ(r->period_reset_ts, std::uint64_t{1790000000});

  // Operations on an unknown IMSI are no-ops, not crashes.
  store.add_usage(999999999999999ull, 100);
  CHECK(!store.reset_period(999999999999999ull, 0));
}

TEST(Store, MemoryMathMatchesTheDocumentedSizing) {
  // The README quotes these figures, so pin them here. Computed rather than
  // allocated: the test suite should not need a spare two gigabytes.
  //
  // At the default 0.5 ceiling, 10M subscribers need 20M slots, and the next
  // power of two is 33.5M -> 2.15 GB at an actual load factor of 0.30.
  CHECK_EQ(SubscriberStore::slots_for(10'000'000, 0.5), std::size_t{33554432});
  CHECK_EQ(SubscriberStore::bytes_for(10'000'000, 0.5), std::size_t{2147483648});

  // The same table holds 16.7M subscribers before it would rehash, so a
  // deployment sized for 10M has 67% headroom at no extra cost.
  CHECK_EQ(SubscriberStore::slots_for(16'700'000, 0.5), std::size_t{33554432});

  // Accepting a 0.6 ceiling halves it: 10M fits in 16.8M slots and 1.07 GB.
  CHECK_EQ(SubscriberStore::slots_for(10'000'000, 0.6), std::size_t{16777216});
  CHECK_EQ(SubscriberStore::bytes_for(10'000'000, 0.6), std::size_t{1073741824});
}

TEST(Store, LoadFactorCeilingIsHonoured) {
  for (const double ceiling : {0.25, 0.5, 0.6, 0.8}) {
    SubscriberStore store(16, ceiling);
    for (std::size_t i = 1; i <= 20000; ++i) store.upsert(make_record(310260000000000ull + i));
    const auto st = store.stats();
    CHECK_MSG(st.load_factor <= ceiling + 1e-9,
              "load factor " + std::to_string(st.load_factor) + " exceeded ceiling " +
                  std::to_string(ceiling));
    // A higher ceiling really does mean longer probe chains — this is the
    // trade the default is making.
    CHECK_GT(st.mean_probe_length, 0.99);
  }
}

TEST(Store, CsvLoaderRejectsUnknownPlans) {
  // A typo in the roster must be an error. Falling back to plan 0 would
  // silently downgrade every affected subscriber's QoS and quota.
  const std::string path = "test_store_bad_plan.csv";
  {
    std::FILE* f = std::fopen(path.c_str(), "w");
    REQUIRE(f != nullptr);
    std::fputs("imsi,imei,plan,status,bytes_used,period_reset_ts,home_plmn,flags\n", f);
    std::fputs("310260100000001,350000000000018,dev-basic,ACTIVE,0,1790000000,310-260,roaming\n", f);
    std::fputs("310260100000002,350000000000026,dev-bassic,ACTIVE,0,1790000000,310-260,\n", f);
    std::fclose(f);
  }
  SubscriberStore store(64);
  const auto res = store.load_csv(path, {"dev-basic", "dev-pro"});
  CHECK_EQ(res.loaded, std::size_t{1});
  CHECK_EQ(res.skipped, std::size_t{1});
  CHECK(!res.ok());
  std::remove(path.c_str());
}

TEST(Store, CsvLoaderParsesEveryColumn) {
  const std::string path = "test_store_ok.csv";
  {
    std::FILE* f = std::fopen(path.c_str(), "w");
    REQUIRE(f != nullptr);
    std::fputs("imsi,imei,plan,status,bytes_used,period_reset_ts,home_plmn,flags\n", f);
    std::fputs("310260100000001,350000000000018,dev-pro,SUSPENDED,12345,1790000000,310-260,roaming|tethering\n", f);
    std::fputs("# a comment line\n", f);
    std::fputs("\n", f);
    std::fputs("234015100000002,,dev-basic,BARRED,0,1790000000,234-15,\n", f);
    std::fclose(f);
  }
  SubscriberStore store(64);
  const auto res = store.load_csv(path, {"dev-basic", "dev-pro"});
  CHECK(res.ok());
  CHECK_EQ(res.loaded, std::size_t{2});

  const auto* a = store.find(310260100000001ull);
  REQUIRE(a != nullptr);
  CHECK_EQ(a->plan_id, 1u);
  CHECK_EQ(a->status, static_cast<std::uint32_t>(SubscriberStatus::kSuspended));
  CHECK_EQ(a->bytes_used_period, std::uint64_t{12345});
  CHECK_EQ(a->home_plmn, 310260u);
  CHECK_EQ(a->flags, std::uint32_t{kSubRoamingAllowed | kSubTetheringAllowed});

  const auto* b = store.find(234015100000002ull);
  REQUIRE(b != nullptr);
  CHECK_EQ(b->imei, std::uint64_t{0});
  CHECK_EQ(b->status, static_cast<std::uint32_t>(SubscriberStatus::kBarred));
  CHECK_EQ(b->home_plmn, 234015u);
  std::remove(path.c_str());
}
