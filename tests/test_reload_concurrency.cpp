// Hot reload under load.
//
// The claim is: rules can be swapped while requests are in flight, with no
// dropped requests, no crashes, and every reply carrying a coherent policy
// version. This test hammers that claim — thousands of reloads while worker
// threads evaluate continuously — and is the test that is run under ASan and
// TSan in CI, where a use-after-free or a data race in the RCU path becomes a
// hard failure rather than a rare flake.
#include <atomic>
#include <random>
#include <thread>
#include <vector>

#include "policy/coarse_clock.hpp"
#include "policy/engine.hpp"
#include "policy/rcu.hpp"
#include "policy/request_gen.hpp"
#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

// Each generated version changes both the table contents and the
// authorization, so a reader that straddled a swap would produce a decision
// that matches neither version — which is what the coherence check detects.
std::string rules_for_version(std::uint32_t v) {
  const unsigned ul = 1 + (v % 50);
  return std::string(
             "dnns: [internet, ims, iot]\n"
             "plans:\n"
             "  - name: p1\n"
             "    qos_5qi: 9\n"
             "    arp: 8\n"
             "    ambr_ul: ") +
         std::to_string(ul) +
         "Mbps\n"
         "    ambr_dl: 100Mbps\n"
         "    quota: 20GB\n"
         "    quota_validity: 30d\n"
         "    rating_group: 100\n"
         "    tethering: true\n"
         "rules:\n"
         "  - id: 11\n    priority: 11\n    when: {status: UNKNOWN}\n"
         "    action: {verdict: DENY, reason: UNKNOWN_SUBSCRIBER}\n"
         "  - id: 30\n    priority: 30\n    when: {roaming: true}\n"
         "    action: {verdict: DENY, reason: ROAMING_NOT_ALLOWED}\n"
         "  - id: 100\n    priority: 100\n    when: {status: ACTIVE}\n"
         "    action: {verdict: ALLOW, reason: PLAN_DEFAULT, inherit: all}\n";
}

std::unique_ptr<RuleSet> build(std::uint32_t version) {
  auto compiled = compile_rules(rules_for_version(version), "reload-test", version);
  if (!compiled.ok()) {
    std::fprintf(stderr, "reload fixture failed to compile: %s\n",
                 compiled.error_summary().c_str());
    std::abort();
  }
  return std::move(compiled.rule_set);
}

}  // namespace

TEST(ReloadConcurrency, ThousandSwapsUnderContinuousLoad) {
  constexpr int kSwaps = 1000;
  constexpr int kWorkers = 4;

  SubscriberStore store(4096);
  std::mt19937_64 rng(4242);
  std::vector<std::uint64_t> imsis;
  for (int i = 0; i < 2000; ++i) {
    SubscriberRecord r{};
    r.imsi = 310260100000000ull + static_cast<std::uint64_t>(i);
    r.imei = 350000000000000ull + static_cast<std::uint64_t>(i);
    r.plan_id = 0;
    r.status = static_cast<std::uint32_t>(i % 50 == 0 ? SubscriberStatus::kSuspended
                                                      : SubscriberStatus::kActive);
    r.bytes_used_period = rng() % 30'000'000'000ull;
    r.period_reset_ts = kGoldenClockUnixS + 86400;
    r.home_plmn = 310260;
    r.flags = kSubRoamingAllowed;
    store.upsert(r);
    imsis.push_back(r.imsi);
  }
  set_coarse_now_unix_s(kGoldenClockUnixS);

  RcuDomain<RuleSet> domain(kWorkers + 2);
  domain.publish(build(1));

  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> evaluations{0};
  std::atomic<int> version_zero{0};
  std::atomic<int> incoherent{0};
  std::atomic<int> null_snapshot{0};

  std::vector<std::thread> workers;
  for (int w = 0; w < kWorkers; ++w) {
    workers.emplace_back([&, w] {
      const std::size_t slot = domain.register_reader();
      RequestGenerator gen(9000 + static_cast<std::uint64_t>(w), imsis, {}, {310260, 46000}, 3);
      PolicyRequest req;
      while (!stop.load(std::memory_order_relaxed)) {
        // One acquisition per batch of requests, exactly as the server does.
        const auto guard = domain.read(slot);
        const RuleSet* rs = guard.get();
        if (rs == nullptr) {
          null_snapshot.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
        const std::uint32_t version = rs->version;
        const std::uint32_t expected_ul = (1 + (version % 50)) * 1000;

        for (int k = 0; k < 32; ++k) {
          gen.fill(req);
          if (req.plmn == 0) req.plmn = 310260;
          const PolicyDecision d = evaluate(*rs, req, store.find(req.imsi));

          // Every reply must carry a real policy version...
          if (d.policy_version == 0) version_zero.fetch_add(1, std::memory_order_relaxed);
          // ...and its authorization must be the one that version defines.
          // A decision built half from one snapshot and half from another
          // would land here.
          if (d.verdict == static_cast<std::uint8_t>(Verdict::kAllow) &&
              d.ambr_ul_kbps != expected_ul) {
            incoherent.fetch_add(1, std::memory_order_relaxed);
          }
          evaluations.fetch_add(1, std::memory_order_relaxed);
        }
      }
      domain.unregister_reader(slot);
    });
  }

  int timeouts = 0;
  for (std::uint32_t v = 2; v <= kSwaps + 1; ++v) {
    if (!domain.swap_and_reclaim(build(v), std::chrono::milliseconds(2000))) ++timeouts;
  }
  stop.store(true, std::memory_order_relaxed);
  for (auto& t : workers) t.join();

  CHECK_MSG(timeouts == 0, std::to_string(timeouts) + " RCU grace period(s) timed out");
  CHECK_EQ(version_zero.load(), 0);
  CHECK_EQ(incoherent.load(), 0);
  CHECK_EQ(null_snapshot.load(), 0);
  CHECK_GT(evaluations.load(), std::uint64_t{100000});

  // Nothing may be left parked for a later grace period.
  CHECK_EQ(domain.deferred_retire_count(), std::size_t{0});

  const auto guard = domain.read(domain.register_reader());
  REQUIRE(guard.get() != nullptr);
  CHECK_EQ(guard->version, static_cast<std::uint32_t>(kSwaps + 1));
}

TEST(ReloadConcurrency, ReadersNeverObserveAPartiallyBuiltSnapshot) {
  // A snapshot is published only after it is fully constructed. If publication
  // were not release-ordered, a reader could see the pointer before the rule
  // vector's contents, and would scan uninitialized memory.
  constexpr int kIterations = 2000;
  RcuDomain<RuleSet> domain(4);
  domain.publish(build(1));

  std::atomic<bool> stop{false};
  std::atomic<int> bad{0};

  std::thread reader([&] {
    const std::size_t slot = domain.register_reader();
    while (!stop.load(std::memory_order_relaxed)) {
      const auto guard = domain.read(slot);
      const RuleSet* rs = guard.get();
      if (rs == nullptr) continue;
      // Everything a worker touches must be consistent with the version.
      if (rs->rules.empty() || rs->plan_count == 0 || rs->version == 0 ||
          rs->plan_names.size() != rs->plan_count || rs->dnn_names.size() != 3) {
        bad.fetch_add(1, std::memory_order_relaxed);
      }
      for (const auto& r : rs->rules) {
        if (r.id == 0 || r.action.verdict > 2) bad.fetch_add(1, std::memory_order_relaxed);
      }
    }
    domain.unregister_reader(slot);
  });

  for (std::uint32_t v = 2; v <= kIterations; ++v) domain.swap_and_reclaim(build(v));
  stop.store(true, std::memory_order_relaxed);
  reader.join();

  CHECK_EQ(bad.load(), 0);
}
