// The decision path.
//
// Three layers here:
//   1. One unit test per rule type, with a fixture subscriber, checking that
//      the right rule fires and produces the right authorization.
//   2. Property tests over random requests: determinism, allocation-freedom,
//      and output-range validity.
//   3. Interaction tests for the cases that are easy to get wrong — priority
//      ordering, plan scoping, inheritance, and DENY not leaking authorization.
#define POLICY_DEFINE_COUNTING_ALLOCATOR
#include "counting_allocator.hpp"

#include <random>
#include <set>

#include "policy/coarse_clock.hpp"
#include "policy/engine.hpp"
#include "policy/request_gen.hpp"
#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

// A compact policy exercising every condition type the compiler supports.
constexpr const char* kFixtureRules = R"YAML(
version: 7
dnns: [internet, ims, sos, iot]
redirects:
  portal: "https://portal.example/top-up"
plans:
  - name: basic
    qos_5qi: 9
    arp: 8
    ambr_ul: 10Mbps
    ambr_dl: 50Mbps
    quota: 20GB
    quota_validity: 30d
    rating_group: 100
    tethering: true
  - name: iot
    qos_5qi: 8
    arp: 11
    ambr_ul: 1Mbps
    ambr_dl: 1Mbps
    quota: 500MB
    quota_validity: 30d
    rating_group: 200
roaming_partners: [310-260, 234-15]
imei_blocklist: [490154203237518]
default_action:
  verdict: DENY
  reason: NO_MATCHING_RULE
rules:
  - id: 1
    priority: 1
    when: {emergency: true}
    action: {verdict: ALLOW, reason: OK, qos_5qi: 5, arp: 1, ambr_ul: 1Mbps, ambr_dl: 1Mbps, rating_group: 0, quota: 0, quota_validity: 1h}
  - id: 10
    priority: 10
    when: {imei_blocked: true}
    action: {verdict: REDIRECT, reason: IMEI_BLOCKED, redirect: portal, qos_5qi: 9, arp: 15, ambr_ul: 64, ambr_dl: 128, rating_group: 0, quota: 10MB, quota_validity: 900s, flags: [throttled]}
  - id: 11
    priority: 11
    when: {status: UNKNOWN}
    action: {verdict: DENY, reason: UNKNOWN_SUBSCRIBER}
  - id: 12
    priority: 12
    when: {status: [BARRED, SUSPENDED]}
    action: {verdict: DENY, reason: SUBSCRIBER_BARRED}
  - id: 30
    priority: 30
    when: {roaming: true, roaming_partner: false}
    action: {verdict: DENY, reason: PLMN_NOT_PARTNER, flags: [roaming_restricted]}
  - id: 40
    priority: 40
    plans: iot
    when: {dnn: [ims, sos]}
    action: {verdict: DENY, reason: DNN_NOT_ALLOWED}
  - id: 41
    priority: 41
    when: {rat: WLAN, dnn: ims}
    action: {verdict: DENY, reason: RAT_NOT_ALLOWED}
  - id: 42
    priority: 42
    when: {tethering_detected: true, tethering_allowed: false}
    action: {verdict: DENY, reason: TETHERING_BLOCKED, flags: [tethering_blocked]}
  - id: 60
    priority: 60
    plans: basic
    when: {quota_exhausted: true, time_between: {start: "02:00", end: "06:00"}}
    action: {verdict: ALLOW, reason: OFF_PEAK_BONUS, inherit: [qos, rating_group], ambr_ul: 5Mbps, ambr_dl: 25Mbps, quota: 2GB, quota_validity: 4h, flags: [off_peak_bonus]}
  - id: 61
    priority: 61
    plans: basic
    when: {quota_exhausted: true}
    action: {verdict: ALLOW, reason: QUOTA_EXHAUSTED_THROTTLED, inherit: [qos, rating_group], ambr_ul: 1Mbps, ambr_dl: 1Mbps, quota: 1GB, quota_validity: 24h, flags: [throttled]}
  - id: 70
    priority: 70
    when: {usage_above: 80%}
    action: {verdict: ALLOW, reason: OK, inherit: all, flags: [quota_warning]}
  - id: 100
    priority: 100
    when: {status: ACTIVE}
    action: {verdict: ALLOW, reason: PLAN_DEFAULT, inherit: all}
)YAML";

struct Fixture {
  std::unique_ptr<RuleSet> rules;
  SubscriberStore store{256};

  static constexpr std::uint64_t kBasicImsi = 310260100000001ull;
  static constexpr std::uint64_t kIotImsi = 310260100000002ull;
  static constexpr std::uint64_t kSuspendedImsi = 310260100000003ull;
  static constexpr std::uint64_t kBarredImsi = 310260100000004ull;
  static constexpr std::uint64_t kUnknownImsi = 999999999999999ull;
  static constexpr std::uint64_t kBlockedImei = 490154203237518ull;
  static constexpr std::uint64_t kGoodImei = 350000000000018ull;

  Fixture() {
    auto compiled = compile_rules(kFixtureRules, "fixture", 7);
    if (!compiled.ok()) {
      std::fprintf(stderr, "fixture policy failed to compile: %s\n",
                   compiled.error_summary().c_str());
      std::abort();
    }
    rules = std::move(compiled.rule_set);

    add(kBasicImsi, 0, SubscriberStatus::kActive, 1'000'000'000ull, kSubRoamingAllowed);
    add(kIotImsi, 1, SubscriberStatus::kActive, 1'000'000ull, 0);
    add(kSuspendedImsi, 0, SubscriberStatus::kSuspended, 0, kSubRoamingAllowed);
    add(kBarredImsi, 0, SubscriberStatus::kBarred, 0, 0);

    // Pin the clock so period-expiry decisions do not depend on the calendar.
    set_coarse_now_unix_s(kGoldenClockUnixS);
  }

  void add(std::uint64_t imsi, std::uint32_t plan, SubscriberStatus status, std::uint64_t used,
           std::uint32_t flags) {
    SubscriberRecord r{};
    r.imsi = imsi;
    r.imei = kGoodImei;
    r.plan_id = plan;
    r.status = static_cast<std::uint32_t>(status);
    r.bytes_used_period = used;
    r.period_reset_ts = kGoldenClockUnixS + 86400;  // not yet expired
    r.home_plmn = 310410;                            // AT&T; partners are 310-260 and 234-15
    r.flags = flags;
    store.upsert(r);
  }

  PolicyRequest request(std::uint64_t imsi) const {
    PolicyRequest req{};
    req.magic_version = kMagicVersion;
    req.imsi = imsi;
    req.imei = kGoodImei;
    req.rat_type = static_cast<std::uint8_t>(RatType::kNr);
    req.dnn_id = 0;  // internet
    req.requested_5qi = 9;
    req.local_minute = 12 * 60;  // midday: outside the off-peak window
    const SubscriberRecord* rec = store.find(imsi);
    req.plmn = rec != nullptr ? rec->home_plmn : 310410;
    return req;
  }

  PolicyDecision decide(const PolicyRequest& req) const {
    return evaluate(*rules, req, store.find(req.imsi));
  }
};

const Fixture& fixture() {
  static const Fixture f;
  return f;
}

}  // namespace

// ---------------------------------------------------------------------------
// One test per rule type
// ---------------------------------------------------------------------------

TEST(Engine, PlanDefaultAuthorizesWhatThePlanSays) {
  const auto& f = fixture();
  const auto d = f.decide(f.request(Fixture::kBasicImsi));
  CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kAllow));
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kPlanDefault));
  CHECK_EQ(d.rule_id, 100u);
  CHECK_EQ(d.qos_5qi, std::uint8_t{9});
  CHECK_EQ(d.arp, std::uint8_t{8});
  CHECK_EQ(d.ambr_ul_kbps, 10000u);
  CHECK_EQ(d.ambr_dl_kbps, 50000u);
  CHECK_EQ(d.rating_group, 100u);
  CHECK_EQ(d.policy_version, 7u);
  // Quota granted is what is LEFT, not the whole allowance.
  CHECK_EQ(d.quota_bytes, std::uint64_t{20'000'000'000ull - 1'000'000'000ull});
}

TEST(Engine, UnknownSubscriberIsDenied) {
  const auto& f = fixture();
  const auto d = f.decide(f.request(Fixture::kUnknownImsi));
  CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kDeny));
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kUnknownSubscriber));
  CHECK_EQ(d.rule_id, 11u);
}

TEST(Engine, BarredAndSuspendedAreDenied) {
  const auto& f = fixture();
  for (const std::uint64_t imsi : {Fixture::kBarredImsi, Fixture::kSuspendedImsi}) {
    const auto d = f.decide(f.request(imsi));
    CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kDeny));
    CHECK_EQ(d.rule_id, 12u);
  }
}

TEST(Engine, BlockedImeiRedirectsBeforeAnySubscriberCheck) {
  const auto& f = fixture();
  // Even a barred subscriber takes the device rule first — it has the lower
  // priority number, and the redirect is more useful than a bare denial.
  auto req = f.request(Fixture::kBarredImsi);
  req.imei = Fixture::kBlockedImei;
  const auto d = f.decide(req);
  CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kRedirect));
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kImeiBlocked));
  CHECK_EQ(d.rule_id, 10u);
  CHECK_NE(d.redirect_id, std::uint8_t{0});
  CHECK((d.flags & kFlagThrottled) != 0);
}

TEST(Engine, EmergencyOutranksEverything) {
  const auto& f = fixture();
  // Barred subscriber, blocked device, non-partner network: still allowed.
  auto req = f.request(Fixture::kBarredImsi);
  req.imei = Fixture::kBlockedImei;
  req.plmn = 46000;
  req.flags |= kReqFlagEmergency;
  const auto d = f.decide(req);
  CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kAllow));
  CHECK_EQ(d.rule_id, 1u);
  CHECK_EQ(d.qos_5qi, std::uint8_t{5});
  CHECK_EQ(d.arp, std::uint8_t{1});
}

TEST(Engine, RoamingOnANonPartnerNetworkIsDenied) {
  const auto& f = fixture();
  auto req = f.request(Fixture::kBasicImsi);
  req.plmn = 46000;  // not in the partner table
  const auto d = f.decide(req);
  CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kDeny));
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kPlmnNotPartner));
  CHECK((d.flags & kFlagRoamingRestricted) != 0);

  // A partner network is fine.
  req.plmn = 310260;
  const auto ok = f.decide(req);
  CHECK_EQ(ok.verdict, static_cast<std::uint8_t>(Verdict::kAllow));
}

TEST(Engine, PlanScopedDnnRestriction) {
  const auto& f = fixture();
  // The IoT plan may not use ims or sos.
  for (const std::uint8_t dnn : {std::uint8_t{1}, std::uint8_t{2}}) {
    auto req = f.request(Fixture::kIotImsi);
    req.dnn_id = dnn;
    const auto d = f.decide(req);
    CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kDeny));
    CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kDnnNotAllowed));
    CHECK_EQ(d.rule_id, 40u);
  }
  // The same DNN on the basic plan is fine — the rule is plan-scoped.
  auto basic = f.request(Fixture::kBasicImsi);
  basic.dnn_id = 1;
  CHECK_EQ(f.decide(basic).verdict, static_cast<std::uint8_t>(Verdict::kAllow));
}

TEST(Engine, ConjunctionOfRatAndDnn) {
  const auto& f = fixture();
  auto req = f.request(Fixture::kBasicImsi);
  req.rat_type = static_cast<std::uint8_t>(RatType::kWlan);
  req.dnn_id = 1;  // ims
  const auto d = f.decide(req);
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kRatNotAllowed));

  // Either half alone must not trigger it.
  req.dnn_id = 0;
  CHECK_NE(f.decide(req).rule_id, 41u);
  req.rat_type = static_cast<std::uint8_t>(RatType::kNr);
  req.dnn_id = 1;
  CHECK_NE(f.decide(req).rule_id, 41u);
}

TEST(Engine, TetheringRequiresEntitlement) {
  const auto& f = fixture();
  // The IoT plan does not permit tethering.
  auto iot = f.request(Fixture::kIotImsi);
  iot.flags |= kReqFlagTetheringDetected;
  const auto denied = f.decide(iot);
  CHECK_EQ(denied.reason, static_cast<std::uint8_t>(Reason::kTetheringBlocked));
  CHECK((denied.flags & kFlagTetheringBlocked) != 0);

  // The basic plan does.
  auto basic = f.request(Fixture::kBasicImsi);
  basic.flags |= kReqFlagTetheringDetected;
  CHECK_EQ(f.decide(basic).verdict, static_cast<std::uint8_t>(Verdict::kAllow));
}

TEST(Engine, QuotaExhaustionThrottlesAndInheritsSelectively) {
  const auto& f = fixture();
  auto req = f.request(Fixture::kBasicImsi);
  req.flags |= kReqFlagUsageValid;
  req.bytes_used_period = 25'000'000'000ull;  // over the 20 GB allowance

  const auto d = f.decide(req);
  CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kAllow));
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kQuotaExhaustedThrottled));
  CHECK_EQ(d.rule_id, 61u);
  // AMBR comes from the rule...
  CHECK_EQ(d.ambr_ul_kbps, 1000u);
  CHECK_EQ(d.ambr_dl_kbps, 1000u);
  // ...while QoS and rating group are inherited from the plan.
  CHECK_EQ(d.qos_5qi, std::uint8_t{9});
  CHECK_EQ(d.rating_group, 100u);
  CHECK_EQ(d.quota_bytes, std::uint64_t{1'000'000'000});
  CHECK((d.flags & kFlagThrottled) != 0);
  CHECK((d.flags & kFlagUsageFromRequest) != 0);
}

TEST(Engine, OffPeakBonusBeatsTheThrottleInsideTheWindow) {
  const auto& f = fixture();
  auto req = f.request(Fixture::kBasicImsi);
  req.flags |= kReqFlagUsageValid;
  req.bytes_used_period = 25'000'000'000ull;
  req.local_minute = 3 * 60;  // 03:00, inside 02:00-06:00

  const auto d = f.decide(req);
  CHECK_EQ(d.rule_id, 60u);
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kOffPeakBonus));
  CHECK_EQ(d.ambr_dl_kbps, 25000u);
  CHECK((d.flags & kFlagOffPeakBonus) != 0);

  // One minute past the window and the throttle applies again.
  req.local_minute = 6 * 60;
  CHECK_EQ(f.decide(req).rule_id, 61u);
  // One minute before it starts, likewise.
  req.local_minute = 2 * 60 - 1;
  CHECK_EQ(f.decide(req).rule_id, 61u);
  // The first minute of the window is inside it.
  req.local_minute = 2 * 60;
  CHECK_EQ(f.decide(req).rule_id, 60u);
}

TEST(Engine, UsageThresholdFiresAtTheBoundary) {
  const auto& f = fixture();
  auto req = f.request(Fixture::kBasicImsi);
  req.flags |= kReqFlagUsageValid;

  req.bytes_used_period = 15'999'999'999ull;  // just under 80% of 20 GB
  CHECK_EQ(f.decide(req).rule_id, 100u);

  req.bytes_used_period = 16'000'000'000ull;  // exactly 80%
  const auto at = f.decide(req);
  CHECK_EQ(at.rule_id, 70u);
  CHECK((at.flags & kFlagQuotaWarning) != 0);
  // `inherit: all` means the authorization is the plan's, unchanged.
  CHECK_EQ(at.ambr_dl_kbps, 50000u);
  CHECK_EQ(at.qos_5qi, std::uint8_t{9});
}

TEST(Engine, RequestUsageOverridesTheStoredCounter) {
  const auto& f = fixture();
  // The stored counter says 1 GB. The serving node reports 25 GB, which is
  // fresher, so the throttle must fire.
  auto req = f.request(Fixture::kBasicImsi);
  CHECK_EQ(f.decide(req).rule_id, 100u);

  req.flags |= kReqFlagUsageValid;
  req.bytes_used_period = 25'000'000'000ull;
  CHECK_EQ(f.decide(req).rule_id, 61u);
}

TEST(Engine, DenyCarriesNoAuthorization) {
  const auto& f = fixture();
  // A serving node that ignored the verdict must still be unable to open a
  // bearer from the reply's QoS fields.
  for (const std::uint64_t imsi : {Fixture::kBarredImsi, Fixture::kUnknownImsi}) {
    const auto d = f.decide(f.request(imsi));
    REQUIRE(d.verdict == static_cast<std::uint8_t>(Verdict::kDeny));
    CHECK_EQ(d.ambr_ul_kbps, 0u);
    CHECK_EQ(d.ambr_dl_kbps, 0u);
    CHECK_EQ(d.quota_bytes, std::uint64_t{0});
    CHECK_EQ(d.quota_validity_s, 0u);
    CHECK_EQ(d.qos_5qi, std::uint8_t{0});
    CHECK_EQ(d.arp, std::uint8_t{0});
  }
}

TEST(Engine, EveryDecisionCarriesItsProvenance) {
  const auto& f = fixture();
  auto req = f.request(Fixture::kBasicImsi);
  req.seq = 0xABCD1234;
  req.client_ts_ns = 0x1122334455667788ull;
  const auto d = f.decide(req);
  CHECK_EQ(d.magic_version, kMagicVersion);
  CHECK_EQ(d.seq, req.seq);
  CHECK_EQ(d.client_ts_ns, req.client_ts_ns);
  CHECK_EQ(d.policy_version, 7u);
  CHECK_NE(d.rule_id, 0u);
}

TEST(Engine, MalformedRequestStillGetsAWellFormedReply) {
  const auto d = malformed_decision(42, 99, 7);
  CHECK_EQ(d.magic_version, kMagicVersion);
  CHECK_EQ(d.seq, 42u);
  CHECK_EQ(d.client_ts_ns, std::uint64_t{99});
  CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kDeny));
  CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kMalformedRequest));
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

namespace {

std::vector<PolicyRequest> random_corpus(const Fixture& f, std::size_t n, std::uint64_t seed) {
  std::vector<std::uint64_t> imsis;
  f.store.for_each([&](const SubscriberRecord& r) { imsis.push_back(r.imsi); });
  std::vector<std::uint64_t> blocked{Fixture::kBlockedImei};
  std::vector<std::uint32_t> visited{310260, 234015, 46000};

  RequestGenerator gen(seed, imsis, blocked, visited,
                       static_cast<std::uint8_t>(f.rules->dnn_names.size()));
  std::vector<PolicyRequest> out(n);
  for (auto& r : out) {
    gen.fill(r);
    if (r.plmn == 0) r.plmn = 310410;
  }
  return out;
}

}  // namespace

TEST(EngineProperty, EvaluateIsDeterministic) {
  const auto& f = fixture();
  const auto corpus = random_corpus(f, 20000, 777);
  for (const auto& req : corpus) {
    const auto a = f.decide(req);
    const auto b = f.decide(req);
    CHECK_EQ(std::memcmp(&a, &b, sizeof(a)), 0);
  }
}

TEST(EngineProperty, EvaluateAllocatesNothing) {
  const auto& f = fixture();
  const auto corpus = random_corpus(f, 20000, 888);
  // Warm anything lazy (the coarse clock's first read, for instance) before
  // sampling, so the count measures evaluate() and not one-time setup.
  volatile std::uint8_t sink = f.decide(corpus.front()).verdict;
  (void)sink;

  std::uint8_t acc = 0;
  const std::size_t allocations = testing::count_allocations([&] {
    for (const auto& req : corpus) {
      const auto d = evaluate(*f.rules, req, f.store.find(req.imsi));
      acc = static_cast<std::uint8_t>(acc + d.verdict);
    }
  });
  CHECK_MSG(allocations == 0,
            "evaluate() allocated " + std::to_string(allocations) + " time(s) over " +
                std::to_string(corpus.size()) + " requests");
  CHECK_MSG(acc != 0xFF || true, "keep the loop from being optimized away");
}

TEST(EngineProperty, OutputsAreAlwaysInRange) {
  const auto& f = fixture();
  const auto corpus = random_corpus(f, 50000, 999);

  // Every value the engine can emit for these fields comes from a validated
  // plan or action, so nothing should ever land outside the legal ranges.
  std::set<std::uint32_t> plan_ambr_ul, plan_ambr_dl;
  for (std::uint32_t i = 0; i < f.rules->plan_count; ++i) {
    plan_ambr_ul.insert(f.rules->plans[i].ambr_ul_kbps);
    plan_ambr_dl.insert(f.rules->plans[i].ambr_dl_kbps);
  }

  for (const auto& req : corpus) {
    const auto d = f.decide(req);
    CHECK_LE(d.verdict, static_cast<std::uint8_t>(Verdict::kRedirect));
    CHECK_LT(d.reason, static_cast<std::uint8_t>(Reason::kCount));
    CHECK_LE(d.arp, std::uint8_t{15});
    CHECK_LT(d.redirect_id, static_cast<std::uint8_t>(f.rules->redirect_targets.size() + 1));
    if (d.verdict == static_cast<std::uint8_t>(Verdict::kDeny)) {
      CHECK_EQ(d.qos_5qi, std::uint8_t{0});
    } else {
      CHECK_GE(d.qos_5qi, std::uint8_t{1});
      CHECK_GE(d.arp, std::uint8_t{1});
      // No decision may authorize more than 100 Gbps, which would be a sign of
      // a unit-conversion bug in the rules loader rather than a real policy.
      CHECK_LE(d.ambr_ul_kbps, 100'000'000u);
      CHECK_LE(d.ambr_dl_kbps, 100'000'000u);
    }
  }
}

TEST(EngineProperty, ARuleAlwaysFiresOrTheDefaultDoes) {
  const auto& f = fixture();
  const auto corpus = random_corpus(f, 20000, 1010);
  for (const auto& req : corpus) {
    const auto d = f.decide(req);
    if (d.rule_id == 0) {
      // No rule matched: the reason must say so, and the fixture's default is
      // DENY. A decision that fell through silently to ALLOW would be the
      // worst possible failure mode for this service.
      CHECK_EQ(d.reason, static_cast<std::uint8_t>(Reason::kNoMatchingRule));
      CHECK_EQ(d.verdict, static_cast<std::uint8_t>(Verdict::kDeny));
    }
  }
}

TEST(EngineProperty, FeatureWordIsAFunctionOfTheRequestAndRecordOnly) {
  const auto& f = fixture();
  const auto corpus = random_corpus(f, 10000, 1111);
  for (const auto& req : corpus) {
    const auto* rec = f.store.find(req.imsi);
    const FeatureWord a = build_features(*f.rules, req, rec);
    const FeatureWord b = build_features(*f.rules, req, rec);
    CHECK_EQ(a, b);

    // Exactly one status bit is ever set.
    const FeatureWord status_mask =
        feat::bit(feat::kStatusActive) | feat::bit(feat::kStatusSuspended) |
        feat::bit(feat::kStatusBarred) | feat::bit(feat::kStatusUnknown);
    CHECK_EQ(__builtin_popcountll(a & status_mask), 1);

    // Home and roaming are mutually exclusive.
    const bool home = (a & feat::bit(feat::kHomePlmn)) != 0;
    const bool roaming = (a & feat::bit(feat::kRoaming)) != 0;
    CHECK(home != roaming);
  }
}
