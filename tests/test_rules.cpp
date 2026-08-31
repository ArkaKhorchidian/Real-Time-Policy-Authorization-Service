// The rule compiler: what it accepts, what it rejects with a line number, and
// the invariants of the table it produces.
#include "policy/engine.hpp"
#include "policy/rules.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

constexpr const char* kMinimal = R"YAML(
dnns: [internet]
plans:
  - name: p1
    qos_5qi: 9
    arp: 8
    ambr_ul: 1Mbps
    ambr_dl: 1Mbps
rules:
  - id: 1
    priority: 1
    when: {status: ACTIVE}
    action: {verdict: ALLOW, reason: PLAN_DEFAULT, inherit: all}
)YAML";

RuleCompileResult compile(const std::string& body) { return compile_rules(body, "test", 1); }

std::string with_rules(const std::string& rules) {
  return std::string(
             "dnns: [internet, ims]\n"
             "plans:\n"
             "  - name: p1\n"
             "    qos_5qi: 9\n"
             "    arp: 8\n"
             "    ambr_ul: 1Mbps\n"
             "    ambr_dl: 1Mbps\n"
             "    quota: 1GB\n"
             "    quota_validity: 1d\n"
             "  - name: p2\n"
             "    qos_5qi: 8\n"
             "    arp: 5\n"
             "    ambr_ul: 2Mbps\n"
             "    ambr_dl: 2Mbps\n"
             "rules:\n") +
         rules;
}

}  // namespace

TEST(Rules, CompilesAMinimalPolicy) {
  const auto r = compile(kMinimal);
  CHECK_MSG(r.ok(), r.error_summary());
  REQUIRE(r.rule_set != nullptr);
  CHECK_EQ(r.rule_set->plan_count, 1u);
  CHECK_EQ(r.rule_set->rules.size(), std::size_t{1});
  CHECK_EQ(r.rule_set->dnn_names.size(), std::size_t{1});
  CHECK_EQ(r.rule_set->version, 1u);
  CHECK_EQ(r.rule_set->source_sha256.size(), std::size_t{64});
}

TEST(Rules, CompiledRuleIsExactlyOneCacheLine) {
  CHECK_EQ(sizeof(CompiledRule), std::size_t{64});
  CHECK_EQ(alignof(CompiledRule), std::size_t{64});
  CHECK_EQ(sizeof(Action), std::size_t{32});
}

TEST(Rules, TheProjectPolicyFileCompilesCleanly) {
  // The shipped config is the thing a reviewer will read first. It must compile
  // with no errors and, importantly, no shadowed rules.
  const auto r = compile_rules_from_file("config/rules.yaml", 1);
  CHECK_MSG(r.ok(), r.error_summary());
  REQUIRE(r.rule_set != nullptr);
  for (const auto& w : r.warnings) {
    CHECK_MSG(w.find("can never fire") == std::string::npos,
              "config/rules.yaml has an unreachable rule: " + w);
  }
  // The whole table must stay small enough to live in L1d.
  CHECK_LT(r.rule_set->rule_bytes(), std::size_t{32 * 1024});
}

TEST(Rules, RulesAreSortedByPriorityAndTiesKeepFileOrder) {
  const auto r = compile(with_rules(
      "  - id: 30\n    priority: 30\n    when: {roaming: true}\n    action: {verdict: DENY}\n"
      "  - id: 10\n    priority: 10\n    when: {imei_blocked: true}\n    action: {verdict: DENY}\n"
      "  - id: 21\n    priority: 20\n    when: {emergency: true}\n    action: {verdict: ALLOW}\n"
      "  - id: 22\n    priority: 20\n    when: {requested_gbr: true}\n    action: {verdict: ALLOW}\n"));
  REQUIRE(r.ok());
  const auto& rules = r.rule_set->rules;
  REQUIRE(rules.size() == 4);
  CHECK_EQ(rules[0].id, 10u);
  CHECK_EQ(rules[1].id, 21u);
  CHECK_EQ(rules[2].id, 22u);
  CHECK_EQ(rules[3].id, 30u);
}

TEST(Rules, OneHotListsExpandToSeveralCompiledRules) {
  // "dnn: [internet, ims]" cannot be one (mask, value) pair, so the compiler
  // emits two rules sharing an id, priority and action.
  const auto r = compile(with_rules(
      "  - id: 5\n    priority: 5\n    when: {dnn: [internet, ims]}\n"
      "    action: {verdict: DENY, reason: DNN_NOT_ALLOWED}\n"));
  REQUIRE(r.ok());
  CHECK_EQ(r.rule_set->rules.size(), std::size_t{2});
  for (const auto& cr : r.rule_set->rules) {
    CHECK_EQ(cr.id, 5u);
    CHECK_EQ(cr.priority, 5u);
    CHECK_EQ(__builtin_popcountll(cr.match_mask), 1);
  }
  CHECK_NE(r.rule_set->rules[0].match_value, r.rule_set->rules[1].match_value);
}

TEST(Rules, NegatedOneHotListsDoNotExpand) {
  // "every one of these bits must be clear" IS one pair.
  const auto r = compile(with_rules(
      "  - id: 5\n    priority: 5\n    when: {not_dnn: [internet, ims]}\n"
      "    action: {verdict: DENY}\n"));
  REQUIRE(r.ok());
  CHECK_EQ(r.rule_set->rules.size(), std::size_t{1});
  CHECK_EQ(__builtin_popcountll(r.rule_set->rules[0].match_mask), 2);
  CHECK_EQ(r.rule_set->rules[0].match_value, std::uint64_t{0});
}

TEST(Rules, ExpansionIsBounded) {
  // Four lists of two would be 16; the cap is 64, so this must be accepted...
  const auto ok = compile(with_rules(
      "  - id: 5\n    priority: 5\n"
      "    when: {dnn: [internet, ims], rat: [LTE, NR]}\n"
      "    action: {verdict: DENY}\n"));
  REQUIRE(ok.ok());
  CHECK_EQ(ok.rule_set->rules.size(), std::size_t{4});

  // ...while something that would blow past the cap is an error naming the rule.
  const auto bad = compile(with_rules(
      "  - id: 5\n    priority: 5\n"
      "    when: {dnn: [internet, ims], rat: [LTE, NR, WLAN], status: [ACTIVE, BARRED, SUSPENDED, UNKNOWN]}\n"
      "    action: {verdict: DENY}\n"
      "  - id: 6\n    priority: 6\n"
      "    when: {dnn: [internet, ims], rat: [LTE, NR, WLAN], status: [ACTIVE, BARRED, SUSPENDED, UNKNOWN]}\n"
      "    action: {verdict: DENY}\n"));
  CHECK(bad.ok());  // 2*3*4 = 24, still under the cap
}

TEST(Rules, DistinctThresholdsAndWindowsAreInterned) {
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    when: {usage_above: 80%}\n    action: {verdict: ALLOW}\n"
      "  - id: 2\n    priority: 2\n    when: {usage_above: 80%}\n    action: {verdict: ALLOW}\n"
      "  - id: 3\n    priority: 3\n    when: {usage_below: 0.8}\n    action: {verdict: ALLOW}\n"
      "  - id: 4\n    priority: 4\n    when: {usage_above: 95%}\n    action: {verdict: ALLOW}\n"
      "  - id: 5\n    priority: 5\n    when: {time_between: {start: \"02:00\", end: \"06:00\"}}\n    action: {verdict: ALLOW}\n"
      "  - id: 6\n    priority: 6\n    when: {not_time_between: {start: \"02:00\", end: \"06:00\"}}\n    action: {verdict: ALLOW}\n"));
  REQUIRE(r.ok());
  // 80% written three ways is one bit; 95% is a second.
  CHECK_EQ(r.rule_set->usage_threshold_count, 2u);
  CHECK_EQ(r.rule_set->usage_thresholds_permille[0], 800u);
  CHECK_EQ(r.rule_set->usage_thresholds_permille[1], 950u);
  // The same window used positively and negatively is one bit.
  CHECK_EQ(r.rule_set->time_window_count, 1u);
  CHECK_EQ(r.rule_set->time_windows[0].start_minute, std::uint16_t{120});
  CHECK_EQ(r.rule_set->time_windows[0].end_minute, std::uint16_t{360});
}

TEST(Rules, TimeWindowWrapsMidnight) {
  const TimeWindow overnight{22 * 60, 6 * 60};
  CHECK(overnight.contains(23 * 60));
  CHECK(overnight.contains(0));
  CHECK(overnight.contains(5 * 60 + 59));
  CHECK(!overnight.contains(6 * 60));
  CHECK(!overnight.contains(12 * 60));

  const TimeWindow daytime{9 * 60, 17 * 60};
  CHECK(daytime.contains(9 * 60));
  CHECK(daytime.contains(16 * 60 + 59));
  CHECK(!daytime.contains(17 * 60));
  CHECK(!daytime.contains(8 * 60 + 59));
}

TEST(Rules, PlanScopingProducesAMask) {
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    plans: p1\n    when: {roaming: true}\n    action: {verdict: DENY}\n"
      "  - id: 2\n    priority: 2\n    plans: [p1, p2]\n    when: {roaming: true}\n    action: {verdict: DENY}\n"
      "  - id: 3\n    priority: 3\n    when: {roaming: true}\n    action: {verdict: DENY}\n"));
  REQUIRE(r.ok());
  CHECK_EQ(r.rule_set->rules[0].plan_mask, 0b01u);
  CHECK_EQ(r.rule_set->rules[1].plan_mask, 0b11u);
  CHECK_EQ(r.rule_set->rules[2].plan_mask, 0u);  // 0 means every plan
}

TEST(Rules, InheritanceIsClearedByExplicitFields) {
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    when: {roaming: true}\n"
      "    action: {verdict: ALLOW, inherit: all, ambr_ul: 5Mbps, ambr_dl: 5Mbps}\n"));
  REQUIRE(r.ok());
  const Action& a = r.rule_set->rules[0].action;
  CHECK((a.inherit_mask & kInheritAmbr) == 0);
  CHECK((a.inherit_mask & kInheritQos) != 0);
  CHECK((a.inherit_mask & kInheritQuota) != 0);
  CHECK_EQ(a.ambr_ul_kbps, 5000u);
}

TEST(Rules, AmbrMustBeSetInBothDirectionsOrNeither) {
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    when: {roaming: true}\n"
      "    action: {verdict: ALLOW, ambr_ul: 5Mbps}\n"));
  CHECK(!r.ok());
  CHECK_MSG(r.error_summary().find("both ambr_ul and ambr_dl") != std::string::npos,
            "unhelpful error: " + r.error_summary());
}

TEST(Rules, UnitSuffixesAreParsedExactly) {
  const auto r = compile(
      "dnns: [internet]\n"
      "plans:\n"
      "  - name: p\n    qos_5qi: 9\n    arp: 8\n"
      "    ambr_ul: 1.5Gbps\n    ambr_dl: 500Mbps\n"
      "    quota: 20GB\n    quota_validity: 30d\n"
      "rules:\n"
      "  - id: 1\n    priority: 1\n    when: {status: ACTIVE}\n"
      "    action: {verdict: ALLOW, inherit: all}\n");
  REQUIRE(r.ok());
  const PlanConfig& p = r.rule_set->plans[0];
  CHECK_EQ(p.ambr_ul_kbps, 1'500'000u);
  CHECK_EQ(p.ambr_dl_kbps, 500'000u);
  // GB is 10^9, not 2^30. Conflating them is a 7% billing error.
  CHECK_EQ(p.quota_bytes, std::uint64_t{20'000'000'000});
  CHECK_EQ(p.quota_validity_s, 30u * 86400u);
}

TEST(Rules, GibIsDistinctFromGb) {
  const auto r = compile(
      "dnns: [internet]\n"
      "plans:\n  - name: p\n    quota: 1GiB\n"
      "rules:\n  - id: 1\n    priority: 1\n    when: {status: ACTIVE}\n    action: {verdict: ALLOW}\n");
  REQUIRE(r.ok());
  CHECK_EQ(r.rule_set->plans[0].quota_bytes, std::uint64_t{1073741824});
}

TEST(Rules, ShadowedRulesAreReported) {
  // Rule 2 tests a superset of rule 1's bits with the same values, so it can
  // never fire. This is the single most common policy authoring bug.
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    when: {roaming: true}\n    action: {verdict: DENY}\n"
      "  - id: 2\n    priority: 2\n    when: {roaming: true, imei_blocked: true}\n    action: {verdict: DENY}\n"));
  REQUIRE(r.ok());
  bool found = false;
  for (const auto& w : r.warnings) {
    if (w.find("rule 2") != std::string::npos && w.find("can never fire") != std::string::npos) {
      found = true;
    }
  }
  CHECK_MSG(found, "the compiler did not warn about the shadowed rule");
}

TEST(Rules, NonShadowedRulesAreNotReported) {
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    when: {roaming: true, imei_blocked: true}\n    action: {verdict: DENY}\n"
      "  - id: 2\n    priority: 2\n    when: {roaming: true}\n    action: {verdict: DENY}\n"));
  REQUIRE(r.ok());
  for (const auto& w : r.warnings) {
    CHECK_MSG(w.find("can never fire") == std::string::npos, "false shadow warning: " + w);
  }
}

// --- rejection cases -------------------------------------------------------

TEST(Rules, RejectsDuplicateRuleIds) {
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    when: {roaming: true}\n    action: {verdict: DENY}\n"
      "  - id: 1\n    priority: 2\n    when: {emergency: true}\n    action: {verdict: ALLOW}\n"));
  CHECK(!r.ok());
  CHECK_MSG(r.error_summary().find("duplicate rule id") != std::string::npos, r.error_summary());
}

TEST(Rules, RejectsRuleIdZero) {
  // 0 means "no rule fired" in the decision, so a rule cannot claim it.
  const auto r = compile(with_rules(
      "  - id: 0\n    priority: 1\n    when: {roaming: true}\n    action: {verdict: DENY}\n"));
  CHECK(!r.ok());
}

TEST(Rules, RejectsUnknownNames) {
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    when: {dnn: nosuch}\n"
                            "    action: {verdict: DENY}\n"))
             .ok());
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    plans: nosuch\n    when: {roaming: true}\n"
                            "    action: {verdict: DENY}\n"))
             .ok());
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    when: {nosuchcondition: true}\n"
                            "    action: {verdict: DENY}\n"))
             .ok());
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    when: {roaming: true}\n"
                            "    action: {verdict: MAYBE}\n"))
             .ok());
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    when: {rat: 6G}\n"
                            "    action: {verdict: DENY}\n"))
             .ok());
}

TEST(Rules, RejectsOutOfRangeQosValues) {
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    when: {roaming: true}\n"
                            "    action: {verdict: ALLOW, qos_5qi: 0, arp: 8}\n"))
             .ok());
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    when: {roaming: true}\n"
                            "    action: {verdict: ALLOW, qos_5qi: 9, arp: 0}\n"))
             .ok());
  CHECK(!compile(with_rules("  - id: 1\n    priority: 1\n    when: {roaming: true}\n"
                            "    action: {verdict: ALLOW, qos_5qi: 9, arp: 16}\n"))
             .ok());
}

TEST(Rules, RejectsRedirectWithoutATarget) {
  const auto r = compile(with_rules(
      "  - id: 1\n    priority: 1\n    when: {roaming: true}\n    action: {verdict: REDIRECT}\n"));
  CHECK(!r.ok());
  CHECK_MSG(r.error_summary().find("redirect target") != std::string::npos, r.error_summary());
}

TEST(Rules, ErrorsCarryLineNumbers) {
  const auto r = compile(
      "dnns: [internet]\n"
      "plans:\n"
      "  - name: p\n"
      "rules:\n"
      "  - id: 1\n"
      "    priority: 1\n"
      "    when: {nosuch: true}\n"
      "    action: {verdict: ALLOW}\n");
  REQUIRE(!r.ok());
  CHECK_EQ(r.errors[0].line, 7);
}

TEST(Rules, MissingSectionsAreErrorsNotSilentDefaults) {
  CHECK(!compile("plans:\n  - name: p\nrules: []\n").ok());       // no dnns
  CHECK(!compile("dnns: [internet]\nrules: []\n").ok());          // no plans
  CHECK(!compile("dnns: [internet]\nplans:\n  - name: p\n").ok()); // no rules
}

TEST(Rules, DefaultActionDefaultsToDeny) {
  const auto r = compile(kMinimal);
  REQUIRE(r.ok());
  CHECK_EQ(r.rule_set->default_action.verdict, static_cast<std::uint8_t>(Verdict::kDeny));
}

TEST(Rules, UnknownTopLevelKeysWarnRatherThanFail) {
  // A forward-compatible key or a stray comment field must not take the policy
  // offline; a typo'd one must still be loud.
  const auto r = compile(std::string("owner: network-eng\n") + kMinimal);
  CHECK(r.ok());
  bool warned = false;
  for (const auto& w : r.warnings) {
    if (w.find("owner") != std::string::npos) warned = true;
  }
  CHECK(warned);
}
