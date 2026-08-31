// Replay the committed golden corpus.
//
// This is the regression net for the whole decision path. A rule reordering, a
// feature-bit renumbering, an inheritance change or an evaluate() bug all show
// up here as a specific list of decisions that moved — which is exactly what a
// reviewer needs to decide whether the change was intended.
#include <cstdio>
#include <map>

#include "policy/coarse_clock.hpp"
#include "policy/engine.hpp"
#include "policy/golden.hpp"
#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"
#include "test_framework.hpp"

using namespace policy;

TEST(Golden, EveryCommittedDecisionStillReproduces) {
  auto compiled = compile_rules_from_file("config/rules.yaml", 1);
  REQUIRE(compiled.ok());
  const RuleSet& rs = *compiled.rule_set;

  SubscriberStore store(1 << 16);
  const auto load = store.load_csv("config/subscribers.csv", rs.plan_names);
  REQUIRE(load.ok());
  REQUIRE(load.loaded > 0);

  // The corpus was generated against a pinned clock, because period-expiry
  // decisions otherwise change with the calendar and the file would fail every
  // day at midnight for no reason.
  set_coarse_now_unix_s(kGoldenClockUnixS);

  const auto golden = load_golden("tests/golden/decisions.csv");
  REQUIRE(golden.ok());
  REQUIRE(!golden.cases.empty());

  int mismatches = 0;
  constexpr int kMaxReported = 10;
  for (const auto& c : golden.cases) {
    const PolicyDecision actual = evaluate(rs, c.request, store.find(c.request.imsi));
    const std::string diff = diff_decisions(c.expected, actual);
    if (diff.empty()) continue;
    ++mismatches;
    if (mismatches <= kMaxReported) {
      ::testing::report_failure("tests/golden/decisions.csv", c.line,
                                "IMSI " + std::to_string(c.request.imsi) + ": " + diff);
    }
  }
  if (mismatches > kMaxReported) {
    std::fprintf(stderr, "    ... and %d more\n", mismatches - kMaxReported);
  }
  CHECK_MSG(mismatches == 0,
            std::to_string(mismatches) + " of " + std::to_string(golden.cases.size()) +
                " golden decisions changed. If this was intentional, regenerate with "
                "`policy-gen-golden` and review the diff.");
}

TEST(Golden, CorpusCoversEveryRuleAndVerdict) {
  // A golden file that only exercises the happy path is a golden file that
  // catches nothing. Assert the corpus actually reaches the interesting rules.
  const auto golden = load_golden("tests/golden/decisions.csv");
  REQUIRE(golden.ok());

  std::map<std::uint32_t, int> by_rule;
  std::map<std::uint8_t, int> by_verdict;
  std::map<std::uint8_t, int> by_reason;
  for (const auto& c : golden.cases) {
    ++by_rule[c.expected.rule_id];
    ++by_verdict[c.expected.verdict];
    ++by_reason[c.expected.reason];
  }

  CHECK_GT(by_verdict[static_cast<std::uint8_t>(Verdict::kAllow)], 100);
  CHECK_GT(by_verdict[static_cast<std::uint8_t>(Verdict::kDeny)], 100);
  CHECK_GT(by_verdict[static_cast<std::uint8_t>(Verdict::kRedirect)], 10);

  // The rules that are easy to break and easy to miss.
  for (const std::uint32_t id : {10u, 11u, 12u, 13u, 30u, 31u, 61u, 63u, 70u, 100u}) {
    CHECK_MSG(by_rule[id] > 0,
              "no golden case exercises rule " + std::to_string(id) +
                  "; the corpus is not covering the policy");
  }
  CHECK_GT(static_cast<int>(by_reason.size()), 6);
}

TEST(Golden, HeaderMismatchIsADiagnosableError) {
  // Silently accepting an old-format file would mean CI comparing the wrong
  // columns and passing.
  const std::string path = "test_golden_badheader.csv";
  {
    std::FILE* f = std::fopen(path.c_str(), "w");
    REQUIRE(f != nullptr);
    std::fputs("imsi,verdict\n1,0\n", f);
    std::fclose(f);
  }
  const auto r = load_golden(path);
  CHECK(!r.ok());
  CHECK_MSG(r.error.find("Regenerate with") != std::string::npos,
            "the error should say how to fix it: " + r.error);
  std::remove(path.c_str());
}
