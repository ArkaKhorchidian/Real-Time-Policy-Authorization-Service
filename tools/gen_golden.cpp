// Regenerate the golden decision file.
//
// Run this only when a policy change is intentional. The diff it produces is
// the review artefact: it shows exactly which decisions the change moved.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "policy/coarse_clock.hpp"
#include "policy/engine.hpp"
#include "policy/golden.hpp"
#include "policy/request_gen.hpp"
#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"

namespace {

void usage(const char* argv0) {
  std::printf(
      "Regenerate the golden decision corpus.\n"
      "\n"
      "Usage: %s [--count N] [--seed N] [--rules PATH] [--subscribers PATH] [--out PATH]\n"
      "\n"
      "  --count N          Cases to generate (default 10000)\n"
      "  --seed N           PRNG seed (default 424242)\n"
      "  --rules PATH       Rules file (default config/rules.yaml)\n"
      "  --subscribers PATH Subscriber CSV (default config/subscribers.csv)\n"
      "  --out PATH         Output file (default tests/golden/decisions.csv)\n",
      argv0);
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t count = 10000;
  std::uint64_t seed = 424242;
  std::string rules_path = "config/rules.yaml";
  std::string subs_path = "config/subscribers.csv";
  std::string out_path = "tests/golden/decisions.csv";

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else if (a == "--count") { if (const char* v = next()) count = std::strtoull(v, nullptr, 10); }
    else if (a == "--seed") { if (const char* v = next()) seed = std::strtoull(v, nullptr, 10); }
    else if (a == "--rules") { if (const char* v = next()) rules_path = v; }
    else if (a == "--subscribers") { if (const char* v = next()) subs_path = v; }
    else if (a == "--out") { if (const char* v = next()) out_path = v; }
    else { std::fprintf(stderr, "unknown option '%s'\n", a.c_str()); return 2; }
  }

  auto compiled = policy::compile_rules_from_file(rules_path, 1);
  if (!compiled.ok()) {
    std::fprintf(stderr, "cannot compile %s: %s\n", rules_path.c_str(),
                 compiled.error_summary().c_str());
    return 1;
  }
  const policy::RuleSet& rs = *compiled.rule_set;

  policy::SubscriberStore store(1 << 16);
  const auto load = store.load_csv(subs_path, rs.plan_names);
  if (!load.ok()) {
    for (const auto& e : load.errors) std::fprintf(stderr, "%s\n", e.c_str());
    return 1;
  }
  if (load.loaded == 0) {
    std::fprintf(stderr, "%s contains no subscribers\n", subs_path.c_str());
    return 1;
  }

  // Period expiry depends on wall-clock time, which would make the golden file
  // change with the calendar. Pin the clock to a fixed instant so the corpus is
  // reproducible; the reader pins the same one.
  policy::set_coarse_now_unix_s(policy::kGoldenClockUnixS);

  std::vector<std::uint64_t> imsis;
  imsis.reserve(load.loaded);
  store.for_each([&](const policy::SubscriberRecord& r) { imsis.push_back(r.imsi); });

  std::vector<std::uint64_t> blocked;
  rs.imei_blocklist.for_each([&](std::uint64_t k) { blocked.push_back(k); });
  std::vector<std::uint32_t> visited;
  rs.roaming_partners.for_each([&](std::uint64_t k) { visited.push_back(static_cast<std::uint32_t>(k)); });
  // Include one network that is not a partner, so the PLMN_NOT_PARTNER rule is
  // represented in the corpus.
  visited.push_back(46000);

  policy::RequestGenerator gen(seed, std::move(imsis), std::move(blocked), std::move(visited),
                               static_cast<std::uint8_t>(rs.dnn_names.size()));

  std::FILE* out = std::fopen(out_path.c_str(), "w");
  if (out == nullptr) {
    std::fprintf(stderr, "cannot write %s\n", out_path.c_str());
    return 1;
  }
  std::fprintf(out, "%s\n", policy::golden_header().c_str());

  policy::PolicyRequest req;
  for (std::size_t i = 0; i < count; ++i) {
    gen.fill(req);
    const policy::SubscriberRecord* rec = store.find(req.imsi);
    if (req.plmn == 0) req.plmn = rec != nullptr ? rec->home_plmn : 310260;
    const policy::PolicyDecision d = policy::evaluate(rs, req, rec);
    std::fprintf(out, "%s\n", policy::golden_row(req, d).c_str());
  }
  std::fclose(out);

  std::fprintf(stderr, "wrote %zu golden cases to %s (seed %llu, policy sha256 %.12s)\n", count,
               out_path.c_str(), static_cast<unsigned long long>(seed), rs.source_sha256.c_str());
  return 0;
}
