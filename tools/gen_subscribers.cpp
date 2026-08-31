// Synthetic subscriber roster generator.
//
// The distribution matters, because a benchmark run against uniformly random
// well-behaved subscribers measures the wrong thing. This generator produces:
//
//   * IMSIs allocated in contiguous blocks per PLMN, the way a carrier actually
//     allocates them — which is precisely the input that makes an identity hash
//     collapse and justifies the splitmix64 finalizer in the store.
//   * A plan mix weighted towards the cheap plans, as in a real base.
//   * A status mix with ~2% suspended and ~0.3% barred, so the DENY paths get
//     exercised at a realistic rate instead of never or half the time.
//   * A usage distribution that is heavily skewed: most subscribers are far
//     below their quota, a long tail is near it, and a few percent are over.
//     The rules that fire at 80% and 100% are the interesting ones.
//   * Valid Luhn IMEIs, so the admin API's validation is exercised.
//
// Everything is driven by a seeded PRNG: the same seed gives the same roster on
// every machine, which is what makes the golden decision file reproducible.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <random>
#include <string>
#include <vector>

#include "policy/imsi.hpp"
#include "policy/rules.hpp"

namespace {

struct Options {
  std::size_t count = 1'000'000;
  std::uint64_t seed = 20260830;
  std::string rules_path = "config/rules.yaml";
  std::string out_path;  // empty = stdout
};

void usage(const char* argv0) {
  std::printf(
      "Generate a synthetic subscriber roster.\n"
      "\n"
      "Usage: %s [--count N] [--seed N] [--rules PATH] [--out PATH]\n"
      "\n"
      "  --count N     Subscribers to generate (default 1000000)\n"
      "  --seed N      PRNG seed; the same seed gives the same roster (default 20260830)\n"
      "  --rules PATH  Rules file, read for the plan names (default config/rules.yaml)\n"
      "  --out PATH    Output file (default: stdout)\n",
      argv0);
}

// Home networks, with the weight of each in the generated base.
struct Plmn {
  std::uint32_t plmn;
  int weight;
};
// PLMNs are packed as MCC*1000 + MNC, the same encoding the wire format and
// the rules file use — so 234-15 is 234015, not 23415. Writing the latter
// silently reinterprets it as MCC 23 / MNC 415.
constexpr Plmn kHomeNetworks[] = {
    {310260, 60},  // T-Mobile US — the "home" network for most of the base
    {310410, 20},  // AT&T US
    {234015, 8},   // Vodafone UK
    {262001, 6},   // Telekom DE
    {208001, 6},   // Orange FR
};

// Plan weights, indexed by position in the rules file's plan list.
constexpr int kPlanWeights[] = {45, 20, 20, 12, 3};

std::uint64_t make_luhn_imei(std::uint64_t body14) {
  // body14 is the 14 significant digits; append the Luhn check digit.
  std::uint32_t sum = 0;
  bool dbl = true;  // the check digit position makes the last body digit doubled
  std::uint64_t v = body14;
  while (v > 0) {
    auto d = static_cast<std::uint32_t>(v % 10);
    v /= 10;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  const std::uint64_t check = (10 - (sum % 10)) % 10;
  return body14 * 10 + check;
}

template <std::size_t N>
std::size_t weighted_pick(const int (&weights)[N], std::mt19937_64& rng) {
  int total = 0;
  for (const int w : weights) total += w;
  std::uniform_int_distribution<int> dist(0, total - 1);
  int r = dist(rng);
  for (std::size_t i = 0; i < N; ++i) {
    r -= weights[i];
    if (r < 0) return i;
  }
  return N - 1;
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else if (a == "--count") { if (const char* v = next()) opt.count = std::strtoull(v, nullptr, 10); }
    else if (a == "--seed") { if (const char* v = next()) opt.seed = std::strtoull(v, nullptr, 10); }
    else if (a == "--rules") { if (const char* v = next()) opt.rules_path = v; }
    else if (a == "--out") { if (const char* v = next()) opt.out_path = v; }
    else { std::fprintf(stderr, "unknown option '%s'\n", a.c_str()); return 2; }
  }

  // Plan names come from the rules file rather than being hard-coded, so the
  // roster and the policy cannot drift apart.
  auto compiled = policy::compile_rules_from_file(opt.rules_path, 1);
  if (!compiled.ok()) {
    std::fprintf(stderr, "cannot compile %s: %s\n", opt.rules_path.c_str(),
                 compiled.error_summary().c_str());
    return 1;
  }
  const std::vector<std::string>& plans = compiled.rule_set->plan_names;
  if (plans.empty()) {
    std::fprintf(stderr, "%s defines no plans\n", opt.rules_path.c_str());
    return 1;
  }

  std::FILE* out = stdout;
  if (!opt.out_path.empty()) {
    out = std::fopen(opt.out_path.c_str(), "w");
    if (out == nullptr) {
      std::fprintf(stderr, "cannot write %s\n", opt.out_path.c_str());
      return 1;
    }
  }

  // Quotas per plan, needed to place usage relative to the limit.
  std::vector<std::uint64_t> quota(plans.size(), 0);
  for (std::size_t i = 0; i < plans.size() && i < policy::kMaxPlans; ++i) {
    quota[i] = compiled.rule_set->plans[i].quota_bytes;
  }

  std::mt19937_64 rng(opt.seed);
  std::uniform_real_distribution<double> unit(0.0, 1.0);

  int plmn_total = 0;
  for (const auto& p : kHomeNetworks) plmn_total += p.weight;

  std::fprintf(out, "imsi,imei,plan,status,bytes_used,period_reset_ts,home_plmn,flags\n");

  // 2026-09-30T00:00:00Z, a plausible next billing boundary.
  constexpr std::uint64_t kPeriodEnd = 1790380800ull;

  // IMSIs are allocated as a contiguous block per network, starting from the
  // network's own MSIN base — sequential, exactly like a real allocation.
  std::vector<std::uint64_t> next_msin(std::size(kHomeNetworks), 100000000ull);

  std::string line;
  line.reserve(128);

  for (std::size_t i = 0; i < opt.count; ++i) {
    std::uniform_int_distribution<int> plmn_dist(0, plmn_total - 1);
    int r = plmn_dist(rng);
    std::size_t net = 0;
    for (std::size_t k = 0; k < std::size(kHomeNetworks); ++k) {
      r -= kHomeNetworks[k].weight;
      if (r < 0) { net = k; break; }
    }
    const std::uint32_t plmn = kHomeNetworks[net].plmn;

    // IMSI = MCC(3) MNC(2 or 3) MSIN(rest), 15 digits total.
    const std::uint32_t mcc = policy::plmn_mcc(plmn);
    const std::uint32_t mnc = policy::plmn_mnc(plmn);
    const int mnc_digits = mnc >= 100 ? 3 : 2;
    const int msin_digits = 15 - 3 - mnc_digits;
    std::uint64_t msin_mod = 1;
    for (int d = 0; d < msin_digits; ++d) msin_mod *= 10;

    const std::uint64_t msin = next_msin[net]++ % msin_mod;
    std::uint64_t imsi = mcc;
    for (int d = 0; d < mnc_digits; ++d) imsi *= 10;
    imsi += mnc;
    imsi = imsi * msin_mod + msin;

    const std::size_t plan_id = weighted_pick(kPlanWeights, rng);
    const std::string& plan = plans[std::min(plan_id, plans.size() - 1)];

    // Status: 97.7% active, 2% suspended, 0.3% barred.
    const double su = unit(rng);
    const char* status = su < 0.977 ? "ACTIVE" : (su < 0.997 ? "SUSPENDED" : "BARRED");

    // Usage: 70% under half their quota, 20% between half and 80%, 7% between
    // 80% and 100% (the warning band), 3% over (the throttle band).
    const std::uint64_t q = quota[std::min(plan_id, quota.size() - 1)];
    std::uint64_t used = 0;
    if (q > 0) {
      const double u = unit(rng);
      double fraction;
      if (u < 0.70) fraction = unit(rng) * 0.5;
      else if (u < 0.90) fraction = 0.5 + unit(rng) * 0.3;
      else if (u < 0.97) fraction = 0.8 + unit(rng) * 0.2;
      else fraction = 1.0 + unit(rng) * 0.6;
      used = static_cast<std::uint64_t>(static_cast<double>(q) * fraction);
    } else {
      used = static_cast<std::uint64_t>(unit(rng) * 5e11);  // unmetered, still counted
    }

    // IMEI: TAC block per network, then a serial, then the Luhn digit.
    const std::uint64_t tac = 35000000ull + net * 111111ull;
    std::uniform_int_distribution<std::uint64_t> serial_dist(0, 999999);
    const std::uint64_t body = tac * 1000000ull + serial_dist(rng);
    const std::uint64_t imei = make_luhn_imei(body);

    // Entitlements: 85% may roam, 40% have tethering, 1% are test SIMs.
    std::string flags;
    if (unit(rng) < 0.85) flags += "roaming";
    if (unit(rng) < 0.40) flags += flags.empty() ? "tethering" : "|tethering";
    if (unit(rng) < 0.60) flags += flags.empty() ? "volte" : "|volte";
    if (unit(rng) < 0.01) flags += flags.empty() ? "test" : "|test";

    // Period reset dates spread over the month, as billing cycles are.
    std::uniform_int_distribution<std::uint64_t> day_dist(0, 29);
    const std::uint64_t reset = kPeriodEnd - day_dist(rng) * 86400ull;

    // The MNC is written with its real digit count: "262-01" and "262-1" are
    // the same packed value, but only the first is how an operator writes it.
    std::fprintf(out, "%s,%015llu,%s,%s,%llu,%llu,%u-%0*u,%s\n",
                 policy::format_imsi(imsi).c_str(), static_cast<unsigned long long>(imei),
                 plan.c_str(), status, static_cast<unsigned long long>(used),
                 static_cast<unsigned long long>(reset), mcc, mnc_digits, mnc, flags.c_str());
  }

  if (out != stdout) std::fclose(out);
  std::fprintf(stderr, "generated %zu subscribers (seed %llu)\n", opt.count,
               static_cast<unsigned long long>(opt.seed));
  return 0;
}
