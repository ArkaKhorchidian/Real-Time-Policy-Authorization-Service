// Compiled rule representation.
//
// Rules arrive as YAML. They are never interpreted in that form. At load time
// the compiler turns every rule into a fixed 64-byte `CompiledRule` whose match
// condition is a single (mask, value) pair over a 64-bit feature word, plus a
// plan bitmask. Matching one rule is then:
//
//     (features & rule.match_mask) == rule.match_value && (rule.plan_mask & plan_bit)
//
// — two ANDs, a compare and a test. No strings, no regex, no allocation, no
// branches that depend on rule content. `evaluate()` scans rules in priority
// order and stops at the first match.
//
// Why a linear scan: a realistic operator policy is ~50-200 rules. At 64 bytes
// each that is 3-13 KB, which lives in L1d and is prefetched perfectly by the
// hardware because the scan is sequential. A decision tree or interval index
// would replace ~100 predictable, pipelined iterations with ~7 dependent loads
// and unpredictable branches — measurably slower at this size. The linear scan
// is the right structure until the rule count is in the thousands, and the
// benchmark in bench/results/rule_count_sweep.csv shows where that crossover is.
//
// Conditions that are not naturally boolean — "usage above 80% of plan quota",
// "between 02:00 and 06:00 local" — are turned into bits at compile time: the
// compiler collects the distinct thresholds and windows a rule set mentions
// (up to 8 of each) and assigns each one a feature bit. The per-request work is
// then a comparison per distinct threshold, done once during feature
// construction, instead of once per rule.
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "policy/flat_set.hpp"
#include "policy/wire.hpp"

namespace policy {

// ---------------------------------------------------------------------------
// Capacity limits. These are compile-time so every structure below is
// fixed-size and the feature word stays 64 bits. Raising them is a deliberate
// act with a memory cost, not a config knob.
// ---------------------------------------------------------------------------
inline constexpr std::size_t kMaxPlans = 32;             // plan_mask is uint32
inline constexpr std::size_t kMaxDnns = 16;              // 16 feature bits
inline constexpr std::size_t kMaxTimeWindows = 8;
inline constexpr std::size_t kMaxUsageThresholds = 8;
inline constexpr std::size_t kMaxRedirects = 16;
inline constexpr std::size_t kMaxRules = 4096;

// ---------------------------------------------------------------------------
// Feature bit layout — the contract between the compiler and evaluate().
// ---------------------------------------------------------------------------
namespace feat {

// RAT, one-hot. Bits 0-2 used, 3-7 reserved for future access types.
inline constexpr int kRatBase = 0;
inline constexpr int kRatBits = 8;

// DNN / APN, one-hot over the rule set's DNN table. Bits 8-23.
inline constexpr int kDnnBase = 8;
inline constexpr int kDnnBits = 16;

// Subscriber state. Exactly one of ACTIVE/SUSPENDED/BARRED/UNKNOWN is set.
inline constexpr int kStatusActive = 24;
inline constexpr int kStatusSuspended = 25;
inline constexpr int kStatusBarred = 26;
inline constexpr int kStatusUnknown = 27;

// Location / roaming.
inline constexpr int kHomePlmn = 28;
inline constexpr int kRoaming = 29;       // serving PLMN != home PLMN
inline constexpr int kRoamingPartner = 30;  // serving PLMN is in the partner table
inline constexpr int kRoamingAllowed = 31;  // subscriber's own roaming entitlement

// Device.
inline constexpr int kImeiKnown = 32;
inline constexpr int kImeiBlocked = 33;

// Session / entitlement.
inline constexpr int kTetheringDetected = 34;
inline constexpr int kTetheringAllowed = 35;
inline constexpr int kEmergency = 36;
inline constexpr int kQuotaExhausted = 37;
inline constexpr int kPeriodExpired = 38;
inline constexpr int kRequestedGbr = 39;  // requested 5QI is a GBR class

// Compiler-assigned predicate bits.
inline constexpr int kTimeWindowBase = 40;   // 40-47
inline constexpr int kUsageThresholdBase = 48;  // 48-55
// 56-63 reserved.

constexpr std::uint64_t bit(int b) { return std::uint64_t{1} << b; }

}  // namespace feat

using FeatureWord = std::uint64_t;

// ---------------------------------------------------------------------------
// Action
// ---------------------------------------------------------------------------

// Fields a rule may leave to the subscriber's plan rather than overriding.
enum InheritBit : std::uint8_t {
  kInheritQos = 1u << 0,      // qos_5qi + arp
  kInheritAmbr = 1u << 1,     // ambr ul + dl
  kInheritQuota = 1u << 2,    // quota_bytes + quota_validity_s
  kInheritRatingGroup = 1u << 3,
  kInheritAll = 0x0Fu,
};

// Fixed size, no pointers, trivially copyable — it is memcpy'd into the reply.
struct Action {
  std::uint64_t quota_bytes;        //  0
  std::uint32_t ambr_ul_kbps;       //  8
  std::uint32_t ambr_dl_kbps;       // 12
  std::uint32_t rating_group;       // 16
  std::uint32_t quota_validity_s;   // 20
  std::uint8_t verdict;             // 24  Verdict
  std::uint8_t reason;              // 25  Reason
  std::uint8_t qos_5qi;             // 26
  std::uint8_t arp;                 // 27  1..15
  std::uint8_t set_flags;           // 28  DecisionFlag bits to OR into the reply
  std::uint8_t redirect_id;         // 29
  std::uint8_t inherit_mask;        // 30  InheritBit
  std::uint8_t reserved;            // 31
};
static_assert(sizeof(Action) == 32, "Action must stay 32 B — two per cache line");
static_assert(std::is_trivially_copyable_v<Action>);

// ---------------------------------------------------------------------------
// CompiledRule — exactly one cache line
// ---------------------------------------------------------------------------
struct alignas(64) CompiledRule {
  std::uint64_t match_mask;   //  0  which feature bits this rule cares about
  std::uint64_t match_value;  //  8  what they must equal
  std::uint32_t plan_mask;    // 16  0 = applies to every plan
  std::uint32_t id;           // 20  stable id, echoed in the decision
  std::uint32_t priority;     // 24  lower fires first
  std::uint32_t reserved;     // 28
  Action action;              // 32
};
static_assert(sizeof(CompiledRule) == 64, "CompiledRule must be exactly one cache line");
static_assert(std::is_trivially_copyable_v<CompiledRule>);

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------
enum PlanFlag : std::uint16_t {
  kPlanTetheringAllowed = 1u << 0,
  kPlanRoamingAllowed = 1u << 1,
};

struct PlanConfig {
  std::uint64_t quota_bytes = 0;  // 0 = unmetered
  std::uint32_t quota_validity_s = 0;
  std::uint32_t rating_group = 0;
  std::uint32_t ambr_ul_kbps = 0;
  std::uint32_t ambr_dl_kbps = 0;
  std::uint32_t id = 0;
  std::uint8_t qos_5qi = 9;
  std::uint8_t arp = 8;
  std::uint16_t flags = 0;
};

// ---------------------------------------------------------------------------
// Compiler-assigned predicates
// ---------------------------------------------------------------------------

// Local-time window, in minutes since midnight. `start > end` wraps midnight,
// which is the common case for off-peak windows.
struct TimeWindow {
  std::uint16_t start_minute = 0;
  std::uint16_t end_minute = 0;

  [[nodiscard]] constexpr bool contains(std::uint16_t m) const noexcept {
    return start_minute <= end_minute ? (m >= start_minute && m < end_minute)
                                      : (m >= start_minute || m < end_minute);
  }
};

// ---------------------------------------------------------------------------
// RuleSet — the immutable snapshot workers read through RCU
// ---------------------------------------------------------------------------
struct RuleSet {
  std::uint32_t version = 0;
  std::vector<CompiledRule> rules;  // sorted by priority, then by id

  std::array<PlanConfig, kMaxPlans> plans{};
  std::uint32_t plan_count = 0;

  std::array<TimeWindow, kMaxTimeWindows> time_windows{};
  std::uint32_t time_window_count = 0;

  // Thresholds are per-mille of the plan quota, so one bit means the same thing
  // for a 1 GB plan and a 1 TB plan.
  std::array<std::uint32_t, kMaxUsageThresholds> usage_thresholds_permille{};
  std::uint32_t usage_threshold_count = 0;

  FlatSet64 roaming_partners;  // packed PLMNs
  FlatSet64 imei_blocklist;

  // Name tables — control plane and admin API only, never touched by evaluate().
  std::vector<std::string> plan_names;
  std::vector<std::string> dnn_names;
  std::vector<std::string> redirect_targets;

  // What happens when no rule matches. Defaults to DENY: a policy engine that
  // fails open is a billing incident.
  Action default_action{};

  // Provenance, surfaced on /rules and in logs.
  std::string source_path;
  std::string source_sha256;
  std::uint64_t loaded_at_unix_ns = 0;

  [[nodiscard]] const PlanConfig* plan(std::uint32_t plan_id) const noexcept {
    return plan_id < plan_count ? &plans[plan_id] : nullptr;
  }

  [[nodiscard]] std::size_t rule_bytes() const noexcept {
    return rules.size() * sizeof(CompiledRule);
  }
};

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

struct RuleCompileError {
  std::string message;
  int line = 0;  // 0 when the error is not tied to a source line
};

struct RuleCompileResult {
  std::unique_ptr<RuleSet> rule_set;
  std::vector<RuleCompileError> errors;
  std::vector<std::string> warnings;

  [[nodiscard]] bool ok() const noexcept { return rule_set != nullptr && errors.empty(); }
  [[nodiscard]] std::string error_summary() const;
};

// Compile from a YAML document already read into memory. `source_path` is used
// only for error messages and provenance.
RuleCompileResult compile_rules(std::string_view yaml_text, std::string_view source_path,
                                std::uint32_t version);

// Read the file and compile it.
RuleCompileResult compile_rules_from_file(const std::string& path, std::uint32_t version);

}  // namespace policy
