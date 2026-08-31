#include "policy/engine.hpp"

#include <cassert>
#include <string>

#include "policy/coarse_clock.hpp"

namespace policy {
namespace {

// Standardized GBR 5QI values (TS 23.501 Table 5.7.4-1). Kept as a bitmap over
// 0..127 so the test is two loads and a shift rather than a chain of compares.
constexpr std::uint64_t gbr_lo_bits() {
  std::uint64_t m = 0;
  for (int q : {1, 2, 3, 4, 65, 66, 67, 71, 72, 73, 74, 75, 76}) {
    if (q < 64) m |= std::uint64_t{1} << q;
  }
  return m;
}
constexpr std::uint64_t gbr_hi_bits() {
  std::uint64_t m = 0;
  for (int q : {1, 2, 3, 4, 65, 66, 67, 71, 72, 73, 74, 75, 76}) {
    if (q >= 64 && q < 128) m |= std::uint64_t{1} << (q - 64);
  }
  return m;
}
constexpr std::uint64_t kGbrLo = gbr_lo_bits();
constexpr std::uint64_t kGbrHi = gbr_hi_bits();

[[nodiscard]] inline bool is_gbr_5qi(std::uint8_t q) noexcept {
  if (q < 64) return (kGbrLo >> q) & 1u;
  if (q < 128) return (kGbrHi >> (q - 64)) & 1u;
  return false;
}

// usage >= permille/1000 * quota, computed without overflow or division.
// 128-bit multiply is a single instruction on both x86-64 and AArch64.
[[nodiscard]] inline bool usage_at_least_permille(std::uint64_t usage, std::uint64_t quota,
                                                  std::uint32_t permille) noexcept {
  if (quota == 0) return false;  // unmetered plan: no threshold is ever crossed
  const auto lhs = static_cast<unsigned __int128>(usage) * 1000u;
  const auto rhs = static_cast<unsigned __int128>(quota) * permille;
  return lhs >= rhs;
}

}  // namespace

std::uint32_t plan_bit_for(const SubscriberRecord* rec) noexcept {
  if (rec == nullptr) return 0;
  const std::uint32_t id = rec->plan_id;
  if (id >= kMaxPlans) return 0;
  return std::uint32_t{1} << id;
}

FeatureWord build_features(const RuleSet& rs, const PolicyRequest& req,
                           const SubscriberRecord* rec) noexcept {
  FeatureWord f = 0;

  // --- Access type -------------------------------------------------------
  if (req.rat_type < feat::kRatBits) f |= feat::bit(feat::kRatBase + req.rat_type);

  // --- DNN ---------------------------------------------------------------
  if (req.dnn_id < feat::kDnnBits) f |= feat::bit(feat::kDnnBase + req.dnn_id);

  // --- Device ------------------------------------------------------------
  if (req.imei != 0) {
    f |= feat::bit(feat::kImeiKnown);
    if (rs.imei_blocklist.contains(req.imei)) f |= feat::bit(feat::kImeiBlocked);
  }

  // --- Session hints from the request ------------------------------------
  if (req.flags & kReqFlagTetheringDetected) f |= feat::bit(feat::kTetheringDetected);
  if (req.flags & kReqFlagEmergency) f |= feat::bit(feat::kEmergency);
  if (is_gbr_5qi(req.requested_5qi)) f |= feat::bit(feat::kRequestedGbr);

  // --- Time windows ------------------------------------------------------
  // The local minute comes from the request: the serving node knows the
  // subscriber's local time zone, this service does not, and guessing it from
  // the PLMN would be wrong for anyone roaming.
  const auto minute = static_cast<std::uint16_t>(req.local_minute % 1440u);
  for (std::uint32_t i = 0; i < rs.time_window_count; ++i) {
    if (rs.time_windows[i].contains(minute)) f |= feat::bit(feat::kTimeWindowBase + static_cast<int>(i));
  }

  // --- Subscriber --------------------------------------------------------
  if (rec == nullptr) {
    f |= feat::bit(feat::kStatusUnknown);
    // An unknown subscriber is, by definition, not roaming on a home network.
    f |= feat::bit(feat::kRoaming);
    return f;
  }

  switch (static_cast<SubscriberStatus>(rec->status)) {
    case SubscriberStatus::kActive: f |= feat::bit(feat::kStatusActive); break;
    case SubscriberStatus::kSuspended: f |= feat::bit(feat::kStatusSuspended); break;
    case SubscriberStatus::kBarred: f |= feat::bit(feat::kStatusBarred); break;
    default: f |= feat::bit(feat::kStatusUnknown); break;
  }

  if (req.plmn == rec->home_plmn) {
    f |= feat::bit(feat::kHomePlmn);
  } else {
    f |= feat::bit(feat::kRoaming);
    if (rs.roaming_partners.contains(req.plmn)) f |= feat::bit(feat::kRoamingPartner);
  }
  if (rec->flags & kSubRoamingAllowed) f |= feat::bit(feat::kRoamingAllowed);

  const PlanConfig* plan = rs.plan(rec->plan_id);
  const bool plan_tethering = plan != nullptr && (plan->flags & kPlanTetheringAllowed);
  if (plan_tethering || (rec->flags & kSubTetheringAllowed)) f |= feat::bit(feat::kTetheringAllowed);

  // --- Usage / quota -----------------------------------------------------
  // A serving node that already knows the session's usage may report it; that
  // is fresher than our replicated counter, so it wins when present.
  const std::uint64_t usage =
      (req.flags & kReqFlagUsageValid) ? req.bytes_used_period : load_usage(*rec);
  const std::uint64_t quota = plan != nullptr ? plan->quota_bytes : 0;

  if (quota != 0 && usage >= quota) f |= feat::bit(feat::kQuotaExhausted);
  for (std::uint32_t i = 0; i < rs.usage_threshold_count; ++i) {
    if (usage_at_least_permille(usage, quota, rs.usage_thresholds_permille[i])) {
      f |= feat::bit(feat::kUsageThresholdBase + static_cast<int>(i));
    }
  }

  const std::uint64_t now = coarse_now_unix_s();
  if (now != 0 && rec->period_reset_ts != 0 && now >= rec->period_reset_ts) {
    f |= feat::bit(feat::kPeriodExpired);
  }

  return f;
}

PolicyDecision evaluate(const RuleSet& rs, const PolicyRequest& req,
                        const SubscriberRecord* rec) noexcept {
  const FeatureWord f = build_features(rs, req, rec);
  const std::uint32_t plan_bit = plan_bit_for(rec);

  // Linear scan in priority order. The loop body is branch-predictable (the
  // early iterations almost always miss) and the rule array is contiguous, so
  // the hardware prefetcher covers the whole scan.
  const CompiledRule* hit = nullptr;
  for (const CompiledRule& r : rs.rules) {
    if ((f & r.match_mask) != r.match_value) continue;
    if (r.plan_mask != 0 && (r.plan_mask & plan_bit) == 0) continue;
    hit = &r;
    break;
  }

  const Action& act = hit != nullptr ? hit->action : rs.default_action;
  const PlanConfig* plan = rec != nullptr ? rs.plan(rec->plan_id) : nullptr;

  PolicyDecision d{};
  d.magic_version = kMagicVersion;
  d.seq = req.seq;
  d.client_ts_ns = req.client_ts_ns;
  d.policy_version = rs.version;
  d.rule_id = hit != nullptr ? hit->id : 0;
  d.verdict = act.verdict;
  d.reason = hit != nullptr ? act.reason : static_cast<std::uint8_t>(Reason::kNoMatchingRule);
  d.redirect_id = act.redirect_id;
  d.flags = act.set_flags;

  // Field-by-field: take the rule's value, or the plan's where the rule asked
  // to inherit. A rule that inherits from a subscriber with no plan (unknown
  // subscriber) gets zeros, which is correct — there is nothing to authorize.
  const bool inh_qos = (act.inherit_mask & kInheritQos) && plan != nullptr;
  const bool inh_ambr = (act.inherit_mask & kInheritAmbr) && plan != nullptr;
  const bool inh_quota = (act.inherit_mask & kInheritQuota) && plan != nullptr;
  const bool inh_rg = (act.inherit_mask & kInheritRatingGroup) && plan != nullptr;

  d.qos_5qi = inh_qos ? plan->qos_5qi : act.qos_5qi;
  d.arp = inh_qos ? plan->arp : act.arp;
  d.ambr_ul_kbps = inh_ambr ? plan->ambr_ul_kbps : act.ambr_ul_kbps;
  d.ambr_dl_kbps = inh_ambr ? plan->ambr_dl_kbps : act.ambr_dl_kbps;
  d.rating_group = inh_rg ? plan->rating_group : act.rating_group;

  if (inh_quota) {
    // Grant the remaining quota, not the whole allowance: the serving node uses
    // this as a credit grant and will come back for more.
    const std::uint64_t usage =
        (req.flags & kReqFlagUsageValid) ? req.bytes_used_period
                                         : (rec != nullptr ? load_usage(*rec) : 0);
    d.quota_bytes = plan->quota_bytes > usage ? plan->quota_bytes - usage : 0;
    d.quota_validity_s = plan->quota_validity_s;
  } else {
    d.quota_bytes = act.quota_bytes;
    d.quota_validity_s = act.quota_validity_s;
  }

  if (req.flags & kReqFlagUsageValid) d.flags |= kFlagUsageFromRequest;

  // A DENY carries no authorization. Zeroing here means a serving node that
  // ignores the verdict still cannot open a bearer on the strength of the
  // reply's QoS fields.
  if (d.verdict == static_cast<std::uint8_t>(Verdict::kDeny)) {
    d.ambr_ul_kbps = 0;
    d.ambr_dl_kbps = 0;
    d.quota_bytes = 0;
    d.quota_validity_s = 0;
    d.qos_5qi = 0;
    d.arp = 0;
  }

  return d;
}

PolicyDecision malformed_decision(std::uint32_t seq, std::uint64_t client_ts_ns,
                                  std::uint32_t policy_version) noexcept {
  PolicyDecision d{};
  d.magic_version = kMagicVersion;
  d.seq = seq;
  d.client_ts_ns = client_ts_ns;
  d.policy_version = policy_version;
  d.verdict = static_cast<std::uint8_t>(Verdict::kDeny);
  d.reason = static_cast<std::uint8_t>(Reason::kMalformedRequest);
  return d;
}

std::string describe_features(const RuleSet& rs, FeatureWord f) {
  std::string out;
  auto add = [&](const char* name) {
    if (!out.empty()) out += ' ';
    out += name;
  };

  for (int i = 0; i < feat::kRatBits; ++i) {
    if (f & feat::bit(feat::kRatBase + i)) {
      out += out.empty() ? "" : " ";
      out += "rat=";
      out += rat_name(static_cast<RatType>(i));
    }
  }
  for (int i = 0; i < feat::kDnnBits; ++i) {
    if (f & feat::bit(feat::kDnnBase + i)) {
      out += out.empty() ? "" : " ";
      out += "dnn=";
      out += static_cast<std::size_t>(i) < rs.dnn_names.size() ? rs.dnn_names[static_cast<std::size_t>(i)]
                                                              : std::to_string(i);
    }
  }

  struct NamedBit {
    int bit;
    const char* name;
  };
  static constexpr NamedBit kNamed[] = {
      {feat::kStatusActive, "status=ACTIVE"},
      {feat::kStatusSuspended, "status=SUSPENDED"},
      {feat::kStatusBarred, "status=BARRED"},
      {feat::kStatusUnknown, "status=UNKNOWN"},
      {feat::kHomePlmn, "home_plmn"},
      {feat::kRoaming, "roaming"},
      {feat::kRoamingPartner, "roaming_partner"},
      {feat::kRoamingAllowed, "roaming_allowed"},
      {feat::kImeiKnown, "imei_known"},
      {feat::kImeiBlocked, "imei_blocked"},
      {feat::kTetheringDetected, "tethering_detected"},
      {feat::kTetheringAllowed, "tethering_allowed"},
      {feat::kEmergency, "emergency"},
      {feat::kQuotaExhausted, "quota_exhausted"},
      {feat::kPeriodExpired, "period_expired"},
      {feat::kRequestedGbr, "requested_gbr"},
  };
  for (const auto& nb : kNamed) {
    if (f & feat::bit(nb.bit)) add(nb.name);
  }

  for (std::uint32_t i = 0; i < rs.time_window_count; ++i) {
    if (f & feat::bit(feat::kTimeWindowBase + static_cast<int>(i))) {
      add("time_window");
      out += '[' + std::to_string(rs.time_windows[i].start_minute) + '-' +
             std::to_string(rs.time_windows[i].end_minute) + ']';
    }
  }
  for (std::uint32_t i = 0; i < rs.usage_threshold_count; ++i) {
    if (f & feat::bit(feat::kUsageThresholdBase + static_cast<int>(i))) {
      add("usage>=");
      out += std::to_string(rs.usage_thresholds_permille[i]) + "permille";
    }
  }

  return out.empty() ? "(none)" : out;
}

}  // namespace policy
