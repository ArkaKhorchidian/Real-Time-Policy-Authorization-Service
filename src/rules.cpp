#include "policy/rules.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

#include "policy/coarse_clock.hpp"
#include "policy/imsi.hpp"
#include "policy/sha256.hpp"
#include "policy/yaml.hpp"

namespace policy {
namespace {

using yaml::Node;

// A single source rule may expand into several compiled rules: a one-hot
// feature group (RAT, DNN) cannot express "LTE or NR" in one (mask, value)
// pair, so the compiler emits the cross product instead. This is bounded so a
// careless list cannot generate a 10,000-rule table.
constexpr std::size_t kMaxExpansionPerRule = 64;

std::string to_upper(std::string_view s) {
  std::string out(s);
  for (char& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return out;
}

// ---------------------------------------------------------------------------
// Enum name tables
// ---------------------------------------------------------------------------
std::optional<Verdict> parse_verdict(std::string_view s) {
  const std::string u = to_upper(s);
  if (u == "ALLOW" || u == "PERMIT") return Verdict::kAllow;
  if (u == "DENY" || u == "REJECT" || u == "BLOCK") return Verdict::kDeny;
  if (u == "REDIRECT") return Verdict::kRedirect;
  return std::nullopt;
}

std::optional<Reason> parse_reason(std::string_view s) {
  const std::string u = to_upper(s);
  for (int i = 0; i < static_cast<int>(Reason::kCount); ++i) {
    if (u == reason_name(static_cast<Reason>(i))) return static_cast<Reason>(i);
  }
  return std::nullopt;
}

std::optional<RatType> parse_rat(std::string_view s) {
  const std::string u = to_upper(s);
  if (u == "LTE" || u == "EUTRAN" || u == "4G") return RatType::kLte;
  if (u == "NR" || u == "5G" || u == "NGRAN") return RatType::kNr;
  if (u == "WLAN" || u == "WIFI" || u == "WI-FI") return RatType::kWlan;
  return std::nullopt;
}

std::optional<std::uint8_t> parse_decision_flag(std::string_view s) {
  const std::string u = to_upper(s);
  if (u == "THROTTLED") return static_cast<std::uint8_t>(kFlagThrottled);
  if (u == "ROAMING_RESTRICTED") return static_cast<std::uint8_t>(kFlagRoamingRestricted);
  if (u == "TETHERING_BLOCKED") return static_cast<std::uint8_t>(kFlagTetheringBlocked);
  if (u == "QUOTA_WARNING") return static_cast<std::uint8_t>(kFlagQuotaWarning);
  if (u == "OFF_PEAK_BONUS") return static_cast<std::uint8_t>(kFlagOffPeakBonus);
  return std::nullopt;
}

std::optional<std::uint8_t> parse_inherit(std::string_view s) {
  const std::string u = to_upper(s);
  if (u == "ALL") return static_cast<std::uint8_t>(kInheritAll);
  if (u == "QOS") return static_cast<std::uint8_t>(kInheritQos);
  if (u == "AMBR") return static_cast<std::uint8_t>(kInheritAmbr);
  if (u == "QUOTA") return static_cast<std::uint8_t>(kInheritQuota);
  if (u == "RATING_GROUP") return static_cast<std::uint8_t>(kInheritRatingGroup);
  return std::nullopt;
}

// 5QI values 1..255 are legal on the wire; 0 means "not set". Standardized
// values are checked so a typo (95 instead of 9) is caught at load time rather
// than rejected by a serving node in production. Operator-specific 5QIs live in
// 128..254 and are allowed without a warning.
bool is_standardized_5qi(std::uint8_t q) {
  static const std::set<std::uint8_t> kStd = {1,  2,  3,  4,  5,  6,  7,  8,  9,  65, 66, 67,
                                              69, 70, 71, 72, 73, 74, 75, 76, 79, 80, 82, 83,
                                              84, 85, 86};
  return kStd.count(q) > 0;
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------
class Compiler {
 public:
  Compiler(std::string_view text, std::string_view source_path, std::uint32_t version)
      : text_(text), source_path_(source_path), version_(version) {}

  RuleCompileResult run() {
    auto parsed = yaml::parse(text_);
    if (!parsed.ok()) {
      err(parsed.error, parsed.error_line);
      return std::move(result_);
    }
    if (!parsed.root.is_map()) {
      err("rules file must be a mapping at the top level", parsed.root.line());
      return std::move(result_);
    }

    rs_ = std::make_unique<RuleSet>();
    rs_->version = version_;
    rs_->source_path = std::string(source_path_);
    rs_->source_sha256 = Sha256::hash_hex(text_);
    rs_->loaded_at_unix_ns = real_now_unix_s() * 1'000'000'000ull;
    rs_->default_action = default_deny_action();

    const Node& root = parsed.root;
    check_unknown_keys(root, {"version", "dnns", "plans", "redirects", "roaming_partners",
                              "imei_blocklist", "default_action", "rules"});

    load_dnns(root.find("dnns"));
    load_redirects(root.find("redirects"));
    load_plans(root.find("plans"));
    load_roaming_partners(root.find("roaming_partners"));
    load_imei_blocklist(root.find("imei_blocklist"));
    if (const Node* d = root.find("default_action")) {
      Action a = default_deny_action();
      parse_action(*d, a);
      rs_->default_action = a;
    }
    load_rules(root.find("rules"));

    if (result_.errors.empty()) {
      sort_and_check();
      result_.rule_set = std::move(rs_);
    }
    return std::move(result_);
  }

 private:
  void err(const std::string& msg, int line) { result_.errors.push_back({msg, line}); }
  void warn(const std::string& msg) { result_.warnings.push_back(msg); }

  static Action default_deny_action() {
    Action a{};
    a.verdict = static_cast<std::uint8_t>(Verdict::kDeny);
    a.reason = static_cast<std::uint8_t>(Reason::kPolicyDefaultDeny);
    return a;
  }

  void check_unknown_keys(const Node& n, std::initializer_list<const char*> known) {
    if (!n.is_map()) return;
    for (const auto& [k, v] : n.fields()) {
      bool found = false;
      for (const char* kn : known) {
        if (k == kn) { found = true; break; }
      }
      // Unknown keys are warnings, not errors: an operator adding a comment
      // field or a future-version key should not take the policy offline. A
      // typo'd key still surfaces loudly in the reload log and on /rules.
      if (!found) warn("unknown key '" + k + "' at line " + std::to_string(v.line()) + " (ignored)");
    }
  }

  // ------------------------------------------------------------------ tables
  void load_dnns(const Node* n) {
    if (n == nullptr || !n->is_seq()) {
      err("'dnns' must be a sequence of DNN/APN names", n ? n->line() : 0);
      return;
    }
    for (const Node& item : n->items()) {
      if (!item.is_scalar()) { err("DNN entries must be names", item.line()); continue; }
      if (rs_->dnn_names.size() >= kMaxDnns) {
        err("more than " + std::to_string(kMaxDnns) + " DNNs; the feature word has " +
                std::to_string(kMaxDnns) + " DNN bits",
            item.line());
        return;
      }
      if (std::find(rs_->dnn_names.begin(), rs_->dnn_names.end(), item.scalar()) !=
          rs_->dnn_names.end()) {
        err("duplicate DNN '" + item.scalar() + "'", item.line());
        continue;
      }
      rs_->dnn_names.push_back(item.scalar());
    }
  }

  void load_redirects(const Node* n) {
    if (n == nullptr) return;
    if (!n->is_map()) { err("'redirects' must be a mapping of name to target", n->line()); return; }
    // Index 0 is reserved for "no redirect".
    rs_->redirect_targets.emplace_back("");
    for (const auto& [name, target] : n->fields()) {
      if (rs_->redirect_targets.size() >= kMaxRedirects) {
        err("more than " + std::to_string(kMaxRedirects) + " redirect targets", target.line());
        return;
      }
      if (!target.is_scalar()) { err("redirect target must be a string", target.line()); continue; }
      redirect_ids_[name] = static_cast<std::uint8_t>(rs_->redirect_targets.size());
      rs_->redirect_targets.push_back(target.scalar());
    }
  }

  void load_plans(const Node* n) {
    if (n == nullptr || !n->is_seq() || n->items().empty()) {
      err("'plans' must be a non-empty sequence", n ? n->line() : 0);
      return;
    }
    for (const Node& item : n->items()) {
      if (!item.is_map()) { err("each plan must be a mapping", item.line()); continue; }
      check_unknown_keys(item, {"name", "qos_5qi", "arp", "ambr_ul", "ambr_dl", "quota",
                                "quota_validity", "rating_group", "tethering", "roaming"});

      const Node* name = item.find("name");
      if (name == nullptr || !name->is_scalar() || name->scalar().empty()) {
        err("plan is missing 'name'", item.line());
        continue;
      }
      if (rs_->plan_names.size() >= kMaxPlans) {
        err("more than " + std::to_string(kMaxPlans) + " plans; plan_mask is 32 bits", item.line());
        return;
      }
      if (plan_ids_.count(name->scalar()) != 0) {
        err("duplicate plan '" + name->scalar() + "'", name->line());
        continue;
      }

      PlanConfig p{};
      p.id = static_cast<std::uint32_t>(rs_->plan_names.size());
      p.qos_5qi = req_5qi(item, "qos_5qi", 9);
      p.arp = req_arp(item, "arp", 8);
      p.ambr_ul_kbps = opt_kbps(item, "ambr_ul", 0);
      p.ambr_dl_kbps = opt_kbps(item, "ambr_dl", 0);
      p.quota_bytes = opt_bytes(item, "quota", 0);
      p.quota_validity_s = opt_seconds(item, "quota_validity", 0);
      p.rating_group = static_cast<std::uint32_t>(opt_uint(item, "rating_group", 0));
      if (opt_bool(item, "tethering", false)) p.flags |= kPlanTetheringAllowed;
      if (opt_bool(item, "roaming", false)) p.flags |= kPlanRoamingAllowed;

      if (p.quota_bytes != 0 && p.quota_validity_s == 0) {
        warn("plan '" + name->scalar() +
             "' grants a quota with no validity time; grants will never expire");
      }

      plan_ids_[name->scalar()] = p.id;
      rs_->plans[p.id] = p;
      rs_->plan_names.push_back(name->scalar());
      rs_->plan_count = static_cast<std::uint32_t>(rs_->plan_names.size());
    }
  }

  void load_roaming_partners(const Node* n) {
    if (n == nullptr) return;
    if (!n->is_seq()) { err("'roaming_partners' must be a sequence of PLMNs", n->line()); return; }
    std::vector<std::uint64_t> keys;
    for (const Node& item : n->items()) {
      if (!item.is_scalar()) { err("PLMN must be a scalar like 310-260", item.line()); continue; }
      const auto plmn = parse_plmn(item.scalar());
      if (!plmn) { err("invalid PLMN '" + item.scalar() + "'", item.line()); continue; }
      keys.push_back(*plmn);
    }
    rs_->roaming_partners.rebuild(keys);
  }

  void load_imei_blocklist(const Node* n) {
    if (n == nullptr) return;
    std::vector<std::uint64_t> keys;
    if (n->is_scalar()) {
      // A path: production blocklists are millions of entries and do not belong
      // inline in the policy file.
      load_imei_file(n->scalar(), n->line(), keys);
    } else if (n->is_seq()) {
      for (const Node& item : n->items()) {
        if (!item.is_scalar()) { err("IMEI must be a scalar", item.line()); continue; }
        const auto imei = parse_imei(item.scalar());
        if (!imei || *imei == 0) { err("invalid IMEI '" + item.scalar() + "'", item.line()); continue; }
        keys.push_back(*imei);
      }
    } else {
      err("'imei_blocklist' must be a sequence or a file path", n->line());
      return;
    }
    rs_->imei_blocklist.rebuild(keys);
  }

  void load_imei_file(const std::string& path, int line, std::vector<std::uint64_t>& keys) {
    std::ifstream in(path);
    if (!in) { err("cannot open IMEI blocklist file '" + path + "'", line); return; }
    std::string l;
    std::size_t bad = 0;
    while (std::getline(in, l)) {
      while (!l.empty() && (l.back() == '\r' || l.back() == ' ')) l.pop_back();
      if (l.empty() || l[0] == '#') continue;
      const auto imei = parse_imei(l);
      if (!imei || *imei == 0) { ++bad; continue; }
      keys.push_back(*imei);
    }
    if (bad != 0) warn(std::to_string(bad) + " malformed line(s) in IMEI blocklist '" + path + "'");
  }

  // ------------------------------------------------------------------ rules
  void load_rules(const Node* n) {
    if (n == nullptr || !n->is_seq()) { err("'rules' must be a sequence", n ? n->line() : 0); return; }

    for (const Node& item : n->items()) {
      if (!item.is_map()) { err("each rule must be a mapping", item.line()); continue; }
      check_unknown_keys(item, {"id", "name", "priority", "plans", "when", "action"});

      const auto id = item.find("id") ? item.find("id")->as_uint() : std::nullopt;
      if (!id || *id == 0 || *id > 0xFFFFFFFFull) {
        err("rule needs a non-zero integer 'id' (0 is reserved for 'no rule fired')", item.line());
        continue;
      }
      const auto rid = static_cast<std::uint32_t>(*id);
      if (!seen_rule_ids_.insert(rid).second) {
        err("duplicate rule id " + std::to_string(rid), item.line());
        continue;
      }

      const auto prio = item.find("priority") ? item.find("priority")->as_uint() : std::nullopt;
      if (!prio || *prio > 0xFFFFFFFFull) {
        err("rule " + std::to_string(rid) + " needs an integer 'priority'", item.line());
        continue;
      }

      std::uint32_t plan_mask = 0;
      if (const Node* plans = item.find("plans")) {
        if (!resolve_plan_mask(*plans, plan_mask)) continue;
      }

      // The condition expands to one or more (mask, value) pairs.
      std::vector<std::pair<std::uint64_t, std::uint64_t>> matches{{0, 0}};
      if (const Node* when = item.find("when")) {
        if (!compile_when(*when, rid, matches)) continue;
      }

      Action action{};
      action.verdict = static_cast<std::uint8_t>(Verdict::kAllow);
      action.reason = static_cast<std::uint8_t>(Reason::kOk);
      action.inherit_mask = kInheritAll;
      const Node* act = item.find("action");
      if (act == nullptr) {
        err("rule " + std::to_string(rid) + " has no 'action'", item.line());
        continue;
      }
      if (!parse_action(*act, action)) continue;

      if (rs_->rules.size() + matches.size() > kMaxRules) {
        err("rule table exceeds " + std::to_string(kMaxRules) + " compiled rules", item.line());
        return;
      }
      for (const auto& [mask, value] : matches) {
        CompiledRule cr{};
        cr.match_mask = mask;
        cr.match_value = value;
        cr.plan_mask = plan_mask;
        cr.id = rid;
        cr.priority = static_cast<std::uint32_t>(*prio);
        cr.action = action;
        rs_->rules.push_back(cr);
      }
    }
  }

  bool resolve_plan_mask(const Node& n, std::uint32_t& out) {
    auto add = [&](const Node& item) {
      if (!item.is_scalar()) { err("plan reference must be a name", item.line()); return false; }
      const auto it = plan_ids_.find(item.scalar());
      if (it == plan_ids_.end()) {
        err("rule references unknown plan '" + item.scalar() + "'", item.line());
        return false;
      }
      out |= std::uint32_t{1} << it->second;
      return true;
    };
    if (n.is_scalar()) return add(n);
    if (!n.is_seq()) { err("'plans' must be a name or a list of names", n.line()); return false; }
    bool ok = true;
    for (const Node& item : n.items()) ok = add(item) && ok;
    return ok;
  }

  // Add a plain boolean condition: bit must be set (or clear).
  static void add_bit(std::vector<std::pair<std::uint64_t, std::uint64_t>>& ms, int bit, bool want) {
    for (auto& [mask, value] : ms) {
      mask |= feat::bit(bit);
      if (want) value |= feat::bit(bit);
    }
  }

  // Add a one-hot alternative: each listed bit produces its own compiled rule,
  // because (mask, value) cannot express OR.
  bool add_one_of(std::vector<std::pair<std::uint64_t, std::uint64_t>>& ms,
                  const std::vector<int>& bits, std::uint32_t rid, int line) {
    if (bits.empty()) return true;
    if (ms.size() * bits.size() > kMaxExpansionPerRule) {
      err("rule " + std::to_string(rid) + " expands to more than " +
              std::to_string(kMaxExpansionPerRule) + " compiled rules; split it",
          line);
      return false;
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t>> out;
    out.reserve(ms.size() * bits.size());
    for (const auto& [mask, value] : ms) {
      for (const int b : bits) {
        out.emplace_back(mask | feat::bit(b), value | feat::bit(b));
      }
    }
    ms.swap(out);
    return true;
  }

  // Negated one-hot: every listed bit must be clear. That IS expressible in one
  // pair, so no expansion.
  static void add_none_of(std::vector<std::pair<std::uint64_t, std::uint64_t>>& ms,
                          const std::vector<int>& bits) {
    for (auto& [mask, value] : ms) {
      for (const int b : bits) mask |= feat::bit(b);
      (void)value;
    }
  }

  // Collect the scalars of a scalar-or-list node.
  static std::vector<const Node*> as_list(const Node& n) {
    std::vector<const Node*> out;
    if (n.is_seq()) {
      for (const Node& i : n.items()) out.push_back(&i);
    } else {
      out.push_back(&n);
    }
    return out;
  }

  bool compile_when(const Node& when, std::uint32_t rid,
                    std::vector<std::pair<std::uint64_t, std::uint64_t>>& ms) {
    if (!when.is_map()) { err("'when' must be a mapping", when.line()); return false; }

    static constexpr struct { const char* key; int bit; } kBoolConds[] = {
        {"roaming", feat::kRoaming},
        {"home_plmn", feat::kHomePlmn},
        {"roaming_partner", feat::kRoamingPartner},
        {"roaming_allowed", feat::kRoamingAllowed},
        {"imei_known", feat::kImeiKnown},
        {"imei_blocked", feat::kImeiBlocked},
        {"tethering_detected", feat::kTetheringDetected},
        {"tethering_allowed", feat::kTetheringAllowed},
        {"emergency", feat::kEmergency},
        {"quota_exhausted", feat::kQuotaExhausted},
        {"period_expired", feat::kPeriodExpired},
        {"requested_gbr", feat::kRequestedGbr},
    };

    for (const auto& [key, node] : when.fields()) {
      bool handled = false;
      for (const auto& bc : kBoolConds) {
        if (key != bc.key) continue;
        const auto b = node.as_bool();
        if (!b) { err("condition '" + key + "' must be true or false", node.line()); return false; }
        add_bit(ms, bc.bit, *b);
        handled = true;
        break;
      }
      if (handled) continue;

      if (key == "status") {
        std::vector<int> bits;
        for (const Node* v : as_list(node)) {
          if (!v->is_scalar()) { err("'status' must be a name", v->line()); return false; }
          const std::string u = to_upper(v->scalar());
          if (u == "ACTIVE") bits.push_back(feat::kStatusActive);
          else if (u == "SUSPENDED") bits.push_back(feat::kStatusSuspended);
          else if (u == "BARRED") bits.push_back(feat::kStatusBarred);
          else if (u == "UNKNOWN") bits.push_back(feat::kStatusUnknown);
          else { err("unknown status '" + v->scalar() + "'", v->line()); return false; }
        }
        if (!add_one_of(ms, bits, rid, node.line())) return false;

      } else if (key == "rat" || key == "not_rat") {
        std::vector<int> bits;
        for (const Node* v : as_list(node)) {
          const auto rat = v->is_scalar() ? parse_rat(v->scalar()) : std::nullopt;
          if (!rat) { err("unknown access type '" + v->scalar() + "'", v->line()); return false; }
          bits.push_back(feat::kRatBase + static_cast<int>(*rat));
        }
        if (key == "rat") {
          if (!add_one_of(ms, bits, rid, node.line())) return false;
        } else {
          add_none_of(ms, bits);
        }

      } else if (key == "dnn" || key == "not_dnn") {
        std::vector<int> bits;
        for (const Node* v : as_list(node)) {
          if (!v->is_scalar()) { err("'dnn' must be a name", v->line()); return false; }
          const auto it = std::find(rs_->dnn_names.begin(), rs_->dnn_names.end(), v->scalar());
          if (it == rs_->dnn_names.end()) {
            err("unknown DNN '" + v->scalar() + "' (add it to the 'dnns' list)", v->line());
            return false;
          }
          bits.push_back(feat::kDnnBase +
                         static_cast<int>(std::distance(rs_->dnn_names.begin(), it)));
        }
        if (key == "dnn") {
          if (!add_one_of(ms, bits, rid, node.line())) return false;
        } else {
          add_none_of(ms, bits);
        }

      } else if (key == "usage_above" || key == "usage_below") {
        const auto pm = node.as_permille();
        if (!pm) { err("'" + key + "' must be a percentage like 80%", node.line()); return false; }
        const auto bit = intern_usage_threshold(*pm, node.line());
        if (bit < 0) return false;
        add_bit(ms, bit, key == "usage_above");

      } else if (key == "time_between" || key == "not_time_between") {
        const Node* start = node.find("start");
        const Node* end = node.find("end");
        if (!node.is_map() || start == nullptr || end == nullptr) {
          err("'" + key + "' needs {start: HH:MM, end: HH:MM}", node.line());
          return false;
        }
        const auto s = start->as_time_of_day();
        const auto e = end->as_time_of_day();
        if (!s || !e) { err("times must be HH:MM in 24-hour form", node.line()); return false; }
        const auto bit = intern_time_window(*s, *e, node.line());
        if (bit < 0) return false;
        add_bit(ms, bit, key == "time_between");

      } else {
        err("unknown condition '" + key + "'", node.line());
        return false;
      }
    }
    return true;
  }

  // Compiler-assigned predicate bits: distinct thresholds and windows are
  // interned so N rules mentioning "80%" share one bit and one comparison.
  int intern_usage_threshold(std::uint32_t permille, int line) {
    for (std::uint32_t i = 0; i < rs_->usage_threshold_count; ++i) {
      if (rs_->usage_thresholds_permille[i] == permille) {
        return feat::kUsageThresholdBase + static_cast<int>(i);
      }
    }
    if (rs_->usage_threshold_count >= kMaxUsageThresholds) {
      err("more than " + std::to_string(kMaxUsageThresholds) +
              " distinct usage thresholds; the feature word has no room",
          line);
      return -1;
    }
    const auto i = rs_->usage_threshold_count++;
    rs_->usage_thresholds_permille[i] = permille;
    return feat::kUsageThresholdBase + static_cast<int>(i);
  }

  int intern_time_window(std::uint16_t start, std::uint16_t end, int line) {
    for (std::uint32_t i = 0; i < rs_->time_window_count; ++i) {
      if (rs_->time_windows[i].start_minute == start && rs_->time_windows[i].end_minute == end) {
        return feat::kTimeWindowBase + static_cast<int>(i);
      }
    }
    if (rs_->time_window_count >= kMaxTimeWindows) {
      err("more than " + std::to_string(kMaxTimeWindows) + " distinct time windows", line);
      return -1;
    }
    const auto i = rs_->time_window_count++;
    rs_->time_windows[i] = TimeWindow{start, end};
    return feat::kTimeWindowBase + static_cast<int>(i);
  }

  // ----------------------------------------------------------------- action
  bool parse_action(const Node& n, Action& a) {
    if (!n.is_map()) { err("'action' must be a mapping", n.line()); return false; }
    check_unknown_keys(n, {"verdict", "reason", "qos_5qi", "arp", "ambr_ul", "ambr_dl",
                           "rating_group", "quota", "quota_validity", "redirect", "flags",
                           "inherit"});

    if (const Node* v = n.find("verdict")) {
      const auto verdict = v->is_scalar() ? parse_verdict(v->scalar()) : std::nullopt;
      if (!verdict) { err("unknown verdict '" + v->scalar() + "'", v->line()); return false; }
      a.verdict = static_cast<std::uint8_t>(*verdict);
    }
    if (const Node* r = n.find("reason")) {
      const auto reason = r->is_scalar() ? parse_reason(r->scalar()) : std::nullopt;
      if (!reason) { err("unknown reason code '" + r->scalar() + "'", r->line()); return false; }
      a.reason = static_cast<std::uint8_t>(*reason);
    }

    // 'inherit' is explicit: listing a field here means the plan supplies it.
    // Any field the action sets directly is removed from the inherit mask, so
    // "set ambr, inherit the rest" needs no ceremony.
    if (const Node* inh = n.find("inherit")) {
      std::uint8_t mask = 0;
      for (const Node* v : as_list(*inh)) {
        const auto bit = v->is_scalar() ? parse_inherit(v->scalar()) : std::nullopt;
        if (!bit) { err("unknown inherit field '" + v->scalar() + "'", v->line()); return false; }
        mask |= *bit;
      }
      a.inherit_mask = mask;
    }

    if (const Node* q = n.find("qos_5qi")) {
      const auto v = q->as_uint();
      if (!v || *v == 0 || *v > 255) { err("qos_5qi must be 1..255", q->line()); return false; }
      a.qos_5qi = static_cast<std::uint8_t>(*v);
      if (!is_standardized_5qi(a.qos_5qi) && a.qos_5qi < 128) {
        warn("5QI " + std::to_string(a.qos_5qi) +
             " is not a standardized value and is below the operator-specific range (128-254)");
      }
      a.inherit_mask = static_cast<std::uint8_t>(a.inherit_mask & ~kInheritQos);
    }
    if (const Node* q = n.find("arp")) {
      const auto v = q->as_uint();
      if (!v || *v < 1 || *v > 15) { err("arp must be 1..15", q->line()); return false; }
      a.arp = static_cast<std::uint8_t>(*v);
      a.inherit_mask = static_cast<std::uint8_t>(a.inherit_mask & ~kInheritQos);
    }
    // ARP without 5QI (or vice versa) would otherwise silently drop the other
    // half, since they share one inherit bit.
    if (n.has("qos_5qi") != n.has("arp") && (n.has("qos_5qi") || n.has("arp"))) {
      if (!n.has("arp")) a.arp = 8;
      if (!n.has("qos_5qi")) a.qos_5qi = 9;
      warn("action at line " + std::to_string(n.line()) +
           " sets only one of qos_5qi/arp; the other defaults rather than inheriting");
    }

    bool set_ul = false, set_dl = false;
    if (const Node* q = n.find("ambr_ul")) {
      const auto v = q->as_kbps();
      if (!v) { err("ambr_ul must be a bit rate like 10Mbps", q->line()); return false; }
      a.ambr_ul_kbps = *v;
      set_ul = true;
    }
    if (const Node* q = n.find("ambr_dl")) {
      const auto v = q->as_kbps();
      if (!v) { err("ambr_dl must be a bit rate like 50Mbps", q->line()); return false; }
      a.ambr_dl_kbps = *v;
      set_dl = true;
    }
    if (set_ul || set_dl) {
      if (set_ul != set_dl) {
        err("an action must set both ambr_ul and ambr_dl, or neither", n.line());
        return false;
      }
      a.inherit_mask = static_cast<std::uint8_t>(a.inherit_mask & ~kInheritAmbr);
    }

    if (const Node* q = n.find("quota")) {
      const auto v = q->as_bytes();
      if (!v) { err("quota must be a byte size like 20GB", q->line()); return false; }
      a.quota_bytes = *v;
      a.inherit_mask = static_cast<std::uint8_t>(a.inherit_mask & ~kInheritQuota);
    }
    if (const Node* q = n.find("quota_validity")) {
      const auto v = q->as_seconds();
      if (!v) { err("quota_validity must be a duration like 30d", q->line()); return false; }
      a.quota_validity_s = *v;
      a.inherit_mask = static_cast<std::uint8_t>(a.inherit_mask & ~kInheritQuota);
    }
    if (const Node* q = n.find("rating_group")) {
      const auto v = q->as_uint();
      if (!v || *v > 0xFFFFFFFFull) { err("rating_group must be an integer", q->line()); return false; }
      a.rating_group = static_cast<std::uint32_t>(*v);
      a.inherit_mask = static_cast<std::uint8_t>(a.inherit_mask & ~kInheritRatingGroup);
    }

    if (const Node* q = n.find("redirect")) {
      if (!q->is_scalar()) { err("redirect must name a target from 'redirects'", q->line()); return false; }
      const auto it = redirect_ids_.find(q->scalar());
      if (it == redirect_ids_.end()) {
        err("unknown redirect target '" + q->scalar() + "'", q->line());
        return false;
      }
      a.redirect_id = it->second;
    }
    if (a.verdict == static_cast<std::uint8_t>(Verdict::kRedirect) && a.redirect_id == 0) {
      err("a REDIRECT action must name a redirect target", n.line());
      return false;
    }

    if (const Node* q = n.find("flags")) {
      for (const Node* v : as_list(*q)) {
        const auto f = v->is_scalar() ? parse_decision_flag(v->scalar()) : std::nullopt;
        if (!f) { err("unknown decision flag '" + v->scalar() + "'", v->line()); return false; }
        a.set_flags = static_cast<std::uint8_t>(a.set_flags | *f);
      }
    }
    return true;
  }

  // ---------------------------------------------------------------- helpers
  std::uint8_t req_5qi(const Node& n, const char* key, std::uint8_t dflt) {
    const Node* v = n.find(key);
    if (v == nullptr) return dflt;
    const auto u = v->as_uint();
    if (!u || *u == 0 || *u > 255) { err(std::string(key) + " must be 1..255", v->line()); return dflt; }
    const auto q = static_cast<std::uint8_t>(*u);
    if (!is_standardized_5qi(q) && q < 128) {
      warn("5QI " + std::to_string(q) + " is not a standardized value");
    }
    return q;
  }

  std::uint8_t req_arp(const Node& n, const char* key, std::uint8_t dflt) {
    const Node* v = n.find(key);
    if (v == nullptr) return dflt;
    const auto u = v->as_uint();
    if (!u || *u < 1 || *u > 15) { err(std::string(key) + " must be 1..15", v->line()); return dflt; }
    return static_cast<std::uint8_t>(*u);
  }

  std::uint32_t opt_kbps(const Node& n, const char* key, std::uint32_t dflt) {
    const Node* v = n.find(key);
    if (v == nullptr) return dflt;
    const auto u = v->as_kbps();
    if (!u) { err(std::string(key) + " must be a bit rate like 50Mbps", v->line()); return dflt; }
    return *u;
  }

  std::uint64_t opt_bytes(const Node& n, const char* key, std::uint64_t dflt) {
    const Node* v = n.find(key);
    if (v == nullptr) return dflt;
    const auto u = v->as_bytes();
    if (!u) { err(std::string(key) + " must be a byte size like 20GB", v->line()); return dflt; }
    return *u;
  }

  std::uint32_t opt_seconds(const Node& n, const char* key, std::uint32_t dflt) {
    const Node* v = n.find(key);
    if (v == nullptr) return dflt;
    const auto u = v->as_seconds();
    if (!u) { err(std::string(key) + " must be a duration like 30d", v->line()); return dflt; }
    return *u;
  }

  std::uint64_t opt_uint(const Node& n, const char* key, std::uint64_t dflt) {
    const Node* v = n.find(key);
    if (v == nullptr) return dflt;
    const auto u = v->as_uint();
    if (!u) { err(std::string(key) + " must be a non-negative integer", v->line()); return dflt; }
    return *u;
  }

  bool opt_bool(const Node& n, const char* key, bool dflt) {
    const Node* v = n.find(key);
    if (v == nullptr) return dflt;
    const auto u = v->as_bool();
    if (!u) { err(std::string(key) + " must be true or false", v->line()); return dflt; }
    return *u;
  }

  // ------------------------------------------------------- ordering + lint
  void sort_and_check() {
    // Stable sort on priority so rules of equal priority keep file order — an
    // operator reading the file top to bottom sees the evaluation order.
    std::stable_sort(rs_->rules.begin(), rs_->rules.end(),
                     [](const CompiledRule& a, const CompiledRule& b) {
                       return a.priority < b.priority;
                     });

    // Shadow detection: rule B can never fire if some earlier rule A tests a
    // subset of B's bits with the same values and covers B's plans. This is the
    // single most common policy authoring bug, and it is silent at runtime.
    for (std::size_t i = 0; i < rs_->rules.size(); ++i) {
      const CompiledRule& b = rs_->rules[i];
      for (std::size_t j = 0; j < i; ++j) {
        const CompiledRule& a = rs_->rules[j];
        if (a.id == b.id) continue;  // same source rule, different expansion
        if ((b.match_mask & a.match_mask) != a.match_mask) continue;
        if ((b.match_value & a.match_mask) != a.match_value) continue;
        if (a.plan_mask != 0 && (b.plan_mask == 0 || (b.plan_mask & ~a.plan_mask) != 0)) continue;
        warn("rule " + std::to_string(b.id) + " (priority " + std::to_string(b.priority) +
             ") can never fire: rule " + std::to_string(a.id) + " (priority " +
             std::to_string(a.priority) + ") always matches first");
        break;
      }
    }

    if (rs_->rules.empty()) warn("rule set contains no rules; every request takes the default action");
  }

  std::string_view text_;
  std::string_view source_path_;
  std::uint32_t version_;
  std::unique_ptr<RuleSet> rs_;
  RuleCompileResult result_;
  std::map<std::string, std::uint32_t> plan_ids_;
  std::map<std::string, std::uint8_t> redirect_ids_;
  std::set<std::uint32_t> seen_rule_ids_;
};

}  // namespace

std::string RuleCompileResult::error_summary() const {
  std::ostringstream os;
  for (std::size_t i = 0; i < errors.size(); ++i) {
    if (i != 0) os << "; ";
    if (errors[i].line > 0) os << "line " << errors[i].line << ": ";
    os << errors[i].message;
  }
  return os.str();
}

RuleCompileResult compile_rules(std::string_view yaml_text, std::string_view source_path,
                                std::uint32_t version) {
  Compiler c(yaml_text, source_path, version);
  return c.run();
}

RuleCompileResult compile_rules_from_file(const std::string& path, std::uint32_t version) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    RuleCompileResult r;
    r.errors.push_back({"cannot open rules file: " + path, 0});
    return r;
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  const std::string text = ss.str();
  return compile_rules(text, path, version);
}

}  // namespace policy
