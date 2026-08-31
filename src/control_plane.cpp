#include "policy/control_plane.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <cinttypes>
#include <cstdlib>
#include <cstdio>
#include <sstream>

#include "policy/affinity.hpp"
#include "policy/build_config.hpp"
#include "policy/cycles.hpp"
#include "policy/engine.hpp"
#include "policy/imsi.hpp"
#include "policy/logging.hpp"

namespace policy {
namespace {

std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (const char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

std::uint64_t now_us() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())
          .count());
}

}  // namespace

ControlPlane::ControlPlane(const ServerConfig& cfg)
    : cfg_(cfg),
      // One RCU reader slot per worker, plus a few for the control plane's own
      // read-side use (/explain, /rules) which holds real guards.
      rules_(cfg.worker_threads + 4),
      store_(cfg.expected_subscribers != 0 ? cfg.expected_subscribers : 1024),
      metrics_(cfg.worker_threads),
      clock_ticker_(std::chrono::milliseconds(100)) {
  started_unix_s_ = real_now_unix_s();
}

ControlPlane::~ControlPlane() { stop(); }

bool ControlPlane::initialize(std::string& error) {
  const auto t0 = now_us();
  auto compiled = compile_rules_from_file(cfg_.rules_path, next_version_.fetch_add(1));
  for (const auto& w : compiled.warnings) LOG_WARN("rules: %s", w.c_str());
  if (!compiled.ok()) {
    error = "cannot compile " + cfg_.rules_path + ": " + compiled.error_summary();
    return false;
  }
  reload_stats_.compile_us = now_us() - t0;

  const std::vector<std::string> plan_names = compiled.rule_set->plan_names;
  const std::uint32_t version = compiled.rule_set->version;
  const std::size_t rule_count = compiled.rule_set->rules.size();

  rules_.publish(std::move(compiled.rule_set));
  reload_stats_.attempts = 1;
  reload_stats_.successes = 1;
  reload_stats_.current_version = version;
  reload_stats_.last_success_unix_s = real_now_unix_s();
  last_seen_mtime_ = rules_file_mtime();

  LOG_INFO("compiled %zu rules from %s in %" PRIu64 " us (policy version %u)", rule_count,
           cfg_.rules_path.c_str(), reload_stats_.compile_us, version);

  if (!cfg_.subscribers_path.empty()) {
    const auto s0 = now_us();
    const auto res = store_.load_csv(cfg_.subscribers_path, plan_names);
    for (const auto& e : res.errors) LOG_ERROR("subscribers: %s", e.c_str());
    if (!res.ok()) {
      // A roster with bad rows is a provisioning bug, and starting anyway would
      // silently deny service to exactly the subscribers whose rows are wrong.
      error = "subscriber file has " + std::to_string(res.skipped) + " bad row(s)";
      return false;
    }
    const auto st = store_.stats();
    LOG_INFO("loaded %zu subscribers from %s in %" PRIu64 " ms — %zu slots, %.1f MB, "
             "load factor %.2f, mean probe %.2f, max probe %zu",
             res.loaded, cfg_.subscribers_path.c_str(), (now_us() - s0) / 1000, st.capacity,
             static_cast<double>(st.memory_bytes) / (1024.0 * 1024.0), st.load_factor,
             st.mean_probe_length, st.max_probe_length);
  }

  return true;
}

bool ControlPlane::start(std::string& error) {
  if (cfg_.admin_port != 0) {
    http_ = std::make_unique<AdminHttpServer>(cfg_.admin_bind_address, cfg_.admin_port);
    register_routes(*http_, ingest_description_);  // keeps whatever start-up set
    if (!http_->start(error)) return false;
    LOG_INFO("admin HTTP on http://%s:%u", cfg_.admin_bind_address.c_str(), http_->bound_port());
  }
  if (cfg_.watch_rules_file) {
    watcher_ = std::thread([this] { watch_loop(); });
  }
  return true;
}

void ControlPlane::stop() {
  stop_.store(true, std::memory_order_release);
  if (watcher_.joinable()) watcher_.join();
  if (http_) {
    http_->stop();
    http_.reset();
  }
}

std::uint16_t ControlPlane::admin_port() const { return http_ ? http_->bound_port() : 0; }

std::uint64_t ControlPlane::rules_file_mtime() const {
  struct stat st {};
  if (::stat(cfg_.rules_path.c_str(), &st) != 0) return 0;
#if defined(__APPLE__)
  return static_cast<std::uint64_t>(st.st_mtimespec.tv_sec) * 1'000'000'000ull +
         static_cast<std::uint64_t>(st.st_mtimespec.tv_nsec);
#else
  return static_cast<std::uint64_t>(st.st_mtim.tv_sec) * 1'000'000'000ull +
         static_cast<std::uint64_t>(st.st_mtim.tv_nsec);
#endif
}

void ControlPlane::watch_loop() {
  name_current_thread("policy-watch");
  if (cfg_.control_plane_core >= 0) {
    std::string detail;
    pin_current_thread(static_cast<unsigned>(cfg_.control_plane_core), detail);
  }

  // Polling mtime rather than inotify/kqueue: it is 30 lines instead of two
  // platform-specific implementations, the latency of noticing an edit is
  // irrelevant (nobody edits policy in a tight loop), and it is immune to the
  // editor-rename problem that makes naive inotify watches stop working after
  // the first save.
  while (!stop_.load(std::memory_order_acquire)) {
    for (std::uint32_t slept = 0;
         slept < cfg_.reload_poll_ms && !stop_.load(std::memory_order_acquire); slept += 50) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (stop_.load(std::memory_order_acquire)) break;

    const std::uint64_t mtime = rules_file_mtime();
    if (mtime == 0 || mtime == last_seen_mtime_) continue;

    LOG_INFO("rules file changed, reloading");
    std::string error;
    if (!reload_rules(error)) {
      LOG_ERROR("reload failed, keeping policy version %u: %s", reload_stats_.current_version,
                error.c_str());
    }
    // Update the watermark even on failure, so a broken file is reported once
    // rather than every poll interval.
    last_seen_mtime_ = mtime;
  }
}

bool ControlPlane::reload_rules(std::string& error) {
  const std::lock_guard<std::mutex> lock(reload_mutex_);
  ++reload_stats_.attempts;

  const auto t0 = now_us();
  auto compiled = compile_rules_from_file(cfg_.rules_path, next_version_.fetch_add(1));
  const auto compile_us = now_us() - t0;

  for (const auto& w : compiled.warnings) LOG_WARN("rules: %s", w.c_str());
  if (!compiled.ok()) {
    error = compiled.error_summary();
    ++reload_stats_.failures;
    reload_stats_.last_error = error;
    return false;
  }

  // Loading subscribers is not part of a rules reload, but a rules file that
  // renames or removes a plan would leave existing records pointing at a plan
  // id that no longer means what it did. Refuse rather than silently reassign.
  {
    const auto guard = rules_.read(rules_.max_readers() - 1);
    if (guard.get() != nullptr) {
      const auto& old_names = guard->plan_names;
      const auto& new_names = compiled.rule_set->plan_names;
      for (std::size_t i = 0; i < old_names.size(); ++i) {
        if (i >= new_names.size() || new_names[i] != old_names[i]) {
          error = "plan '" + old_names[i] + "' changed position or was removed (slot " +
                  std::to_string(i) +
                  "); subscriber records hold plan ids, so this needs a restart, not a reload";
          ++reload_stats_.failures;
          reload_stats_.last_error = error;
          return false;
        }
      }
    }
  }

  const std::uint32_t version = compiled.rule_set->version;
  const std::size_t rule_count = compiled.rule_set->rules.size();
  const std::string sha = compiled.rule_set->source_sha256;

  const auto g0 = now_us();
  const bool quiesced = rules_.swap_and_reclaim(std::move(compiled.rule_set),
                                                std::chrono::milliseconds(500));
  const auto grace_us = now_us() - g0;

  reload_stats_.compile_us = compile_us;
  reload_stats_.grace_period_us = grace_us;
  reload_stats_.current_version = version;
  reload_stats_.last_success_unix_s = real_now_unix_s();
  ++reload_stats_.successes;
  reload_stats_.last_error.clear();

  if (!quiesced) {
    // The new rules are live either way — the pointer swap already happened.
    // Only reclamation of the old snapshot was deferred.
    LOG_WARN("RCU grace period timed out; retired %zu snapshot(s) deferred to the next reload",
             rules_.deferred_retire_count());
  }

  LOG_INFO("policy version %u live: %zu rules, sha256 %.12s, compile %" PRIu64
           " us, grace %" PRIu64 " us",
           version, rule_count, sha.c_str(), compile_us, grace_us);
  return true;
}

std::string ControlPlane::describe(const std::string& ingest) const {
  const auto guard = const_cast<RcuDomain<RuleSet>&>(rules_).read(rules_.max_readers() - 2);
  const auto st = store_.stats();
  std::ostringstream os;
  os << "policyd " POLICY_VERSION_STRING " (" POLICY_BUILD_TYPE ", " POLICY_COMPILER_ID
        " " POLICY_COMPILER_VER ")\n"
     << "  host          : " POLICY_SYSTEM_NAME "/" POLICY_SYSTEM_PROC ", "
     << hardware_thread_count() << " hardware threads\n"
     << "  ingest        : " << ingest << "\n"
     << "  workers       : " << cfg_.worker_threads << ", batch cap " << cfg_.batch_size
     << ", busy-poll " << cfg_.busy_poll_us << " us\n"
     << "  pinning       : " << (cfg_.pin_workers ? "requested" : "disabled") << " — "
     << affinity_support_description() << "\n"
     << "  cycle counter : " << cycle_counter_name() << " @ "
     << static_cast<std::uint64_t>(cycles_per_second() / 1e6) << " MHz, "
     << cycle_read_overhead_ns() << " ns per read (service times include two)\n"
     << "  listening     : " << cfg_.bind_address << ":" << cfg_.port << " (UDP)\n";
  if (guard.get() != nullptr) {
    os << "  policy        : version " << guard->version << ", " << guard->rules.size()
       << " rules (" << guard->rule_bytes() << " B), " << guard->plan_count << " plans, "
       << guard->dnn_names.size() << " DNNs, sha256 " << guard->source_sha256.substr(0, 12) << "\n";
  }
  os << "  subscribers   : " << st.size << " in " << st.capacity << " slots, "
     << (st.memory_bytes / (1024 * 1024)) << " MB, load factor " << st.load_factor
     << ", mean probe " << st.mean_probe_length << "\n";
  return os.str();
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------

void ControlPlane::register_routes(AdminHttpServer& http, const std::string& ingest) {
  ingest_description_ = ingest;

  http.route("GET", "/healthz", [this](const HttpRequest&) {
    const auto guard = rules_.read(rules_.max_readers() - 3);
    if (guard.get() == nullptr) return HttpResponse::error(503, "no policy loaded");
    return HttpResponse::text("ok\n");
  });

  http.route("GET", "/metrics", [this](const HttpRequest& r) { return handle_metrics(r); });
  http.route("GET", "/stats", [this](const HttpRequest& r) { return handle_stats(r); });
  http.route("GET", "/rules", [this](const HttpRequest& r) { return handle_rules(r); });
  http.route("POST", "/rules/reload", [this](const HttpRequest& r) { return handle_reload(r); });
  http.route("GET", "/explain", [this](const HttpRequest& r) { return handle_explain(r); });
  http.route_prefix("GET", "/subscriber/",
                    [this](const HttpRequest& r) { return handle_subscriber(r); });
}

HttpResponse ControlPlane::handle_metrics(const HttpRequest&) const {
  const auto snap = metrics_.snapshot();
  const auto guard = const_cast<RcuDomain<RuleSet>&>(rules_).read(rules_.max_readers() - 3);
  const auto st = store_.stats();

  std::ostringstream os;
  auto counter = [&](const char* name, const char* help, auto value) {
    os << "# HELP " << name << " " << help << "\n# TYPE " << name << " counter\n"
       << name << " " << value << "\n";
  };
  auto gauge = [&](const char* name, const char* help, auto value) {
    os << "# HELP " << name << " " << help << "\n# TYPE " << name << " gauge\n"
       << name << " " << value << "\n";
  };

  counter("policy_requests_total", "Requests decoded and evaluated.", snap.requests);
  counter("policy_replies_sent_total", "Decisions written to the socket.", snap.replies_sent);
  counter("policy_short_datagrams_total", "Datagrams of the wrong size, dropped without a reply.",
          snap.short_datagrams);
  counter("policy_bad_magic_total", "Correctly sized datagrams with an unknown magic/version.",
          snap.bad_magic);
  counter("policy_unknown_subscriber_total", "Requests whose IMSI is not provisioned.",
          snap.unknown_subscriber);
  counter("policy_send_failures_total", "Replies the kernel would not accept.", snap.send_failures);
  counter("policy_recv_errors_total", "Receive errors.", snap.recv_errors);
  counter("policy_batches_total", "Receive batches processed.", snap.batches);
  counter("policy_full_batches_total", "Batches that hit the batch cap (the loop is saturated).",
          snap.full_batches);
  counter("policy_idle_spins_total", "Receive calls that found nothing.", snap.idle_spins);
  counter("policy_blocking_waits_total", "Times a worker parked after exhausting its poll budget.",
          snap.blocking_waits);
  gauge("policy_mean_batch_size", "Mean realized receive batch.", snap.mean_batch());

  static constexpr const char* kVerdictNames[3] = {"allow", "deny", "redirect"};
  os << "# HELP policy_verdicts_total Decisions by verdict.\n"
     << "# TYPE policy_verdicts_total counter\n";
  for (std::size_t i = 0; i < 3; ++i) {
    os << "policy_verdicts_total{verdict=\"" << kVerdictNames[i] << "\"} " << snap.verdicts[i]
       << "\n";
  }

  os << "# HELP policy_reasons_total Decisions by reason code.\n"
     << "# TYPE policy_reasons_total counter\n";
  for (std::size_t i = 0; i < static_cast<std::size_t>(Reason::kCount); ++i) {
    if (snap.reasons[i] == 0) continue;
    os << "policy_reasons_total{reason=\"" << reason_name(static_cast<Reason>(i)) << "\"} "
       << snap.reasons[i] << "\n";
  }

  // Service time as a Prometheus summary. These are the server's own compute
  // numbers; the headline end-to-end latency comes from the load generator,
  // which is the only place it can be measured honestly.
  os << "# HELP policy_service_time_ns Time from decode to encode, excluding syscalls.\n"
     << "# TYPE policy_service_time_ns summary\n";
  for (const double q : {0.5, 0.9, 0.99, 0.999, 0.9999}) {
    os << "policy_service_time_ns{quantile=\"" << q << "\"} "
       << snap.service_ns.value_at_percentile(q * 100.0) << "\n";
  }
  os << "policy_service_time_ns_sum " << static_cast<std::uint64_t>(
            snap.service_ns.mean() * static_cast<double>(snap.service_ns.total_count()))
     << "\npolicy_service_time_ns_count " << snap.service_ns.total_count() << "\n";

  gauge("policy_rules_version", "Live policy version.", guard.get() ? guard->version : 0);
  gauge("policy_rules_count", "Compiled rules in the live rule set.",
        guard.get() ? guard->rules.size() : 0);
  counter("policy_reloads_total", "Rule reload attempts that succeeded.", reload_stats_.successes);
  counter("policy_reload_failures_total", "Rule reload attempts that failed.",
          reload_stats_.failures);
  gauge("policy_reload_compile_us", "Duration of the last rule compile.", reload_stats_.compile_us);
  gauge("policy_reload_grace_us", "Duration of the last RCU grace period.",
        reload_stats_.grace_period_us);
  gauge("policy_subscribers", "Provisioned subscribers.", st.size);
  gauge("policy_subscriber_slots", "Slots in the subscriber table.", st.capacity);
  gauge("policy_subscriber_bytes", "Bytes resident in the subscriber table.", st.memory_bytes);
  gauge("policy_subscriber_mean_probe", "Mean probe length for a hit.", st.mean_probe_length);
  gauge("policy_uptime_seconds", "Seconds since start.", real_now_unix_s() - started_unix_s_);

  return HttpResponse::text(os.str());
}

HttpResponse ControlPlane::handle_stats(const HttpRequest&) const {
  const auto snap = metrics_.snapshot();
  const auto guard = const_cast<RcuDomain<RuleSet>&>(rules_).read(rules_.max_readers() - 3);
  const auto st = store_.stats();

  std::ostringstream os;
  os << "{\n"
     << "  \"version\": \"" POLICY_VERSION_STRING "\",\n"
     << "  \"build\": \"" POLICY_BUILD_TYPE " " POLICY_COMPILER_ID " " POLICY_COMPILER_VER "\",\n"
     << "  \"host\": \"" POLICY_SYSTEM_NAME "/" POLICY_SYSTEM_PROC "\",\n"
     << "  \"uptime_s\": " << (real_now_unix_s() - started_unix_s_) << ",\n"
     << "  \"ingest\": \"" << json_escape(ingest_description_) << "\",\n"
     << "  \"workers\": " << cfg_.worker_threads << ",\n"
     << "  \"batch_cap\": " << cfg_.batch_size << ",\n"
     << "  \"pinned\": " << (cfg_.pin_workers ? "true" : "false") << ",\n"
     << "  \"requests\": " << snap.requests << ",\n"
     << "  \"replies_sent\": " << snap.replies_sent << ",\n"
     << "  \"unknown_subscriber\": " << snap.unknown_subscriber << ",\n"
     << "  \"short_datagrams\": " << snap.short_datagrams << ",\n"
     << "  \"bad_magic\": " << snap.bad_magic << ",\n"
     << "  \"send_failures\": " << snap.send_failures << ",\n"
     << "  \"mean_batch\": " << snap.mean_batch() << ",\n"
     << "  \"service_ns\": {\"p50\": " << snap.service_ns.value_at_percentile(50)
     << ", \"p99\": " << snap.service_ns.value_at_percentile(99)
     << ", \"p99_9\": " << snap.service_ns.value_at_percentile(99.9)
     << ", \"p99_99\": " << snap.service_ns.value_at_percentile(99.99)
     << ", \"max\": " << snap.service_ns.max() << ", \"count\": " << snap.service_ns.total_count()
     << "},\n"
     << "  \"verdicts\": {\"allow\": " << snap.verdicts[0] << ", \"deny\": " << snap.verdicts[1]
     << ", \"redirect\": " << snap.verdicts[2] << "},\n"
     << "  \"reload\": {\"attempts\": " << reload_stats_.attempts
     << ", \"successes\": " << reload_stats_.successes
     << ", \"failures\": " << reload_stats_.failures
     << ", \"compile_us\": " << reload_stats_.compile_us
     << ", \"grace_us\": " << reload_stats_.grace_period_us
     << ", \"last_error\": \"" << json_escape(reload_stats_.last_error) << "\"},\n"
     << "  \"policy_version\": " << (guard.get() ? guard->version : 0) << ",\n"
     << "  \"rules\": " << (guard.get() ? guard->rules.size() : 0) << ",\n"
     << "  \"subscribers\": {\"count\": " << st.size << ", \"slots\": " << st.capacity
     << ", \"bytes\": " << st.memory_bytes << ", \"load_factor\": " << st.load_factor
     << ", \"mean_probe\": " << st.mean_probe_length << ", \"max_probe\": " << st.max_probe_length
     << "}\n"
     << "}\n";
  return HttpResponse::json(os.str());
}

HttpResponse ControlPlane::handle_rules(const HttpRequest&) const {
  const auto guard = const_cast<RcuDomain<RuleSet>&>(rules_).read(rules_.max_readers() - 3);
  if (guard.get() == nullptr) return HttpResponse::error(503, "no policy loaded");
  const RuleSet& rs = *guard;

  std::ostringstream os;
  os << "{\n  \"version\": " << rs.version << ",\n"
     << "  \"source\": \"" << json_escape(rs.source_path) << "\",\n"
     << "  \"sha256\": \"" << rs.source_sha256 << "\",\n"
     << "  \"compiled_rules\": " << rs.rules.size() << ",\n"
     << "  \"table_bytes\": " << rs.rule_bytes() << ",\n"
     << "  \"roaming_partners\": " << rs.roaming_partners.size() << ",\n"
     << "  \"imei_blocklist\": " << rs.imei_blocklist.size() << ",\n";

  os << "  \"plans\": [";
  for (std::uint32_t i = 0; i < rs.plan_count; ++i) {
    const PlanConfig& p = rs.plans[i];
    if (i != 0) os << ",";
    os << "\n    {\"id\": " << i << ", \"name\": \"" << json_escape(rs.plan_names[i])
       << "\", \"qos_5qi\": " << static_cast<int>(p.qos_5qi)
       << ", \"arp\": " << static_cast<int>(p.arp) << ", \"ambr_ul_kbps\": " << p.ambr_ul_kbps
       << ", \"ambr_dl_kbps\": " << p.ambr_dl_kbps << ", \"quota_bytes\": " << p.quota_bytes
       << ", \"quota_validity_s\": " << p.quota_validity_s
       << ", \"rating_group\": " << p.rating_group << "}";
  }
  os << "\n  ],\n  \"dnns\": [";
  for (std::size_t i = 0; i < rs.dnn_names.size(); ++i) {
    os << (i ? ", " : "") << "\"" << json_escape(rs.dnn_names[i]) << "\"";
  }
  os << "],\n  \"rules\": [";
  for (std::size_t i = 0; i < rs.rules.size(); ++i) {
    const CompiledRule& r = rs.rules[i];
    char mask[24], value[24];
    std::snprintf(mask, sizeof(mask), "0x%016llx", static_cast<unsigned long long>(r.match_mask));
    std::snprintf(value, sizeof(value), "0x%016llx", static_cast<unsigned long long>(r.match_value));
    if (i != 0) os << ",";
    os << "\n    {\"id\": " << r.id << ", \"priority\": " << r.priority << ", \"plan_mask\": "
       << r.plan_mask << ", \"match_mask\": \"" << mask << "\", \"match_value\": \"" << value
       << "\", \"verdict\": \"" << verdict_name(static_cast<Verdict>(r.action.verdict))
       << "\", \"reason\": \"" << reason_name(static_cast<Reason>(r.action.reason)) << "\"}";
  }
  os << "\n  ]\n}\n";
  return HttpResponse::json(os.str());
}

HttpResponse ControlPlane::handle_reload(const HttpRequest&) {
  std::string error;
  if (!reload_rules(error)) {
    return HttpResponse::error(422, json_escape(error));
  }
  std::ostringstream os;
  os << "{\"version\": " << reload_stats_.current_version
     << ", \"compile_us\": " << reload_stats_.compile_us
     << ", \"grace_us\": " << reload_stats_.grace_period_us << "}\n";
  return HttpResponse::json(os.str());
}

HttpResponse ControlPlane::handle_subscriber(const HttpRequest& req) const {
  static constexpr std::string_view kPrefix = "/subscriber/";
  if (req.path.size() <= kPrefix.size()) return HttpResponse::error(400, "missing IMSI");
  const std::string imsi_text = req.path.substr(kPrefix.size());

  const auto imsi = parse_imsi(imsi_text);
  if (!imsi || *imsi == 0) return HttpResponse::error(400, "invalid IMSI '" + imsi_text + "'");

  const SubscriberRecord* rec = store_.find(*imsi);
  if (rec == nullptr) return HttpResponse::error(404, "IMSI not provisioned");

  const auto guard = const_cast<RcuDomain<RuleSet>&>(rules_).read(rules_.max_readers() - 3);
  const char* plan_name = "?";
  if (guard.get() != nullptr && rec->plan_id < guard->plan_names.size()) {
    plan_name = guard->plan_names[rec->plan_id].c_str();
  }
  static constexpr const char* kStatus[] = {"ACTIVE", "SUSPENDED", "BARRED"};

  std::ostringstream os;
  os << "{\n  \"imsi\": \"" << format_imsi(rec->imsi) << "\",\n"
     << "  \"imei\": \"" << (rec->imei ? format_imsi(rec->imei) : "") << "\",\n"
     << "  \"plan\": \"" << json_escape(plan_name) << "\",\n"
     << "  \"plan_id\": " << rec->plan_id << ",\n"
     << "  \"status\": \"" << (rec->status < 3 ? kStatus[rec->status] : "INVALID") << "\",\n"
     << "  \"bytes_used_period\": " << load_usage(*rec) << ",\n"
     << "  \"period_reset_ts\": " << rec->period_reset_ts << ",\n"
     << "  \"home_plmn\": \"" << format_plmn(rec->home_plmn) << "\",\n"
     << "  \"flags\": " << rec->flags << "\n}\n";
  return HttpResponse::json(os.str());
}

HttpResponse ControlPlane::handle_explain(const HttpRequest& req) const {
  const auto guard = const_cast<RcuDomain<RuleSet>&>(rules_).read(rules_.max_readers() - 3);
  if (guard.get() == nullptr) return HttpResponse::error(503, "no policy loaded");
  const RuleSet& rs = *guard;

  const std::string* imsi_param = req.param("imsi");
  if (imsi_param == nullptr) return HttpResponse::error(400, "imsi parameter is required");
  const auto imsi = parse_imsi(*imsi_param);
  if (!imsi) return HttpResponse::error(400, "invalid IMSI");

  auto uint_param = [&](const char* name, std::uint64_t dflt) -> std::uint64_t {
    const std::string* v = req.param(name);
    return v == nullptr ? dflt : std::strtoull(v->c_str(), nullptr, 10);
  };

  PolicyRequest pr{};
  pr.magic_version = kMagicVersion;
  pr.imsi = *imsi;
  pr.seq = 0;
  pr.client_ts_ns = 0;
  pr.imei = 0;
  if (const std::string* v = req.param("imei")) {
    if (const auto parsed = parse_imei(*v)) pr.imei = *parsed;
  }
  pr.plmn = static_cast<std::uint32_t>(uint_param("plmn", 0));
  if (const std::string* v = req.param("plmn")) {
    if (const auto parsed = parse_plmn(*v)) pr.plmn = *parsed;
  }
  const SubscriberRecord* rec = store_.find(pr.imsi);
  if (pr.plmn == 0 && rec != nullptr) pr.plmn = rec->home_plmn;

  pr.rat_type = static_cast<std::uint8_t>(uint_param("rat", 0));
  pr.requested_5qi = static_cast<std::uint8_t>(uint_param("qos_5qi", 9));
  pr.local_minute = static_cast<std::uint16_t>(uint_param("minute", 720));
  pr.dnn_id = 0;
  if (const std::string* v = req.param("dnn")) {
    const auto it = std::find(rs.dnn_names.begin(), rs.dnn_names.end(), *v);
    if (it == rs.dnn_names.end()) return HttpResponse::error(400, "unknown DNN '" + *v + "'");
    pr.dnn_id = static_cast<std::uint8_t>(std::distance(rs.dnn_names.begin(), it));
  }
  if (const std::string* v = req.param("usage")) {
    pr.bytes_used_period = std::strtoull(v->c_str(), nullptr, 10);
    pr.flags |= kReqFlagUsageValid;
  }
  if (req.param("tethering") != nullptr) pr.flags |= kReqFlagTetheringDetected;
  if (req.param("emergency") != nullptr) pr.flags |= kReqFlagEmergency;

  const FeatureWord features = build_features(rs, pr, rec);
  const PolicyDecision d = evaluate(rs, pr, rec);

  char feat_hex[24];
  std::snprintf(feat_hex, sizeof(feat_hex), "0x%016llx",
                static_cast<unsigned long long>(features));

  std::ostringstream os;
  os << "{\n  \"imsi\": \"" << format_imsi(pr.imsi) << "\",\n"
     << "  \"subscriber_found\": " << (rec != nullptr ? "true" : "false") << ",\n"
     << "  \"features\": \"" << feat_hex << "\",\n"
     << "  \"features_decoded\": \"" << json_escape(describe_features(rs, features)) << "\",\n"
     << "  \"policy_version\": " << d.policy_version << ",\n"
     << "  \"rule_id\": " << d.rule_id << ",\n"
     << "  \"verdict\": \"" << verdict_name(static_cast<Verdict>(d.verdict)) << "\",\n"
     << "  \"reason\": \"" << reason_name(static_cast<Reason>(d.reason)) << "\",\n"
     << "  \"qos_5qi\": " << static_cast<int>(d.qos_5qi) << ",\n"
     << "  \"arp\": " << static_cast<int>(d.arp) << ",\n"
     << "  \"ambr_ul_kbps\": " << d.ambr_ul_kbps << ",\n"
     << "  \"ambr_dl_kbps\": " << d.ambr_dl_kbps << ",\n"
     << "  \"rating_group\": " << d.rating_group << ",\n"
     << "  \"quota_bytes\": " << d.quota_bytes << ",\n"
     << "  \"quota_validity_s\": " << d.quota_validity_s << ",\n"
     << "  \"flags\": " << static_cast<int>(d.flags) << ",\n"
     << "  \"redirect\": \""
     << (d.redirect_id < rs.redirect_targets.size()
             ? json_escape(rs.redirect_targets[d.redirect_id])
             : "")
     << "\"\n}\n";
  return HttpResponse::json(os.str());
}

}  // namespace policy
