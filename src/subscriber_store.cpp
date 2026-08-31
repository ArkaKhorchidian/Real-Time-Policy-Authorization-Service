#include "policy/subscriber_store.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>

#include "policy/imsi.hpp"

namespace policy {

std::size_t next_pow2(std::size_t n) {
  std::size_t p = 8;
  while (p < n) p <<= 1;
  return p;
}

std::size_t SubscriberStore::slots_for(std::size_t n, double load_factor) {
  load_factor = std::clamp(load_factor, 0.25, 0.9);
  const auto needed = static_cast<std::size_t>(
      std::ceil(static_cast<double>(std::max<std::size_t>(n, 4)) / load_factor));
  return next_pow2(needed);
}

SubscriberStore::SubscriberStore(std::size_t expected_subscribers, double max_load_factor)
    : max_load_factor_(std::clamp(max_load_factor, 0.25, 0.9)) {
  const std::size_t cap = slots_for(expected_subscribers, max_load_factor_);
  slots_.assign(cap, SubscriberRecord{});
  mask_ = cap - 1;
}

SubscriberRecord* SubscriberStore::find_mutable(std::uint64_t imsi) noexcept {
  if (imsi == 0) return nullptr;
  std::size_t i = hash(imsi) & mask_;
  for (;;) {
    SubscriberRecord& r = slots_[i];
    if (r.imsi == imsi) return &r;
    if (r.imsi == 0) return nullptr;
    i = (i + 1) & mask_;
  }
}

void SubscriberStore::grow(std::size_t new_capacity) {
  std::vector<SubscriberRecord> old;
  old.swap(slots_);
  slots_.assign(new_capacity, SubscriberRecord{});
  mask_ = new_capacity - 1;
  size_ = 0;
  for (const auto& r : old) {
    if (r.imsi != 0) upsert(r);
  }
}

bool SubscriberStore::upsert(const SubscriberRecord& rec) {
  if (rec.imsi == 0) return false;

  // Keep the load factor at or below the configured ceiling. Average probe
  // length for linear probing grows as (1 + 1/(1-alpha))/2: 1.5 at alpha 0.5,
  // 1.8 at 0.6, 3.0 at 0.8, 5.5 at 0.9. Memory is usually cheaper than tail
  // latency, which is why the default ceiling is 0.5.
  if (static_cast<double>(size_ + 1) > static_cast<double>(slots_.size()) * max_load_factor_) {
    grow(slots_.size() * 2);
  }

  std::size_t i = hash(rec.imsi) & mask_;
  for (;;) {
    SubscriberRecord& slot = slots_[i];
    if (slot.imsi == rec.imsi) {
      slot = rec;  // update in place
      return true;
    }
    if (slot.imsi == 0) {
      slot = rec;
      ++size_;
      return true;
    }
    i = (i + 1) & mask_;
  }
}

void SubscriberStore::add_usage(std::uint64_t imsi, std::uint64_t bytes) noexcept {
  SubscriberRecord* r = find_mutable(imsi);
  if (r == nullptr) return;
  // Relaxed RMW on the one field workers may write. A decision made against a
  // counter that is a few hundred nanoseconds stale is not a wrong decision;
  // ordering this against anything else would cost every reader a fence.
  __atomic_fetch_add(&r->bytes_used_period, bytes, __ATOMIC_RELAXED);
}

bool SubscriberStore::reset_period(std::uint64_t imsi, std::uint64_t new_reset_ts) noexcept {
  SubscriberRecord* r = find_mutable(imsi);
  if (r == nullptr) return false;
  __atomic_store_n(&r->bytes_used_period, std::uint64_t{0}, __ATOMIC_RELAXED);
  r->period_reset_ts = new_reset_ts;
  return true;
}

StoreStats SubscriberStore::stats() const {
  StoreStats s;
  s.size = size_;
  s.capacity = slots_.size();
  s.memory_bytes = slots_.size() * sizeof(SubscriberRecord);
  s.load_factor = s.capacity ? static_cast<double>(s.size) / static_cast<double>(s.capacity) : 0.0;

  std::size_t total_probes = 0;
  for (std::size_t i = 0; i < slots_.size(); ++i) {
    if (slots_[i].imsi == 0) continue;
    const std::size_t home = hash(slots_[i].imsi) & mask_;
    const std::size_t probes = ((i - home) & mask_) + 1;
    total_probes += probes;
    s.max_probe_length = std::max(s.max_probe_length, probes);
  }
  s.mean_probe_length =
      s.size ? static_cast<double>(total_probes) / static_cast<double>(s.size) : 0.0;
  return s;
}

namespace {

// Split on ',' without allocating a vector of strings per row — the loader runs
// over 10M rows and the naive version spends its whole time in malloc.
std::size_t split_fields(std::string_view line, std::string_view* out, std::size_t max_fields) {
  std::size_t n = 0;
  std::size_t start = 0;
  while (n < max_fields) {
    const auto comma = line.find(',', start);
    if (comma == std::string_view::npos) {
      out[n++] = line.substr(start);
      break;
    }
    out[n++] = line.substr(start, comma - start);
    start = comma + 1;
  }
  return n;
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return s;
}

std::optional<std::uint64_t> parse_u64(std::string_view s) {
  s = trim(s);
  if (s.empty()) return std::nullopt;
  std::uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') return std::nullopt;
    v = v * 10 + static_cast<std::uint64_t>(c - '0');
  }
  return v;
}

std::optional<SubscriberStatus> parse_status(std::string_view s) {
  s = trim(s);
  if (s == "ACTIVE" || s == "active" || s == "0") return SubscriberStatus::kActive;
  if (s == "SUSPENDED" || s == "suspended" || s == "1") return SubscriberStatus::kSuspended;
  if (s == "BARRED" || s == "barred" || s == "2") return SubscriberStatus::kBarred;
  return std::nullopt;
}

std::uint32_t parse_sub_flags(std::string_view s) {
  std::uint32_t flags = 0;
  std::size_t start = 0;
  while (start <= s.size()) {
    const auto sep = s.find('|', start);
    const std::string_view tok =
        trim(s.substr(start, sep == std::string_view::npos ? std::string_view::npos : sep - start));
    if (tok == "roaming") flags |= kSubRoamingAllowed;
    else if (tok == "tethering") flags |= kSubTetheringAllowed;
    else if (tok == "volte") flags |= kSubVolteEnabled;
    else if (tok == "test") flags |= kSubTestSubscriber;
    if (sep == std::string_view::npos) break;
    start = sep + 1;
  }
  return flags;
}

}  // namespace

SubscriberStore::LoadResult SubscriberStore::load_csv(const std::string& path,
                                                      const std::vector<std::string>& plan_names) {
  LoadResult res;
  std::ifstream in(path);
  if (!in) {
    res.errors.push_back("cannot open subscriber file: " + path);
    return res;
  }

  std::string line;
  std::size_t line_no = 0;
  bool header_seen = false;

  auto note = [&](const std::string& msg) {
    ++res.skipped;
    if (res.errors.size() < kMaxReportedErrors) {
      res.errors.push_back(path + ":" + std::to_string(line_no) + ": " + msg);
    } else if (res.errors.size() == kMaxReportedErrors) {
      res.errors.push_back("... further errors suppressed");
    }
  };

  while (std::getline(in, line)) {
    ++line_no;
    std::string_view sv = trim(line);
    if (sv.empty() || sv.front() == '#') continue;

    if (!header_seen) {
      header_seen = true;
      // Accept a header row, but do not require one: a generated 10M-row file
      // should not need a special case to be loadable.
      if (sv.substr(0, 4) == "imsi") continue;
    }

    std::string_view f[8];
    const std::size_t n = split_fields(sv, f, 8);
    if (n < 7) {
      note("expected at least 7 comma-separated fields, got " + std::to_string(n));
      continue;
    }

    const auto imsi = parse_imsi(trim(f[0]));
    if (!imsi || *imsi == 0) {
      note("invalid IMSI '" + std::string(trim(f[0])) + "'");
      continue;
    }
    const auto imei = parse_imei(trim(f[1]));
    if (!imei) {
      note("invalid IMEI '" + std::string(trim(f[1])) + "'");
      continue;
    }

    const std::string_view plan_name = trim(f[2]);
    const auto it = std::find(plan_names.begin(), plan_names.end(), plan_name);
    if (it == plan_names.end()) {
      // Deliberately an error, not a silent fallback to plan 0: a typo in the
      // roster would otherwise downgrade every affected subscriber's QoS.
      note("unknown plan '" + std::string(plan_name) + "'");
      continue;
    }

    const auto status = parse_status(f[3]);
    if (!status) {
      note("invalid status '" + std::string(trim(f[3])) + "'");
      continue;
    }
    const auto used = parse_u64(f[4]);
    const auto reset_ts = parse_u64(f[5]);
    const auto plmn = parse_plmn(trim(f[6]));
    if (!used || !reset_ts || !plmn) {
      note("invalid usage/reset/plmn field");
      continue;
    }

    SubscriberRecord rec{};
    rec.imsi = *imsi;
    rec.imei = *imei;
    rec.plan_id = static_cast<std::uint32_t>(std::distance(plan_names.begin(), it));
    rec.status = static_cast<std::uint32_t>(*status);
    rec.bytes_used_period = *used;
    rec.period_reset_ts = *reset_ts;
    rec.home_plmn = *plmn;
    rec.flags = n >= 8 ? parse_sub_flags(f[7]) : 0;

    upsert(rec);
    ++res.loaded;
  }

  return res;
}

}  // namespace policy
