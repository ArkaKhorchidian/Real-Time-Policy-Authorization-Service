#include "policy/golden.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace policy {
namespace {

constexpr const char* kHeader =
    "imsi,imei,plmn,tac,rat,dnn,req_5qi,req_flags,local_minute,bytes_used,"
    "verdict,reason,qos_5qi,arp,ambr_ul_kbps,ambr_dl_kbps,rating_group,"
    "quota_bytes,quota_validity_s,rule_id,dec_flags,redirect_id";

constexpr std::size_t kFieldCount = 22;

std::uint64_t to_u64(std::string_view s) {
  return std::strtoull(std::string(s).c_str(), nullptr, 10);
}

}  // namespace

std::string golden_header() { return kHeader; }

std::string golden_row(const PolicyRequest& r, const PolicyDecision& d) {
  char buf[512];
  std::snprintf(buf, sizeof(buf),
                "%llu,%llu,%u,%u,%u,%u,%u,%u,%u,%llu,"
                "%u,%u,%u,%u,%u,%u,%u,%llu,%u,%u,%u,%u",
                static_cast<unsigned long long>(r.imsi), static_cast<unsigned long long>(r.imei),
                r.plmn, r.tac, r.rat_type, r.dnn_id, r.requested_5qi, r.flags, r.local_minute,
                static_cast<unsigned long long>(r.bytes_used_period), d.verdict, d.reason,
                d.qos_5qi, d.arp, d.ambr_ul_kbps, d.ambr_dl_kbps, d.rating_group,
                static_cast<unsigned long long>(d.quota_bytes), d.quota_validity_s, d.rule_id,
                d.flags, d.redirect_id);
  return buf;
}

GoldenLoadResult load_golden(const std::string& path) {
  GoldenLoadResult res;
  std::ifstream in(path);
  if (!in) {
    res.error = "cannot open golden file: " + path;
    return res;
  }

  std::string line;
  int line_no = 0;
  bool header_checked = false;

  while (std::getline(in, line)) {
    ++line_no;
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    if (line.empty() || line[0] == '#') continue;

    if (!header_checked) {
      header_checked = true;
      if (line != kHeader) {
        res.error = path + ":1: header does not match the current golden format.\n  expected: " +
                    kHeader + "\n  found:    " + line +
                    "\nRegenerate with: policy-gen-golden --out " + path;
        return res;
      }
      continue;
    }

    std::string_view f[kFieldCount];
    std::size_t n = 0;
    std::size_t start = 0;
    while (n < kFieldCount) {
      const auto comma = line.find(',', start);
      if (comma == std::string::npos) {
        f[n++] = std::string_view(line).substr(start);
        break;
      }
      f[n++] = std::string_view(line).substr(start, comma - start);
      start = comma + 1;
    }
    if (n != kFieldCount) {
      res.error = path + ":" + std::to_string(line_no) + ": expected " +
                  std::to_string(kFieldCount) + " fields, found " + std::to_string(n);
      return res;
    }

    GoldenCase c;
    c.line = line_no;
    c.request.magic_version = kMagicVersion;
    c.request.imsi = to_u64(f[0]);
    c.request.imei = to_u64(f[1]);
    c.request.plmn = static_cast<std::uint32_t>(to_u64(f[2]));
    c.request.tac = static_cast<std::uint16_t>(to_u64(f[3]));
    c.request.rat_type = static_cast<std::uint8_t>(to_u64(f[4]));
    c.request.dnn_id = static_cast<std::uint8_t>(to_u64(f[5]));
    c.request.requested_5qi = static_cast<std::uint8_t>(to_u64(f[6]));
    c.request.flags = static_cast<std::uint8_t>(to_u64(f[7]));
    c.request.local_minute = static_cast<std::uint16_t>(to_u64(f[8]));
    c.request.bytes_used_period = to_u64(f[9]);

    c.expected.magic_version = kMagicVersion;
    c.expected.verdict = static_cast<std::uint8_t>(to_u64(f[10]));
    c.expected.reason = static_cast<std::uint8_t>(to_u64(f[11]));
    c.expected.qos_5qi = static_cast<std::uint8_t>(to_u64(f[12]));
    c.expected.arp = static_cast<std::uint8_t>(to_u64(f[13]));
    c.expected.ambr_ul_kbps = static_cast<std::uint32_t>(to_u64(f[14]));
    c.expected.ambr_dl_kbps = static_cast<std::uint32_t>(to_u64(f[15]));
    c.expected.rating_group = static_cast<std::uint32_t>(to_u64(f[16]));
    c.expected.quota_bytes = to_u64(f[17]);
    c.expected.quota_validity_s = static_cast<std::uint32_t>(to_u64(f[18]));
    c.expected.rule_id = static_cast<std::uint32_t>(to_u64(f[19]));
    c.expected.flags = static_cast<std::uint8_t>(to_u64(f[20]));
    c.expected.redirect_id = static_cast<std::uint8_t>(to_u64(f[21]));

    res.cases.push_back(c);
  }

  if (res.cases.empty()) res.error = path + ": no cases";
  return res;
}

std::string diff_decisions(const PolicyDecision& e, const PolicyDecision& a) {
  std::ostringstream os;
  auto cmp = [&](const char* name, auto expected, auto actual) {
    if (expected != actual) {
      os << (os.tellp() == 0 ? "" : ", ") << name << ": expected "
         << static_cast<std::uint64_t>(expected) << " got " << static_cast<std::uint64_t>(actual);
    }
  };
  if (e.verdict != a.verdict) {
    os << "verdict: expected " << verdict_name(static_cast<Verdict>(e.verdict)) << " got "
       << verdict_name(static_cast<Verdict>(a.verdict));
  }
  if (e.reason != a.reason) {
    os << (os.tellp() == 0 ? "" : ", ") << "reason: expected "
       << reason_name(static_cast<Reason>(e.reason)) << " got "
       << reason_name(static_cast<Reason>(a.reason));
  }
  cmp("rule_id", e.rule_id, a.rule_id);
  cmp("qos_5qi", e.qos_5qi, a.qos_5qi);
  cmp("arp", e.arp, a.arp);
  cmp("ambr_ul_kbps", e.ambr_ul_kbps, a.ambr_ul_kbps);
  cmp("ambr_dl_kbps", e.ambr_dl_kbps, a.ambr_dl_kbps);
  cmp("rating_group", e.rating_group, a.rating_group);
  cmp("quota_bytes", e.quota_bytes, a.quota_bytes);
  cmp("quota_validity_s", e.quota_validity_s, a.quota_validity_s);
  cmp("flags", e.flags, a.flags);
  cmp("redirect_id", e.redirect_id, a.redirect_id);
  return os.str();
}

}  // namespace policy
