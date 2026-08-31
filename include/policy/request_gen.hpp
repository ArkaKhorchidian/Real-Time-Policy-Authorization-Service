// Deterministic synthetic request generator.
//
// Shared by the golden-file tool, the tests and the load generator, so all
// three exercise the same traffic mix and a golden file generated on one
// machine reproduces exactly on another.
//
// The mix is chosen so the interesting rules actually fire. A generator that
// draws uniformly over the input space spends its time on requests that all
// take the same path through evaluate(), which makes the branch predictor look
// far better than it would in production and hides the cost of the rules that
// matter.
#pragma once

#include <cstdint>
#include <random>
#include <vector>

#include "policy/wire.hpp"

namespace policy {

struct RequestMix {
  // Fraction of requests whose IMSI is not provisioned. Real signalling always
  // carries some: failed attach attempts, stale sessions, typo'd provisioning.
  double unknown_imsi = 0.02;

  // Fraction carrying a usage snapshot from the serving node instead of relying
  // on the store's replicated counter.
  double usage_in_request = 0.25;

  // Fraction on a visited network rather than the subscriber's home PLMN.
  double roaming = 0.08;

  // Fraction flagged as tethering by the serving node's traffic detection.
  double tethering = 0.05;

  // Fraction of emergency sessions. Rare, but they take the very first rule and
  // must be represented or that path never gets measured.
  double emergency = 0.001;

  // Fraction reporting no IMEI at all.
  double imei_absent = 0.05;

  // Fraction whose IMEI is on the blocklist. Higher than reality (which is
  // ~0.01%) so the redirect path gets meaningful sample counts in a short run.
  double imei_blocked = 0.002;

  // Fraction that land inside the 02:00-06:00 off-peak window.
  double off_peak = 0.15;
};

class RequestGenerator {
 public:
  // `imsis` is the pool of provisioned identities; `blocked_imeis` and
  // `visited_plmns` steer the corresponding fractions of the mix. All are
  // copied, so the generator is self-contained and safe to move between
  // threads (one generator per thread — it is not itself thread-safe).
  RequestGenerator(std::uint64_t seed, std::vector<std::uint64_t> imsis,
                   std::vector<std::uint64_t> blocked_imeis, std::vector<std::uint32_t> visited_plmns,
                   std::uint8_t dnn_count, RequestMix mix = {})
      : rng_(seed),
        imsis_(std::move(imsis)),
        blocked_imeis_(std::move(blocked_imeis)),
        visited_plmns_(std::move(visited_plmns)),
        dnn_count_(dnn_count == 0 ? 1 : dnn_count),
        mix_(mix) {}

  // Fill `req` with the next synthetic request. `seq` and `client_ts_ns` are
  // left to the caller, which owns the latency bookkeeping.
  void fill(PolicyRequest& req) {
    req = PolicyRequest{};
    req.magic_version = kMagicVersion;

    // Identity.
    if (!imsis_.empty() && unit() >= mix_.unknown_imsi) {
      std::uniform_int_distribution<std::size_t> pick(0, imsis_.size() - 1);
      req.imsi = imsis_[pick(rng_)];
    } else {
      // An IMSI in a range no roster covers. Deterministic, and guaranteed not
      // to collide with a provisioned one.
      std::uniform_int_distribution<std::uint64_t> pick(999'000'000'000'000ull,
                                                        999'999'999'999'999ull);
      req.imsi = pick(rng_);
    }

    // Device.
    const double imei_roll = unit();
    if (imei_roll < mix_.imei_absent) {
      req.imei = 0;
    } else if (imei_roll < mix_.imei_absent + mix_.imei_blocked && !blocked_imeis_.empty()) {
      std::uniform_int_distribution<std::size_t> pick(0, blocked_imeis_.size() - 1);
      req.imei = blocked_imeis_[pick(rng_)];
    } else {
      std::uniform_int_distribution<std::uint64_t> pick(350'000'000'000'000ull,
                                                        359'999'999'999'999ull);
      req.imei = pick(rng_);
    }

    // Access. LTE still carries the majority of attach signalling; NR is
    // growing; Wi-Fi offload is a small slice.
    const double rat_roll = unit();
    req.rat_type = static_cast<std::uint8_t>(rat_roll < 0.55   ? RatType::kLte
                                             : rat_roll < 0.93 ? RatType::kNr
                                                               : RatType::kWlan);

    // DNN: internet dominates, ims is the second most common, the rest are
    // long-tail.
    const double dnn_roll = unit();
    if (dnn_roll < 0.70) req.dnn_id = 0;
    else if (dnn_roll < 0.88) req.dnn_id = static_cast<std::uint8_t>(1 % dnn_count_);
    else {
      std::uniform_int_distribution<int> pick(0, dnn_count_ - 1);
      req.dnn_id = static_cast<std::uint8_t>(pick(rng_));
    }

    // Location. plmn 0 means "use the subscriber's home network", which the
    // caller resolves; a roaming request picks a visited network.
    if (unit() < mix_.roaming && !visited_plmns_.empty()) {
      std::uniform_int_distribution<std::size_t> pick(0, visited_plmns_.size() - 1);
      req.plmn = visited_plmns_[pick(rng_)];
    } else {
      req.plmn = 0;
    }
    std::uniform_int_distribution<int> tac_pick(1, 65534);
    req.tac = static_cast<std::uint16_t>(tac_pick(rng_));

    // Requested QoS: mostly the default bearer, sometimes a GBR class.
    const double qos_roll = unit();
    req.requested_5qi = qos_roll < 0.80 ? 9 : (qos_roll < 0.95 ? 8 : 1);
    req.req_ambr_ul_kbps = 100'000;
    req.req_ambr_dl_kbps = 500'000;

    // Time of day. The off-peak window is over-represented relative to its
    // 4/24 share of the day so the bonus rule gets exercised.
    if (unit() < mix_.off_peak) {
      std::uniform_int_distribution<int> pick(120, 359);  // 02:00-05:59
      req.local_minute = static_cast<std::uint16_t>(pick(rng_));
    } else {
      std::uniform_int_distribution<int> pick(360, 1439 + 119);
      req.local_minute = static_cast<std::uint16_t>(pick(rng_) % 1440);
    }

    // Session flags.
    if (unit() < mix_.tethering) req.flags |= kReqFlagTetheringDetected;
    if (unit() < mix_.emergency) req.flags |= kReqFlagEmergency;
    if (unit() < mix_.usage_in_request) {
      req.flags |= kReqFlagUsageValid;
      // Same skew as the roster: mostly well under, a tail at and over the line.
      const double u = unit();
      double gb;
      if (u < 0.70) gb = unit() * 8.0;
      else if (u < 0.92) gb = 8.0 + unit() * 10.0;
      else gb = 18.0 + unit() * 20.0;
      req.bytes_used_period = static_cast<std::uint64_t>(gb * 1e9);
    }
  }

 private:
  double unit() { return dist_(rng_); }

  std::mt19937_64 rng_;
  std::uniform_real_distribution<double> dist_{0.0, 1.0};
  std::vector<std::uint64_t> imsis_;
  std::vector<std::uint64_t> blocked_imeis_;
  std::vector<std::uint32_t> visited_plmns_;
  std::uint8_t dnn_count_;
  RequestMix mix_;
};

}  // namespace policy
