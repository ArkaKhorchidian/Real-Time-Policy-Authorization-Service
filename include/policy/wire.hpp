// Fixed-size binary wire format for the latency-critical decision path.
//
// Both messages are exactly 64 bytes — one cache line — little-endian on the
// wire, with a versioned magic header. There is no length prefix and no
// variable-length field anywhere: a datagram is either exactly 64 bytes and
// parseable in a handful of loads, or it is dropped. That is the whole point
// of this format. Names (DNN, plan, RAT) are enums on the wire; the string
// forms live only in the control plane.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace policy {

// 'PLCY' in ASCII, with the protocol version in the low byte. Bump the low
// byte on any layout change; a decoder rejects versions it does not know.
inline constexpr std::uint32_t kMagicBase = 0x504C4300u;  // "PLC\0"
inline constexpr std::uint8_t kWireVersion = 1;
inline constexpr std::uint32_t kMagicVersion = kMagicBase | kWireVersion;

inline constexpr std::size_t kWireMsgSize = 64;

// ---------------------------------------------------------------------------
// Enumerations carried on the wire
// ---------------------------------------------------------------------------

enum class RatType : std::uint8_t {
  kLte = 0,   // E-UTRAN
  kNr = 1,    // 5G New Radio
  kWlan = 2,  // untrusted Wi-Fi / N3IWF
  kCount = 3,
};

enum class Verdict : std::uint8_t {
  kAllow = 0,
  kDeny = 1,
  kRedirect = 2,
};

// Reason codes are stable: they end up in CDRs and in operator dashboards, so
// renumbering one is a breaking change. Append, never reorder.
enum class Reason : std::uint8_t {
  kOk = 0,
  kUnknownSubscriber = 1,
  kSubscriberSuspended = 2,
  kSubscriberBarred = 3,
  kImeiBlocked = 4,
  kRoamingNotAllowed = 5,
  kPlmnNotPartner = 6,
  kDnnNotAllowed = 7,
  kRatNotAllowed = 8,
  kQuotaExhausted = 9,
  kQuotaExhaustedThrottled = 10,
  kTetheringBlocked = 11,
  kNoMatchingRule = 12,
  kPolicyDefaultDeny = 13,
  kOffPeakBonus = 14,
  kPlanDefault = 15,
  kMalformedRequest = 16,
  kCount = 17,
};

// Decision flags, bitwise.
enum DecisionFlag : std::uint8_t {
  kFlagThrottled = 1u << 0,
  kFlagRoamingRestricted = 1u << 1,
  kFlagTetheringBlocked = 1u << 2,
  kFlagQuotaWarning = 1u << 3,
  kFlagOffPeakBonus = 1u << 4,
  kFlagUsageFromRequest = 1u << 5,
};

// Request flags, bitwise.
enum RequestFlag : std::uint8_t {
  kReqFlagTetheringDetected = 1u << 0,
  kReqFlagEmergency = 1u << 1,
  kReqFlagUsageValid = 1u << 2,  // bytes_used_period carries a real value
};

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

// 64 B request. Field order is chosen so every multi-byte field is naturally
// aligned and there is no implicit padding — the layout below is the layout on
// the wire.
struct alignas(64) PolicyRequest {
  std::uint32_t magic_version;      //  0
  std::uint32_t seq;                //  4  client-chosen, echoed verbatim
  std::uint64_t imsi;               //  8  packed 15 digits as a decimal uint64
  std::uint64_t imei;               // 16  packed, 0 if unknown
  std::uint64_t client_ts_ns;       // 24  for one-way latency estimation
  std::uint64_t bytes_used_period;  // 32  usage snapshot; valid iff kReqFlagUsageValid
  std::uint32_t plmn;               // 40  MCC*1000 + MNC, e.g. 310260
  std::uint16_t tac;                // 44  tracking area code
  std::uint8_t rat_type;            // 46  RatType
  std::uint8_t dnn_id;              // 47  index into the RuleSet DNN table
  std::uint8_t requested_5qi;       // 48
  std::uint8_t flags;               // 49  RequestFlag bits
  std::uint16_t local_minute;       // 50  minutes since local midnight, 0..1439
  std::uint32_t req_ambr_ul_kbps;   // 52
  std::uint32_t req_ambr_dl_kbps;   // 56
  std::uint32_t reserved;           // 60
};
static_assert(sizeof(PolicyRequest) == kWireMsgSize, "PolicyRequest must be 64 B");
static_assert(std::is_trivially_copyable_v<PolicyRequest>);
static_assert(offsetof(PolicyRequest, imsi) == 8);
static_assert(offsetof(PolicyRequest, req_ambr_dl_kbps) == 56);

// 64 B decision.
struct alignas(64) PolicyDecision {
  std::uint32_t magic_version;    //  0
  std::uint32_t seq;              //  4  echoed
  std::uint64_t client_ts_ns;     //  8  echoed
  std::uint64_t quota_bytes;      // 16  granted quota for this rating group
  std::uint32_t ambr_ul_kbps;     // 24  authorized session AMBR, uplink
  std::uint32_t ambr_dl_kbps;     // 28  authorized session AMBR, downlink
  std::uint32_t rating_group;     // 32
  std::uint32_t quota_validity_s; // 36
  std::uint32_t rule_id;          // 40  which rule fired — for auditability
  std::uint32_t policy_version;   // 44  which RuleSet produced this
  std::uint8_t verdict;           // 48  Verdict
  std::uint8_t reason;            // 49  Reason
  std::uint8_t qos_5qi;           // 50
  std::uint8_t arp;               // 51  1..15, 1 = highest priority
  std::uint8_t flags;             // 52  DecisionFlag bits
  std::uint8_t redirect_id;       // 53  index into the RuleSet redirect table
  std::uint16_t reserved;         // 54
  std::uint64_t server_ts_ns;     // 56  set on send; service time observability
};
static_assert(sizeof(PolicyDecision) == kWireMsgSize, "PolicyDecision must be 64 B");
static_assert(std::is_trivially_copyable_v<PolicyDecision>);
static_assert(offsetof(PolicyDecision, verdict) == 48);
static_assert(offsetof(PolicyDecision, server_ts_ns) == 56);

// ---------------------------------------------------------------------------
// Byte order
// ---------------------------------------------------------------------------
//
// The wire is little-endian. On a little-endian host (every machine this is
// meant to run on) encode/decode are a straight memcpy and the compiler emits
// nothing at all. The big-endian path exists so the format stays honest, not
// because it is expected to be exercised.

inline constexpr bool kHostIsLittleEndian =
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__;
#else
    true;
#endif

namespace detail {
constexpr std::uint16_t bswap16(std::uint16_t v) { return static_cast<std::uint16_t>(v << 8 | v >> 8); }
constexpr std::uint32_t bswap32(std::uint32_t v) { return __builtin_bswap32(v); }
constexpr std::uint64_t bswap64(std::uint64_t v) { return __builtin_bswap64(v); }

template <typename T>
constexpr T to_le(T v) {
  if constexpr (kHostIsLittleEndian) {
    return v;
  } else if constexpr (sizeof(T) == 2) {
    return static_cast<T>(bswap16(static_cast<std::uint16_t>(v)));
  } else if constexpr (sizeof(T) == 4) {
    return static_cast<T>(bswap32(static_cast<std::uint32_t>(v)));
  } else if constexpr (sizeof(T) == 8) {
    return static_cast<T>(bswap64(static_cast<std::uint64_t>(v)));
  } else {
    return v;
  }
}
}  // namespace detail

// Byte-swap every multi-byte field in place. Self-inverse, so the same routine
// serves encode and decode.
inline void swap_endianness(PolicyRequest& r) {
  r.magic_version = detail::to_le(r.magic_version);
  r.seq = detail::to_le(r.seq);
  r.imsi = detail::to_le(r.imsi);
  r.imei = detail::to_le(r.imei);
  r.client_ts_ns = detail::to_le(r.client_ts_ns);
  r.bytes_used_period = detail::to_le(r.bytes_used_period);
  r.plmn = detail::to_le(r.plmn);
  r.tac = detail::to_le(r.tac);
  r.local_minute = detail::to_le(r.local_minute);
  r.req_ambr_ul_kbps = detail::to_le(r.req_ambr_ul_kbps);
  r.req_ambr_dl_kbps = detail::to_le(r.req_ambr_dl_kbps);
  r.reserved = detail::to_le(r.reserved);
}

inline void swap_endianness(PolicyDecision& d) {
  d.magic_version = detail::to_le(d.magic_version);
  d.seq = detail::to_le(d.seq);
  d.client_ts_ns = detail::to_le(d.client_ts_ns);
  d.quota_bytes = detail::to_le(d.quota_bytes);
  d.ambr_ul_kbps = detail::to_le(d.ambr_ul_kbps);
  d.ambr_dl_kbps = detail::to_le(d.ambr_dl_kbps);
  d.rating_group = detail::to_le(d.rating_group);
  d.quota_validity_s = detail::to_le(d.quota_validity_s);
  d.rule_id = detail::to_le(d.rule_id);
  d.policy_version = detail::to_le(d.policy_version);
  d.reserved = detail::to_le(d.reserved);
  d.server_ts_ns = detail::to_le(d.server_ts_ns);
}

// Serialize `in` into a 64-byte buffer. `out` need not be aligned.
template <typename Msg>
inline void encode(const Msg& in, void* out) {
  if constexpr (kHostIsLittleEndian) {
    std::memcpy(out, &in, kWireMsgSize);
  } else {
    Msg tmp = in;
    swap_endianness(tmp);
    std::memcpy(out, &tmp, kWireMsgSize);
  }
}

// Deserialize a datagram. Returns false — without touching `out` in a way the
// caller can mistake for success — if the length or magic is wrong.
template <typename Msg>
[[nodiscard]] inline bool decode(const void* in, std::size_t len, Msg& out) {
  if (len != kWireMsgSize) return false;
  std::memcpy(&out, in, kWireMsgSize);
  if constexpr (!kHostIsLittleEndian) swap_endianness(out);
  return out.magic_version == kMagicVersion;
}

// ---------------------------------------------------------------------------
// Small helpers shared by server, loadgen and tests
// ---------------------------------------------------------------------------

inline const char* verdict_name(Verdict v) {
  switch (v) {
    case Verdict::kAllow: return "ALLOW";
    case Verdict::kDeny: return "DENY";
    case Verdict::kRedirect: return "REDIRECT";
  }
  return "INVALID";
}

inline const char* reason_name(Reason r) {
  switch (r) {
    case Reason::kOk: return "OK";
    case Reason::kUnknownSubscriber: return "UNKNOWN_SUBSCRIBER";
    case Reason::kSubscriberSuspended: return "SUBSCRIBER_SUSPENDED";
    case Reason::kSubscriberBarred: return "SUBSCRIBER_BARRED";
    case Reason::kImeiBlocked: return "IMEI_BLOCKED";
    case Reason::kRoamingNotAllowed: return "ROAMING_NOT_ALLOWED";
    case Reason::kPlmnNotPartner: return "PLMN_NOT_PARTNER";
    case Reason::kDnnNotAllowed: return "DNN_NOT_ALLOWED";
    case Reason::kRatNotAllowed: return "RAT_NOT_ALLOWED";
    case Reason::kQuotaExhausted: return "QUOTA_EXHAUSTED";
    case Reason::kQuotaExhaustedThrottled: return "QUOTA_EXHAUSTED_THROTTLED";
    case Reason::kTetheringBlocked: return "TETHERING_BLOCKED";
    case Reason::kNoMatchingRule: return "NO_MATCHING_RULE";
    case Reason::kPolicyDefaultDeny: return "POLICY_DEFAULT_DENY";
    case Reason::kOffPeakBonus: return "OFF_PEAK_BONUS";
    case Reason::kPlanDefault: return "PLAN_DEFAULT";
    case Reason::kMalformedRequest: return "MALFORMED_REQUEST";
    case Reason::kCount: break;
  }
  return "INVALID";
}

inline const char* rat_name(RatType r) {
  switch (r) {
    case RatType::kLte: return "LTE";
    case RatType::kNr: return "NR";
    case RatType::kWlan: return "WLAN";
    case RatType::kCount: break;
  }
  return "INVALID";
}

}  // namespace policy
