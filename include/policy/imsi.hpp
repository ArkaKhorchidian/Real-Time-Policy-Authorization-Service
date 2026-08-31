// IMSI / IMEI packing.
//
// An IMSI is at most 15 decimal digits, so it fits in a uint64_t as a plain
// decimal integer (max 999'999'999'999'999 < 2^50). That representation is
// chosen deliberately over BCD: it keeps the hash key a single register, makes
// the PLMN prefix (MCC+MNC) recoverable with a divide by a constant the
// compiler turns into a multiply, and round-trips to the printed form exactly.
//
// Leading zeros matter — MCC 208 (France) and MCC 020 are different networks —
// so the digit count is carried alongside the value wherever the printed form
// has to be reproduced. In the store we key on the value alone and normalize
// all IMSIs to 15 digits, which is what a real HSS/UDM does.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace policy {

inline constexpr std::size_t kImsiDigits = 15;
inline constexpr std::size_t kImeiDigits = 15;
inline constexpr std::uint64_t kInvalidImsi = 0;

// Parse `digits` decimal characters into a uint64_t. Rejects empty input,
// anything longer than `max_digits`, and any non-digit character. Returns
// nullopt rather than a sentinel so a caller cannot forget to check.
[[nodiscard]] inline std::optional<std::uint64_t> parse_digits(std::string_view s,
                                                               std::size_t max_digits) {
  if (s.empty() || s.size() > max_digits) return std::nullopt;
  std::uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') return std::nullopt;
    v = v * 10 + static_cast<std::uint64_t>(c - '0');
  }
  return v;
}

[[nodiscard]] inline std::optional<std::uint64_t> parse_imsi(std::string_view s) {
  return parse_digits(s, kImsiDigits);
}

[[nodiscard]] inline std::optional<std::uint64_t> parse_imei(std::string_view s) {
  if (s.empty()) return 0;  // IMEI is optional; empty means "not reported"
  return parse_digits(s, kImeiDigits);
}

// Render back to the canonical zero-padded form.
[[nodiscard]] inline std::string format_imsi(std::uint64_t imsi, std::size_t digits = kImsiDigits) {
  std::string out(digits, '0');
  for (std::size_t i = digits; i-- > 0;) {
    out[i] = static_cast<char>('0' + static_cast<char>(imsi % 10));
    imsi /= 10;
  }
  return out;
}

// PLMN as MCC*1000+MNC, the packed form used on the wire and in the rules file.
// A 2-digit MNC is stored as-is (310260 vs 20408), matching how operators write
// them; the rules loader normalizes both spellings.
[[nodiscard]] constexpr std::uint32_t make_plmn(std::uint32_t mcc, std::uint32_t mnc) {
  return mcc * 1000u + mnc;
}

[[nodiscard]] constexpr std::uint32_t plmn_mcc(std::uint32_t plmn) { return plmn / 1000u; }
[[nodiscard]] constexpr std::uint32_t plmn_mnc(std::uint32_t plmn) { return plmn % 1000u; }

// Parse "310-260", "310260" or "310/260".
[[nodiscard]] inline std::optional<std::uint32_t> parse_plmn(std::string_view s) {
  const auto sep = s.find_first_of("-/ ");
  if (sep == std::string_view::npos) {
    // Bare digits: 5 digits is MCC + 2-digit MNC, 6 digits is MCC + 3-digit MNC.
    if (s.size() != 5 && s.size() != 6) return std::nullopt;
    const auto mcc = parse_digits(s.substr(0, 3), 3);
    const auto mnc = parse_digits(s.substr(3), 3);
    if (!mcc || !mnc) return std::nullopt;
    return make_plmn(static_cast<std::uint32_t>(*mcc), static_cast<std::uint32_t>(*mnc));
  }
  // The MCC is always exactly three digits and the MNC is two or three.
  // Accepting a short MCC would let "31-260" parse as a valid network, which is
  // a different operator on a different continent from "310-260".
  const std::string_view mcc_text = s.substr(0, sep);
  const std::string_view mnc_text = s.substr(sep + 1);
  if (mcc_text.size() != 3 || mnc_text.size() < 2 || mnc_text.size() > 3) return std::nullopt;
  const auto mcc = parse_digits(mcc_text, 3);
  const auto mnc = parse_digits(mnc_text, 3);
  if (!mcc || !mnc) return std::nullopt;
  return make_plmn(static_cast<std::uint32_t>(*mcc), static_cast<std::uint32_t>(*mnc));
}

[[nodiscard]] inline std::string format_plmn(std::uint32_t plmn) {
  return std::to_string(plmn_mcc(plmn)) + "-" + std::to_string(plmn_mnc(plmn));
}

// Luhn check digit, the last digit of a 15-digit IMEI. Used by the synthetic
// data generator so the fixtures look like real IMEIs, and by the admin API to
// reject obvious typos.
[[nodiscard]] inline bool imei_luhn_valid(std::uint64_t imei) {
  std::uint32_t sum = 0;
  bool dbl = false;
  while (imei > 0) {
    auto d = static_cast<std::uint32_t>(imei % 10);
    imei /= 10;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 == 0;
}

}  // namespace policy
