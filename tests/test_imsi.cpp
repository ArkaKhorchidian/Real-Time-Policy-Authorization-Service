#include "policy/imsi.hpp"
#include "test_framework.hpp"

using namespace policy;

TEST(Imsi, ParsesAndFormatsRoundTrip) {
  const auto v = parse_imsi("310260123456789");
  REQUIRE(v.has_value());
  CHECK_EQ(*v, 310260123456789ull);
  CHECK_EQ(format_imsi(*v), std::string("310260123456789"));
}

TEST(Imsi, PreservesLeadingZeros) {
  // MCC 020 and MCC 208 are different networks. An IMSI printed without its
  // leading zeros routes to the wrong place.
  const auto v = parse_imsi("020801234567890");
  REQUIRE(v.has_value());
  CHECK_EQ(format_imsi(*v), std::string("020801234567890"));
}

TEST(Imsi, RejectsMalformedInput) {
  CHECK(!parse_imsi("").has_value());
  CHECK(!parse_imsi("3102601234567890").has_value());  // 16 digits
  CHECK(!parse_imsi("31026012345678a").has_value());
  CHECK(!parse_imsi("310 260 123").has_value());
  CHECK(!parse_imsi("-310260123456789").has_value());
  CHECK(!parse_imsi("+31026012345678").has_value());
  // Shorter IMSIs are legal: not every network uses all 15 digits.
  CHECK(parse_imsi("31026012345").has_value());
}

TEST(Imsi, EmptyImeiMeansNotReported) {
  const auto v = parse_imei("");
  REQUIRE(v.has_value());
  CHECK_EQ(*v, std::uint64_t{0});
}

TEST(Imsi, PlmnPacking) {
  CHECK_EQ(make_plmn(310, 260), 310260u);
  CHECK_EQ(plmn_mcc(310260), 310u);
  CHECK_EQ(plmn_mnc(310260), 260u);
  // A 2-digit MNC keeps its value, so 234-15 is 234015 and not 23415 — the
  // latter would silently mean MCC 23 / MNC 415.
  CHECK_EQ(make_plmn(234, 15), 234015u);
  CHECK_EQ(plmn_mcc(234015), 234u);
  CHECK_EQ(plmn_mnc(234015), 15u);
}

TEST(Imsi, PlmnParsingAcceptsTheSpellingsOperatorsUse) {
  CHECK_EQ(parse_plmn("310-260").value_or(0), 310260u);
  CHECK_EQ(parse_plmn("310260").value_or(0), 310260u);
  CHECK_EQ(parse_plmn("310/260").value_or(0), 310260u);
  CHECK_EQ(parse_plmn("234-15").value_or(0), 234015u);
  CHECK_EQ(parse_plmn("23415").value_or(0), 234015u);
  CHECK_EQ(parse_plmn("262-01").value_or(0), 262001u);
  CHECK(!parse_plmn("").has_value());
  CHECK(!parse_plmn("31-260").has_value());
  CHECK(!parse_plmn("abcdef").has_value());
}

TEST(Imsi, LuhnCheckDigit) {
  // Two published example IMEIs with valid check digits.
  CHECK(imei_luhn_valid(490154203237518ull));
  CHECK(imei_luhn_valid(356938035643809ull));
  // Flip the check digit.
  CHECK(!imei_luhn_valid(490154203237519ull));
  CHECK(!imei_luhn_valid(356938035643800ull));
}
