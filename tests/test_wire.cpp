// Wire format: layout, round-tripping, and rejection of everything that is not
// a well-formed 64-byte message.
#include <cstring>
#include <random>

#include "policy/wire.hpp"
#include "test_framework.hpp"

using namespace policy;

TEST(Wire, MessagesAreExactlyOneCacheLine) {
  // These are static_asserts in the header too; repeating them here means a
  // failure names the reason rather than just a line number.
  CHECK_EQ(sizeof(PolicyRequest), std::size_t{64});
  CHECK_EQ(sizeof(PolicyDecision), std::size_t{64});
  CHECK_EQ(alignof(PolicyRequest), std::size_t{64});
  CHECK_EQ(alignof(PolicyDecision), std::size_t{64});
}

TEST(Wire, FieldOffsetsAreStable) {
  // The wire format is a contract with every client. If one of these moves, a
  // deployed serving node starts reading the wrong bytes and the failure is
  // silent — a plausible-looking decision built from garbage.
  CHECK_EQ(offsetof(PolicyRequest, magic_version), std::size_t{0});
  CHECK_EQ(offsetof(PolicyRequest, seq), std::size_t{4});
  CHECK_EQ(offsetof(PolicyRequest, imsi), std::size_t{8});
  CHECK_EQ(offsetof(PolicyRequest, imei), std::size_t{16});
  CHECK_EQ(offsetof(PolicyRequest, client_ts_ns), std::size_t{24});
  CHECK_EQ(offsetof(PolicyRequest, bytes_used_period), std::size_t{32});
  CHECK_EQ(offsetof(PolicyRequest, plmn), std::size_t{40});
  CHECK_EQ(offsetof(PolicyRequest, tac), std::size_t{44});
  CHECK_EQ(offsetof(PolicyRequest, rat_type), std::size_t{46});
  CHECK_EQ(offsetof(PolicyRequest, dnn_id), std::size_t{47});
  CHECK_EQ(offsetof(PolicyRequest, requested_5qi), std::size_t{48});
  CHECK_EQ(offsetof(PolicyRequest, flags), std::size_t{49});
  CHECK_EQ(offsetof(PolicyRequest, local_minute), std::size_t{50});
  CHECK_EQ(offsetof(PolicyRequest, req_ambr_ul_kbps), std::size_t{52});
  CHECK_EQ(offsetof(PolicyRequest, req_ambr_dl_kbps), std::size_t{56});

  CHECK_EQ(offsetof(PolicyDecision, client_ts_ns), std::size_t{8});
  CHECK_EQ(offsetof(PolicyDecision, quota_bytes), std::size_t{16});
  CHECK_EQ(offsetof(PolicyDecision, ambr_ul_kbps), std::size_t{24});
  CHECK_EQ(offsetof(PolicyDecision, rule_id), std::size_t{40});
  CHECK_EQ(offsetof(PolicyDecision, policy_version), std::size_t{44});
  CHECK_EQ(offsetof(PolicyDecision, verdict), std::size_t{48});
  CHECK_EQ(offsetof(PolicyDecision, server_ts_ns), std::size_t{56});
}

TEST(Wire, RequestRoundTrips) {
  std::mt19937_64 rng(12345);
  for (int i = 0; i < 1000; ++i) {
    PolicyRequest in{};
    // Fill every byte with noise, then fix up the magic, so a field the encoder
    // forgets shows up as a mismatch rather than as two matching zeros.
    auto* raw = reinterpret_cast<std::uint8_t*>(&in);
    for (std::size_t b = 0; b < sizeof(in); ++b) raw[b] = static_cast<std::uint8_t>(rng());
    in.magic_version = kMagicVersion;
    in.reserved = 0;

    alignas(64) char buf[kWireMsgSize];
    encode(in, buf);
    PolicyRequest out{};
    REQUIRE(decode(buf, sizeof(buf), out));
    CHECK_EQ(std::memcmp(&in, &out, sizeof(in)), 0);
  }
}

TEST(Wire, DecisionRoundTrips) {
  std::mt19937_64 rng(54321);
  for (int i = 0; i < 1000; ++i) {
    PolicyDecision in{};
    auto* raw = reinterpret_cast<std::uint8_t*>(&in);
    for (std::size_t b = 0; b < sizeof(in); ++b) raw[b] = static_cast<std::uint8_t>(rng());
    in.magic_version = kMagicVersion;
    in.reserved = 0;

    alignas(64) char buf[kWireMsgSize];
    encode(in, buf);
    PolicyDecision out{};
    REQUIRE(decode(buf, sizeof(buf), out));
    CHECK_EQ(std::memcmp(&in, &out, sizeof(in)), 0);
  }
}

TEST(Wire, DecodeRejectsWrongLength) {
  PolicyRequest req{};
  req.magic_version = kMagicVersion;
  alignas(64) char buf[128] = {};
  encode(req, buf);

  PolicyRequest out{};
  CHECK(!decode(buf, 0, out));
  CHECK(!decode(buf, 63, out));
  CHECK(!decode(buf, 65, out));
  CHECK(!decode(buf, 128, out));
  CHECK(decode(buf, 64, out));
}

TEST(Wire, DecodeRejectsUnknownMagicAndVersion) {
  PolicyRequest req{};
  req.magic_version = kMagicVersion;
  alignas(64) char buf[kWireMsgSize];

  encode(req, buf);
  PolicyRequest out{};
  CHECK(decode(buf, sizeof(buf), out));

  // Wrong protocol entirely.
  req.magic_version = 0xDEADBEEF;
  encode(req, buf);
  CHECK(!decode(buf, sizeof(buf), out));

  // Right protocol, future version. Must be rejected, not best-effort parsed:
  // a v2 layout read as v1 produces a plausible decision from wrong fields.
  req.magic_version = kMagicBase | 2u;
  encode(req, buf);
  CHECK(!decode(buf, sizeof(buf), out));

  // Right protocol, older version.
  req.magic_version = kMagicBase | 0u;
  encode(req, buf);
  CHECK(!decode(buf, sizeof(buf), out));
}

TEST(Wire, EncodeDoesNotRequireAlignedOutput) {
  // The receive buffer is a byte array at an arbitrary offset within a batch,
  // so encode/decode must not assume 64-byte alignment on the wire side.
  PolicyDecision d{};
  d.magic_version = kMagicVersion;
  d.seq = 0x11223344;
  d.quota_bytes = 0x0102030405060708ull;

  char raw[kWireMsgSize + 8];
  char* unaligned = raw + 3;
  encode(d, unaligned);
  PolicyDecision out{};
  REQUIRE(decode(unaligned, kWireMsgSize, out));
  CHECK_EQ(out.seq, d.seq);
  CHECK_EQ(out.quota_bytes, d.quota_bytes);
}

TEST(Wire, SwapEndiannessIsSelfInverse) {
  PolicyRequest a{};
  a.magic_version = kMagicVersion;
  a.imsi = 310260123456789ull;
  a.plmn = 310260;
  a.tac = 0x1234;
  a.local_minute = 1439;
  const PolicyRequest original = a;

  swap_endianness(a);
  swap_endianness(a);
  CHECK_EQ(std::memcmp(&a, &original, sizeof(a)), 0);
}

TEST(Wire, ReasonAndVerdictNamesCoverEveryValue) {
  // A reason code with no name means a dashboard shows "INVALID" for a real
  // decision, which is exactly when someone is trying to debug an outage.
  for (int i = 0; i < static_cast<int>(Reason::kCount); ++i) {
    const char* name = reason_name(static_cast<Reason>(i));
    CHECK_MSG(std::strcmp(name, "INVALID") != 0,
              "reason code " + std::to_string(i) + " has no name");
  }
  CHECK_EQ(std::string(verdict_name(Verdict::kAllow)), std::string("ALLOW"));
  CHECK_EQ(std::string(verdict_name(Verdict::kDeny)), std::string("DENY"));
  CHECK_EQ(std::string(verdict_name(Verdict::kRedirect)), std::string("REDIRECT"));
}
