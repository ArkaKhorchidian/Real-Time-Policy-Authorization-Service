// The HTTP front: query parsing, JSON rendering, and the server driven end to
// end over a real socket with keep-alive.
//
// This path exists to put a number on protocol overhead, which means it has to
// be correct as well as fast — a comparison against a front that answers
// slightly wrong questions is worse than no comparison.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "policy/coarse_clock.hpp"
#include "policy/control_plane.hpp"
#include "policy/engine.hpp"
#include "policy/http_front.hpp"
#include "policy/imsi.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

std::unique_ptr<RuleSet> fixture_rules() {
  auto compiled = compile_rules_from_file("config/rules.yaml", 3);
  if (!compiled.ok()) {
    std::fprintf(stderr, "config/rules.yaml failed to compile: %s\n",
                 compiled.error_summary().c_str());
    std::abort();
  }
  return std::move(compiled.rule_set);
}

// A tiny keep-alive HTTP client: connect once, issue several requests.
class Client {
 public:
  bool connect(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    int one = 1;
    ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return ::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
  }

  ~Client() {
    if (fd_ >= 0) ::close(fd_);
  }

  // Returns the full response, or "" on timeout.
  std::string get(const std::string& target) {
    const std::string req =
        "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    if (::send(fd_, req.data(), req.size(), 0) != static_cast<ssize_t>(req.size())) return "";

    std::string resp;
    for (int i = 0; i < 200; ++i) {
      pollfd p{};
      p.fd = fd_;
      p.events = POLLIN;
      if (::poll(&p, 1, 50) <= 0) continue;
      char buf[4096];
      const ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
      if (n <= 0) break;
      resp.append(buf, static_cast<std::size_t>(n));
      const auto head_end = resp.find("\r\n\r\n");
      if (head_end == std::string::npos) continue;
      const auto cl = resp.find("Content-Length: ");
      if (cl == std::string::npos) break;
      const auto len = static_cast<std::size_t>(std::atoi(resp.c_str() + cl + 16));
      if (resp.size() >= head_end + 4 + len) break;
    }
    return resp;
  }

 private:
  int fd_ = -1;
};

int status_of(const std::string& r) { return r.size() > 12 ? std::atoi(r.c_str() + 9) : -1; }
std::string body_of(const std::string& r) {
  const auto p = r.find("\r\n\r\n");
  return p == std::string::npos ? "" : r.substr(p + 4);
}

ServerConfig front_config() {
  ServerConfig cfg;
  cfg.worker_threads = 2;
  cfg.rules_path = "config/rules.yaml";
  cfg.subscribers_path = "config/subscribers.csv";
  cfg.admin_port = 0;
  cfg.watch_rules_file = false;
  cfg.pin_workers = false;
  return cfg;
}

std::string first_imsi() {
  std::FILE* f = std::fopen("config/subscribers.csv", "r");
  if (f == nullptr) return "";
  char line[512];
  (void)std::fgets(line, sizeof(line), f);  // header
  if (std::fgets(line, sizeof(line), f) == nullptr) {
    std::fclose(f);
    return "";
  }
  std::fclose(f);
  const char* comma = std::strchr(line, ',');
  return comma == nullptr ? "" : std::string(line, static_cast<std::size_t>(comma - line));
}

}  // namespace

TEST(HttpFront, QueryParsingAcceptsWhatTheApiDocuments) {
  const auto rs = fixture_rules();
  PolicyRequest req;
  std::string error;

  REQUIRE(parse_decide_query(*rs, "imsi=310260100000001&dnn=internet&rat=NR", req, error));
  CHECK_EQ(req.imsi, 310260100000001ull);
  CHECK_EQ(req.dnn_id, std::uint8_t{0});
  CHECK_EQ(req.rat_type, static_cast<std::uint8_t>(RatType::kNr));

  // Every optional parameter.
  REQUIRE(parse_decide_query(
      *rs,
      "imsi=310260100000001&imei=350000000000018&plmn=310-260&dnn=ims&rat=LTE"
      "&qos_5qi=5&tac=1234&minute=180&usage=12345&tethering=1&emergency=1&seq=7",
      req, error));
  CHECK_EQ(req.imei, 350000000000018ull);
  CHECK_EQ(req.plmn, 310260u);
  CHECK_EQ(req.dnn_id, std::uint8_t{1});
  CHECK_EQ(req.rat_type, static_cast<std::uint8_t>(RatType::kLte));
  CHECK_EQ(req.requested_5qi, std::uint8_t{5});
  CHECK_EQ(req.tac, std::uint16_t{1234});
  CHECK_EQ(req.local_minute, std::uint16_t{180});
  CHECK_EQ(req.bytes_used_period, std::uint64_t{12345});
  CHECK((req.flags & kReqFlagUsageValid) != 0);
  CHECK((req.flags & kReqFlagTetheringDetected) != 0);
  CHECK((req.flags & kReqFlagEmergency) != 0);
  CHECK_EQ(req.seq, 7u);

  // A DNN index is accepted as well as a name, for machine-generated clients.
  REQUIRE(parse_decide_query(*rs, "imsi=310260100000001&dnn=2", req, error));
  CHECK_EQ(req.dnn_id, std::uint8_t{2});
}

TEST(HttpFront, QueryParsingRejectsRatherThanGuessing) {
  const auto rs = fixture_rules();
  PolicyRequest req;
  std::string error;

  // A missing IMSI must not become a decision about subscriber zero.
  CHECK(!parse_decide_query(*rs, "dnn=internet", req, error));
  CHECK_MSG(error.find("imsi") != std::string::npos, error);

  // An unknown parameter is an error, not something to ignore: silently
  // dropping "usaage=..." would answer a different question than was asked.
  CHECK(!parse_decide_query(*rs, "imsi=310260100000001&usaage=5", req, error));
  CHECK(!parse_decide_query(*rs, "imsi=notdigits", req, error));
  CHECK(!parse_decide_query(*rs, "imsi=310260100000001&dnn=nosuch", req, error));
  CHECK(!parse_decide_query(*rs, "imsi=310260100000001&rat=6G", req, error));
  CHECK(!parse_decide_query(*rs, "imsi=310260100000001&qos_5qi=0", req, error));
  CHECK(!parse_decide_query(*rs, "imsi=310260100000001&qos_5qi=999", req, error));
  CHECK(!parse_decide_query(*rs, "imsi=310260100000001&minute=1440", req, error));
  CHECK(!parse_decide_query(*rs, "imsi=310260100000001&plmn=31-260", req, error));
}

TEST(HttpFront, JsonRenderingIsCompleteAndBounded) {
  const auto rs = fixture_rules();
  PolicyDecision d{};
  d.magic_version = kMagicVersion;
  d.verdict = static_cast<std::uint8_t>(Verdict::kRedirect);
  d.reason = static_cast<std::uint8_t>(Reason::kQuotaExhausted);
  d.rule_id = 63;
  d.policy_version = 3;
  d.qos_5qi = 9;
  d.arp = 15;
  d.ambr_ul_kbps = 64;
  d.ambr_dl_kbps = 128;
  d.rating_group = 0;
  d.quota_bytes = 10'000'000;
  d.quota_validity_s = 900;
  d.flags = kFlagThrottled;
  d.redirect_id = 1;

  char buf[1024];
  const std::size_t n = decision_to_json(d, buf, sizeof(buf));
  REQUIRE(n > 0);
  const std::string json(buf, n);
  for (const char* needle : {"\"verdict\":\"REDIRECT\"", "\"reason\":\"QUOTA_EXHAUSTED\"",
                             "\"rule_id\":63", "\"policy_version\":3", "\"qos_5qi\":9",
                             "\"arp\":15", "\"ambr_dl_kbps\":128", "\"quota_bytes\":10000000",
                             "\"quota_validity_s\":900"}) {
    CHECK_MSG(json.find(needle) != std::string::npos, std::string("missing ") + needle);
  }

  // A buffer too small must report failure rather than emit a truncated
  // document that a client would fail to parse in a confusing way.
  char small[16];
  CHECK_EQ(decision_to_json(d, small, sizeof(small)), std::size_t{0});
}

TEST(HttpFront, ServesDecisionsOverKeepAliveConnections) {
  ControlPlane cp(front_config());
  std::string error;
  REQUIRE_MSG(cp.initialize(error), error);
  set_coarse_now_unix_s(kGoldenClockUnixS);

  ServerDeps deps;
  deps.rules = &cp.rules();
  deps.store = &cp.store();
  deps.metrics = &cp.metrics();

  HttpFrontServer front(front_config(), deps, "127.0.0.1", 0);
  REQUIRE_MSG(front.start(error), error);
  const std::uint16_t port = front.bound_port();
  REQUIRE(port != 0);

  const std::string imsi = first_imsi();
  REQUIRE(!imsi.empty());

  Client c;
  REQUIRE(c.connect(port));

  // Several requests down one connection — the point of keep-alive, and the
  // thing that makes the protocol-overhead comparison fair.
  for (int i = 0; i < 25; ++i) {
    const std::string r = c.get("/v1/decide?imsi=" + imsi + "&dnn=internet&rat=NR");
    REQUIRE_MSG(!r.empty(), "no response on request " + std::to_string(i));
    CHECK_EQ(status_of(r), 200);
    const std::string body = body_of(r);
    CHECK_MSG(body.find("\"verdict\"") != std::string::npos, body);
    CHECK_MSG(body.find("\"policy_version\":1") != std::string::npos, body);
    CHECK_MSG(body.find("\"rule_id\"") != std::string::npos, body);
  }

  const auto stats = front.snapshot();
  CHECK_GE(stats.requests, std::uint64_t{25});
  CHECK_EQ(stats.bad_requests, std::uint64_t{0});
  CHECK_GT(stats.service_ns.total_count(), std::int64_t{0});

  front.request_stop();
  front.join();
}

TEST(HttpFront, AgreesWithTheBinaryPathDecisionForDecision) {
  // The whole point of measuring protocol overhead is that both paths answer
  // the same question. If they diverge, the comparison is meaningless.
  ControlPlane cp(front_config());
  std::string error;
  REQUIRE_MSG(cp.initialize(error), error);
  set_coarse_now_unix_s(kGoldenClockUnixS);

  ServerDeps deps;
  deps.rules = &cp.rules();
  deps.store = &cp.store();
  deps.metrics = &cp.metrics();

  HttpFrontServer front(front_config(), deps, "127.0.0.1", 0);
  REQUIRE_MSG(front.start(error), error);

  Client c;
  REQUIRE(c.connect(front.bound_port()));

  const auto guard = cp.rules().read(0);
  REQUIRE(guard.get() != nullptr);

  int compared = 0;
  cp.store().for_each([&](const SubscriberRecord& rec) {
    if (compared >= 40) return;
    for (const std::uint8_t dnn : {std::uint8_t{0}, std::uint8_t{1}}) {
      char target[256];
      std::snprintf(target, sizeof(target), "/v1/decide?imsi=%s&dnn=%u&rat=1&minute=720",
                    format_imsi(rec.imsi).c_str(), dnn);
      const std::string r = c.get(target);
      if (r.empty()) continue;

      PolicyRequest req{};
      req.magic_version = kMagicVersion;
      req.imsi = rec.imsi;
      req.dnn_id = dnn;
      req.rat_type = 1;
      req.requested_5qi = 9;
      req.local_minute = 720;
      req.plmn = rec.home_plmn;
      const PolicyDecision expected = evaluate(*guard, req, &rec);

      char want[1024];
      const std::size_t n = decision_to_json(expected, want, sizeof(want));
      REQUIRE(n > 0);
      CHECK_MSG(body_of(r) == std::string(want, n),
                "HTTP and binary paths disagree for IMSI " + format_imsi(rec.imsi) +
                    "\n      http:   " + body_of(r) + "      binary: " + std::string(want, n));
      ++compared;
    }
  });
  CHECK_GT(compared, 20);

  front.request_stop();
  front.join();
}

TEST(HttpFront, ErrorsAreDiagnosable) {
  ControlPlane cp(front_config());
  std::string error;
  REQUIRE_MSG(cp.initialize(error), error);

  ServerDeps deps;
  deps.rules = &cp.rules();
  deps.store = &cp.store();
  deps.metrics = &cp.metrics();

  HttpFrontServer front(front_config(), deps, "127.0.0.1", 0);
  REQUIRE_MSG(front.start(error), error);

  Client c;
  REQUIRE(c.connect(front.bound_port()));

  const std::string missing = c.get("/v1/decide");
  CHECK_EQ(status_of(missing), 400);
  CHECK_MSG(body_of(missing).find("imsi") != std::string::npos, body_of(missing));

  const std::string bad = c.get("/v1/decide?imsi=310260100000001&dnn=nosuch");
  CHECK_EQ(status_of(bad), 400);

  const std::string nowhere = c.get("/v1/nope");
  CHECK_EQ(status_of(nowhere), 404);

  // An unprovisioned IMSI is a policy outcome, not an HTTP error.
  const std::string unknown = c.get("/v1/decide?imsi=999999999999999");
  CHECK_EQ(status_of(unknown), 200);
  CHECK_MSG(body_of(unknown).find("UNKNOWN_SUBSCRIBER") != std::string::npos, body_of(unknown));

  const auto stats = front.snapshot();
  CHECK_GE(stats.bad_requests, std::uint64_t{2});
  CHECK_GE(stats.not_found, std::uint64_t{1});

  front.request_stop();
  front.join();
}
