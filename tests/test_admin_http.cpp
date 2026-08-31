// The admin HTTP layer: request parsing, routing, and the control plane's
// handlers driven end to end over a real socket.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include "policy/admin_http.hpp"
#include "policy/control_plane.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

// Minimal blocking HTTP client — enough to drive the admin server.
std::string http_request(std::uint16_t port, const std::string& method, const std::string& target,
                         const std::string& body = "") {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return "";
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return "";
  }

  std::string req = method + " " + target + " HTTP/1.1\r\nHost: localhost\r\n";
  req += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
  ::send(fd, req.data(), req.size(), 0);

  std::string response;
  char buf[8192];
  for (;;) {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) break;
    response.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return response;
}

int status_of(const std::string& response) {
  if (response.size() < 12) return -1;
  return std::atoi(response.c_str() + 9);
}

std::string body_of(const std::string& response) {
  const auto pos = response.find("\r\n\r\n");
  return pos == std::string::npos ? "" : response.substr(pos + 4);
}

ServerConfig test_config() {
  ServerConfig cfg;
  cfg.worker_threads = 2;
  cfg.rules_path = "config/rules.yaml";
  cfg.subscribers_path = "config/subscribers.csv";
  cfg.admin_bind_address = "127.0.0.1";
  cfg.admin_port = 0;  // let the kernel choose, so tests never collide
  cfg.watch_rules_file = false;
  cfg.pin_workers = false;
  return cfg;
}

}  // namespace

TEST(AdminHttp, UrlDecoding) {
  CHECK_EQ(url_decode("plain"), std::string("plain"));
  CHECK_EQ(url_decode("a%20b"), std::string("a b"));
  CHECK_EQ(url_decode("a+b"), std::string("a b"));
  CHECK_EQ(url_decode("%2Fsubscriber%2F1"), std::string("/subscriber/1"));
  CHECK_EQ(url_decode("100%25"), std::string("100%"));
  // A malformed escape is left alone rather than dropped.
  CHECK_EQ(url_decode("%zz"), std::string("%zz"));
  CHECK_EQ(url_decode("trailing%"), std::string("trailing%"));
}

TEST(AdminHttp, RoutingAndErrorCodes) {
  AdminHttpServer http("127.0.0.1", 0);
  http.route("GET", "/thing", [](const HttpRequest&) { return HttpResponse::text("thing\n"); });
  http.route("POST", "/action", [](const HttpRequest& r) {
    return HttpResponse::text("got " + std::to_string(r.body.size()) + " bytes\n");
  });
  http.route_prefix("GET", "/items/", [](const HttpRequest& r) {
    return HttpResponse::text("item " + r.path.substr(std::strlen("/items/")) + "\n");
  });

  std::string error;
  REQUIRE(http.start(error));
  const std::uint16_t port = http.bound_port();
  REQUIRE(port != 0);

  CHECK_EQ(status_of(http_request(port, "GET", "/thing")), 200);
  CHECK_EQ(body_of(http_request(port, "GET", "/thing")), std::string("thing\n"));
  CHECK_EQ(body_of(http_request(port, "POST", "/action", "hello")), std::string("got 5 bytes\n"));
  CHECK_EQ(body_of(http_request(port, "GET", "/items/42")), std::string("item 42\n"));
  CHECK_EQ(status_of(http_request(port, "GET", "/nope")), 404);
  // A real path with the wrong method is a client bug, not a typo, and gets a
  // different code so it is diagnosable.
  CHECK_EQ(status_of(http_request(port, "POST", "/thing")), 405);

  http.stop();
}

TEST(AdminHttp, QueryParametersAreParsedAndDecoded) {
  AdminHttpServer http("127.0.0.1", 0);
  http.route("GET", "/echo", [](const HttpRequest& r) {
    std::string out;
    for (const auto& [k, v] : r.query) out += k + "=" + v + ";";
    return HttpResponse::text(out);
  });
  std::string error;
  REQUIRE(http.start(error));
  const auto body = body_of(http_request(http.bound_port(), "GET", "/echo?a=1&b=two%20words&c="));
  CHECK_EQ(body, std::string("a=1;b=two words;c=;"));
  http.stop();
}

TEST(AdminHttp, ControlPlaneEndpoints) {
  ControlPlane cp(test_config());
  std::string error;
  REQUIRE_MSG(cp.initialize(error), error);

  AdminHttpServer http("127.0.0.1", 0);
  cp.set_ingest_description("test-harness");
  cp.register_routes(http, "test-harness");
  REQUIRE(http.start(error));
  const std::uint16_t port = http.bound_port();

  // /healthz
  CHECK_EQ(status_of(http_request(port, "GET", "/healthz")), 200);

  // /metrics — Prometheus text format with the counters a dashboard needs.
  const std::string metrics = body_of(http_request(port, "GET", "/metrics"));
  CHECK_MSG(metrics.find("# TYPE policy_requests_total counter") != std::string::npos,
            "metrics missing policy_requests_total");
  CHECK_MSG(metrics.find("policy_rules_version") != std::string::npos,
            "metrics missing policy_rules_version");
  CHECK_MSG(metrics.find("policy_subscribers ") != std::string::npos,
            "metrics missing policy_subscribers");
  CHECK_MSG(metrics.find("policy_service_time_ns{quantile=\"0.99\"}") != std::string::npos,
            "metrics missing the service-time summary");

  // /stats
  const std::string stats = body_of(http_request(port, "GET", "/stats"));
  CHECK_MSG(stats.find("\"policy_version\": 1") != std::string::npos, stats);
  CHECK_MSG(stats.find("\"ingest\": \"test-harness\"") != std::string::npos, stats);

  // /rules
  const std::string rules = body_of(http_request(port, "GET", "/rules"));
  CHECK_MSG(rules.find("\"sha256\"") != std::string::npos, "rules missing the source fingerprint");
  CHECK_MSG(rules.find("\"compiled_rules\"") != std::string::npos, rules);
  CHECK_MSG(rules.find("dev-basic") != std::string::npos, "rules missing the plan table");

  // /subscriber/{imsi}
  const std::string first_imsi = "310260100000000";
  const std::string sub = http_request(port, "GET", "/subscriber/" + first_imsi);
  CHECK_EQ(status_of(sub), 200);
  CHECK_MSG(body_of(sub).find(first_imsi) != std::string::npos, body_of(sub));
  CHECK_EQ(status_of(http_request(port, "GET", "/subscriber/999999999999999")), 404);
  CHECK_EQ(status_of(http_request(port, "GET", "/subscriber/notanimsi")), 400);

  // /explain — the decoded feature word and the rule that fired.
  const std::string explain =
      body_of(http_request(port, "GET", "/explain?imsi=" + first_imsi + "&dnn=internet&rat=1"));
  CHECK_MSG(explain.find("\"features_decoded\"") != std::string::npos, explain);
  CHECK_MSG(explain.find("\"rule_id\"") != std::string::npos, explain);
  CHECK_MSG(explain.find("\"verdict\"") != std::string::npos, explain);
  CHECK_EQ(status_of(http_request(port, "GET", "/explain")), 400);
  CHECK_EQ(status_of(http_request(port, "GET", "/explain?imsi=" + first_imsi + "&dnn=nosuch")), 400);

  // /rules/reload — the file has not changed, so this is a clean no-op reload
  // that still advances the policy version.
  const std::string reload = http_request(port, "POST", "/rules/reload");
  CHECK_EQ(status_of(reload), 200);
  CHECK_MSG(body_of(reload).find("\"version\": 2") != std::string::npos, body_of(reload));
  CHECK_EQ(cp.reload_stats().successes, std::uint64_t{2});
  CHECK_EQ(cp.reload_stats().failures, std::uint64_t{0});

  http.stop();
}

TEST(AdminHttp, ReloadOfABrokenFileKeepsTheLivePolicy) {
  // A bad edit must never take the policy offline.
  const std::string rules_copy = "test_admin_rules.yaml";
  {
    std::FILE* in = std::fopen("config/rules.yaml", "rb");
    REQUIRE(in != nullptr);
    std::FILE* out = std::fopen(rules_copy.c_str(), "wb");
    REQUIRE(out != nullptr);
    char buf[8192];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), in)) > 0) std::fwrite(buf, 1, n, out);
    std::fclose(in);
    std::fclose(out);
  }

  ServerConfig cfg = test_config();
  cfg.rules_path = rules_copy;
  ControlPlane cp(cfg);
  std::string error;
  REQUIRE_MSG(cp.initialize(error), error);
  const std::uint32_t live_version = cp.reload_stats().current_version;

  // Break the file.
  {
    std::FILE* f = std::fopen(rules_copy.c_str(), "a");
    REQUIRE(f != nullptr);
    std::fputs("\n  - id: 999\n    priority: 1\n    when: {nosuch: true}\n    action: {verdict: ALLOW}\n", f);
    std::fclose(f);
  }

  std::string reload_error;
  CHECK(!cp.reload_rules(reload_error));
  CHECK_MSG(!reload_error.empty(), "a failed reload must explain why");
  CHECK_EQ(cp.reload_stats().failures, std::uint64_t{1});

  // The previous policy is still live and still answering.
  const auto guard = cp.rules().read(0);
  REQUIRE(guard.get() != nullptr);
  CHECK_EQ(guard->version, live_version);
  CHECK_GT(guard->rules.size(), std::size_t{0});

  std::remove(rules_copy.c_str());
}

TEST(AdminHttp, ReloadThatRenamesAPlanIsRefused) {
  // Subscriber records hold plan ids. Renaming or reordering a plan changes
  // what those ids mean, so it needs a restart, not a hot swap — and silently
  // accepting it would move every affected subscriber onto a different tariff.
  const std::string rules_copy = "test_admin_planshift.yaml";
  {
    std::FILE* out = std::fopen(rules_copy.c_str(), "w");
    REQUIRE(out != nullptr);
    std::fputs(
        "dnns: [internet]\n"
        "plans:\n"
        "  - name: alpha\n    qos_5qi: 9\n    arp: 8\n    ambr_ul: 1Mbps\n    ambr_dl: 1Mbps\n"
        "  - name: beta\n    qos_5qi: 8\n    arp: 5\n    ambr_ul: 2Mbps\n    ambr_dl: 2Mbps\n"
        "rules:\n"
        "  - id: 1\n    priority: 1\n    when: {status: ACTIVE}\n"
        "    action: {verdict: ALLOW, inherit: all}\n",
        out);
    std::fclose(out);
  }

  ServerConfig cfg = test_config();
  cfg.rules_path = rules_copy;
  cfg.subscribers_path = "";
  ControlPlane cp(cfg);
  std::string error;
  REQUIRE_MSG(cp.initialize(error), error);

  // Swap the two plans around.
  {
    std::FILE* out = std::fopen(rules_copy.c_str(), "w");
    REQUIRE(out != nullptr);
    std::fputs(
        "dnns: [internet]\n"
        "plans:\n"
        "  - name: beta\n    qos_5qi: 8\n    arp: 5\n    ambr_ul: 2Mbps\n    ambr_dl: 2Mbps\n"
        "  - name: alpha\n    qos_5qi: 9\n    arp: 8\n    ambr_ul: 1Mbps\n    ambr_dl: 1Mbps\n"
        "rules:\n"
        "  - id: 1\n    priority: 1\n    when: {status: ACTIVE}\n"
        "    action: {verdict: ALLOW, inherit: all}\n",
        out);
    std::fclose(out);
  }

  std::string reload_error;
  CHECK(!cp.reload_rules(reload_error));
  CHECK_MSG(reload_error.find("restart") != std::string::npos,
            "the error should say a restart is needed: " + reload_error);

  std::remove(rules_copy.c_str());
}
