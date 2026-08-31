// The worker fleet.
//
// One thread per core, each owning its socket (Linux) and its metrics block.
// Workers share exactly two things: an immutable RuleSet snapshot read through
// RCU, and a read-only SubscriberStore. There is no lock anywhere on the
// request path.
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "policy/config.hpp"
#include "policy/metrics.hpp"
#include "policy/net.hpp"
#include "policy/rcu.hpp"
#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"

namespace policy {

// Everything a worker needs, passed by reference. Nothing here is owned by the
// server: the control plane outlives it.
struct ServerDeps {
  RcuDomain<RuleSet>* rules = nullptr;
  const SubscriberStore* store = nullptr;
  MetricsRegistry* metrics = nullptr;
};

// Common interface so the ingest backend is a runtime choice and the control
// plane does not care which one is live.
class IngestServer {
 public:
  virtual ~IngestServer() = default;

  // Bind sockets and start workers. On failure nothing is left running.
  [[nodiscard]] virtual bool start(std::string& error) = 0;

  // Ask workers to finish the current batch and exit.
  virtual void request_stop() = 0;
  virtual void join() = 0;
  [[nodiscard]] virtual bool running() const = 0;

  // Description of the ingest path actually in use, for the run banner and for
  // benchmark metadata. Never a guess — it reflects compile-time detection and
  // the runtime fallbacks that actually fired.
  [[nodiscard]] virtual std::string ingest_description() const = 0;
};

// Socket backend: recvmmsg/sendmmsg on Linux, a recvfrom/sendto loop elsewhere.
class UdpServer final : public IngestServer {
 public:
  UdpServer(const ServerConfig& cfg, ServerDeps deps);
  ~UdpServer() override;

  UdpServer(const UdpServer&) = delete;
  UdpServer& operator=(const UdpServer&) = delete;

  [[nodiscard]] bool start(std::string& error) override;
  void request_stop() override;
  void join() override;
  [[nodiscard]] bool running() const override { return running_.load(std::memory_order_acquire); }
  [[nodiscard]] std::string ingest_description() const override;

 private:
  void worker_loop(std::size_t worker_index, int fd);

  ServerConfig cfg_;
  ServerDeps deps_;
  std::vector<Socket> sockets_;
  std::vector<std::thread> threads_;
  std::atomic<bool> stop_{false};
  std::atomic<bool> running_{false};
};

// True when this binary contains a usable io_uring backend.
[[nodiscard]] bool io_uring_available();

// Build the backend named in the config. Falls back to the socket path with a
// warning if io_uring was requested but is not available, rather than refusing
// to start — a benchmark script that sweeps backends should record "fell back"
// rather than die.
[[nodiscard]] std::unique_ptr<IngestServer> make_server(const ServerConfig& cfg, ServerDeps deps,
                                                        std::string& error);

}  // namespace policy
