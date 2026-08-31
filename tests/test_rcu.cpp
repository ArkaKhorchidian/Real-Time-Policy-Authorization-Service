// The RCU snapshot mechanism: correctness under concurrent readers, and the
// grace-period guarantee that makes reclamation safe.
#include <atomic>
#include <thread>
#include <vector>

#include "policy/rcu.hpp"
#include "test_framework.hpp"

using namespace policy;

namespace {

// A payload that notices its own destruction, so a use-after-free shows up as a
// deterministic assertion rather than as an occasional crash.
struct Payload {
  explicit Payload(int v) : value(v) { ++live(); }
  ~Payload() {
    magic = 0xDEAD;
    --live();
  }
  static std::atomic<int>& live() {
    static std::atomic<int> n{0};
    return n;
  }
  int value;
  std::uint32_t magic = 0xF00D;
};

}  // namespace

TEST(Rcu, ReaderSlotIsCacheLineIsolated) {
  // Two readers sharing a line would write-invalidate each other on every
  // request, which is the entire cost this design exists to avoid.
  CHECK_EQ(sizeof(ReaderSlot), kCacheLine);
  CHECK_EQ(alignof(ReaderSlot), kCacheLine);
}

TEST(Rcu, PublishAndRead) {
  RcuDomain<Payload> domain(4);
  const std::size_t slot = domain.register_reader();
  REQUIRE(slot != static_cast<std::size_t>(-1));

  {
    const auto guard = domain.read(slot);
    CHECK(guard.get() == nullptr);  // nothing published yet
  }

  CHECK(domain.swap_and_reclaim(std::make_unique<Payload>(1)));
  {
    const auto guard = domain.read(slot);
    REQUIRE(guard.get() != nullptr);
    CHECK_EQ(guard->value, 1);
  }

  CHECK(domain.swap_and_reclaim(std::make_unique<Payload>(2)));
  {
    const auto guard = domain.read(slot);
    CHECK_EQ(guard->value, 2);
  }
  domain.unregister_reader(slot);
}

TEST(Rcu, ReaderSlotsAreExclusive) {
  RcuDomain<Payload> domain(3);
  const auto a = domain.register_reader();
  const auto b = domain.register_reader();
  const auto c = domain.register_reader();
  CHECK_NE(a, b);
  CHECK_NE(b, c);
  CHECK_NE(a, c);
  // Out of slots.
  CHECK_EQ(domain.register_reader(), static_cast<std::size_t>(-1));

  domain.unregister_reader(b);
  const auto reused = domain.register_reader();
  CHECK_EQ(reused, b);
}

TEST(Rcu, NoSnapshotIsFreedWhileAReaderHoldsIt) {
  // The load-bearing property. Readers spin on the snapshot for the whole run
  // while the writer swaps continuously; if reclamation were premature, the
  // magic check below would fail (and ASan would fire in the sanitizer build).
  constexpr int kReaders = 4;
  constexpr int kSwaps = 500;

  RcuDomain<Payload> domain(kReaders);
  domain.publish(std::make_unique<Payload>(0));

  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> reads{0};
  std::atomic<int> corruption{0};
  std::vector<std::thread> readers;

  for (int i = 0; i < kReaders; ++i) {
    readers.emplace_back([&] {
      const std::size_t slot = domain.register_reader();
      while (!stop.load(std::memory_order_relaxed)) {
        const auto guard = domain.read(slot);
        if (guard.get() == nullptr) continue;
        // Read the payload repeatedly inside the critical section, so a
        // premature free has many chances to be observed.
        for (int k = 0; k < 32; ++k) {
          if (guard->magic != 0xF00D) {
            corruption.fetch_add(1, std::memory_order_relaxed);
            break;
          }
        }
        reads.fetch_add(1, std::memory_order_relaxed);
      }
      domain.unregister_reader(slot);
    });
  }

  for (int i = 1; i <= kSwaps; ++i) {
    CHECK_MSG(domain.swap_and_reclaim(std::make_unique<Payload>(i)),
              "grace period timed out on swap " + std::to_string(i));
  }
  stop.store(true, std::memory_order_relaxed);
  for (auto& t : readers) t.join();

  CHECK_EQ(corruption.load(), 0);
  CHECK_GT(reads.load(), std::uint64_t{1000});

  // Every snapshot but the live one must have been reclaimed.
  CHECK_EQ(domain.deferred_retire_count(), std::size_t{0});
  CHECK_EQ(Payload::live().load(), 1);
}

TEST(Rcu, ReadersAlwaysSeeAValidVersionAcrossSwaps) {
  // Versions must move forward and never go backwards or skip into garbage —
  // this is what lets a decision's policy_version be trusted.
  RcuDomain<Payload> domain(2);
  domain.publish(std::make_unique<Payload>(1));

  std::atomic<bool> stop{false};
  std::atomic<int> regressions{0};

  std::thread reader([&] {
    const std::size_t slot = domain.register_reader();
    int last = 0;
    while (!stop.load(std::memory_order_relaxed)) {
      const auto guard = domain.read(slot);
      if (guard.get() == nullptr) continue;
      const int v = guard->value;
      if (v < last) regressions.fetch_add(1, std::memory_order_relaxed);
      last = v;
    }
    domain.unregister_reader(slot);
  });

  for (int i = 2; i <= 300; ++i) domain.swap_and_reclaim(std::make_unique<Payload>(i));
  stop.store(true, std::memory_order_relaxed);
  reader.join();

  CHECK_EQ(regressions.load(), 0);
}

TEST(Rcu, EverythingIsFreedWhenTheDomainDies) {
  const int before = Payload::live().load();
  {
    RcuDomain<Payload> domain(2);
    domain.publish(std::make_unique<Payload>(1));
    domain.swap_and_reclaim(std::make_unique<Payload>(2));
  }
  CHECK_EQ(Payload::live().load(), before);
}

TEST(Rcu, SynchronizeReturnsPromptlyWithNoActiveReaders) {
  RcuDomain<Payload> domain(8);
  domain.publish(std::make_unique<Payload>(1));
  const auto t0 = std::chrono::steady_clock::now();
  CHECK(domain.synchronize(std::chrono::milliseconds(500)));
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  CHECK_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),
           std::int64_t{100});
}
