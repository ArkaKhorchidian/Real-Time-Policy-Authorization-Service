// RCU-style snapshot publication for the rule set.
//
// The read side must cost one acquire load and nothing else — no mutex, no
// reference-count increment, no shared cache line written per request. Writers
// (the control plane, at most a few times a minute) may do arbitrary work.
//
// The scheme is classic quiescent-state-based reclamation:
//
//   reader:  slot.epoch.store(global_epoch, release)   // enter
//            ptr = current.load(acquire)               // snapshot
//            ... use ptr ...
//            slot.epoch.store(kQuiescent, release)     // leave
//
//   writer:  current.store(new_ptr, release)
//            global_epoch += 1
//            wait until every slot is either quiescent or at the new epoch
//            delete old_ptr
//
// Each reader slot sits on its own cache line, so a reader's epoch store never
// invalidates another core's line. The store is to a line that core already
// owns exclusively, which on the measured path is under a nanosecond.
//
// A reader that stalls forever inside a critical section would stall the
// writer; that cannot happen here because the critical section is a bounded,
// allocation-free, branch-only evaluate() call. `synchronize()` still takes a
// timeout so a bug cannot wedge the control plane.
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <thread>
#include <vector>

namespace policy {

#if defined(__cpp_lib_hardware_interference_size) && !defined(__APPLE__)
inline constexpr std::size_t kCacheLine = std::hardware_destructive_interference_size;
#else
inline constexpr std::size_t kCacheLine = 64;
#endif

inline constexpr std::uint64_t kQuiescent = 0;

// One cache-line-isolated slot per reader thread.
struct alignas(kCacheLine) ReaderSlot {
  std::atomic<std::uint64_t> epoch{kQuiescent};
  std::atomic<bool> in_use{false};
  char pad[kCacheLine - sizeof(std::atomic<std::uint64_t>) - sizeof(std::atomic<bool>)]{};
};
static_assert(sizeof(ReaderSlot) == kCacheLine);

template <typename T>
class RcuDomain;

// RAII guard over a reader critical section. Non-copyable, non-movable:
// it must not outlive the scope that took it.
template <typename T>
class [[nodiscard]] RcuGuard {
 public:
  RcuGuard(const RcuGuard&) = delete;
  RcuGuard& operator=(const RcuGuard&) = delete;
  RcuGuard(RcuGuard&&) = delete;
  RcuGuard& operator=(RcuGuard&&) = delete;

  ~RcuGuard() { slot_->epoch.store(kQuiescent, std::memory_order_release); }

  const T* get() const noexcept { return ptr_; }
  const T& operator*() const noexcept { return *ptr_; }
  const T* operator->() const noexcept { return ptr_; }
  explicit operator bool() const noexcept { return ptr_ != nullptr; }

 private:
  friend class RcuDomain<T>;
  RcuGuard(ReaderSlot* slot, const T* ptr) noexcept : slot_(slot), ptr_(ptr) {}

  ReaderSlot* slot_;
  const T* ptr_;
};

template <typename T>
class RcuDomain {
 public:
  // `max_readers` is fixed at construction: reader slots are never reallocated,
  // so a reader's pointer into the slot array stays valid for the domain's life.
  explicit RcuDomain(std::size_t max_readers) : slots_(max_readers) {}

  ~RcuDomain() {
    delete current_.load(std::memory_order_acquire);
    for (const T* p : retired_) delete p;
  }

  RcuDomain(const RcuDomain&) = delete;
  RcuDomain& operator=(const RcuDomain&) = delete;

  // Claim a reader slot. Call once per worker thread, at startup, off the hot
  // path. Returns SIZE_MAX if the domain is out of slots.
  [[nodiscard]] std::size_t register_reader() {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      bool expected = false;
      if (slots_[i].in_use.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return i;
      }
    }
    return static_cast<std::size_t>(-1);
  }

  void unregister_reader(std::size_t idx) {
    if (idx >= slots_.size()) return;
    slots_[idx].epoch.store(kQuiescent, std::memory_order_release);
    slots_[idx].in_use.store(false, std::memory_order_release);
  }

  std::size_t max_readers() const noexcept { return slots_.size(); }

  // The read-side fast path. Two stores to an exclusively-owned line plus one
  // acquire load of a line that is read-shared and almost never written.
  [[nodiscard]] RcuGuard<T> read(std::size_t idx) noexcept {
    ReaderSlot* slot = &slots_[idx];
    slot->epoch.store(global_epoch_.load(std::memory_order_relaxed), std::memory_order_release);
    // The seq_cst fence pairs with the one in synchronize(): it guarantees that
    // a writer either sees this reader's epoch, or this reader sees the new
    // pointer. Without it, store-load reordering lets both go stale at once.
    std::atomic_thread_fence(std::memory_order_seq_cst);
    return RcuGuard<T>(slot, current_.load(std::memory_order_acquire));
  }

  // Lock-free peek for code that only wants to read a version number and is
  // not going to dereference across a possible retire (admin endpoints hold a
  // real guard instead).
  [[nodiscard]] const T* unsafe_current() const noexcept {
    return current_.load(std::memory_order_acquire);
  }

  // Publish a new snapshot. Takes ownership. Returns the retired pointer, which
  // is NOT yet safe to free — pass it to reclaim() after synchronize().
  const T* publish(std::unique_ptr<T> next) {
    const T* old = current_.exchange(next.release(), std::memory_order_acq_rel);
    global_epoch_.fetch_add(1, std::memory_order_release);
    return old;
  }

  // Wait until every reader that was inside a critical section at publish time
  // has left it or re-entered at a newer epoch. Returns false on timeout, in
  // which case the caller must NOT free the retired pointer.
  [[nodiscard]] bool synchronize(std::chrono::milliseconds timeout = std::chrono::milliseconds(500)) {
    std::atomic_thread_fence(std::memory_order_seq_cst);
    const std::uint64_t target = global_epoch_.load(std::memory_order_acquire);
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    for (auto& slot : slots_) {
      for (;;) {
        const std::uint64_t e = slot.epoch.load(std::memory_order_acquire);
        // Quiescent, or already re-entered at or after the new epoch.
        if (e == kQuiescent || e >= target) break;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::yield();
      }
    }
    return true;
  }

  // Publish, wait for the grace period, then free the old snapshot. This is the
  // whole reload sequence; it runs on the control-plane thread and blocks only
  // the control plane.
  bool swap_and_reclaim(std::unique_ptr<T> next,
                        std::chrono::milliseconds timeout = std::chrono::milliseconds(500)) {
    const T* old = publish(std::move(next));
    const bool quiesced = synchronize(timeout);
    if (!quiesced) {
      // Readers did not quiesce in time. Leaking is the only safe option; park
      // the pointer so a later reload can retry the grace period.
      if (old != nullptr) retired_.push_back(old);
      return false;
    }
    delete old;
    // A previous reload may have parked pointers; this grace period covers them.
    for (const T* p : retired_) delete p;
    retired_.clear();
    return true;
  }

  std::size_t deferred_retire_count() const noexcept { return retired_.size(); }

 private:
  std::atomic<const T*> current_{nullptr};
  std::atomic<std::uint64_t> global_epoch_{1};
  std::vector<ReaderSlot> slots_;
  std::vector<const T*> retired_;  // control-plane thread only
};

}  // namespace policy
