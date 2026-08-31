// Global allocation counter.
//
// `evaluate()` claims to be allocation-free. That is a property the compiler
// will not enforce and code review will eventually miss — a std::string built
// for an error path, a vector that stopped fitting its small-size optimization,
// a std::function capture. So the test measures it: replace global operator
// new/delete with counting versions and assert the count does not move across
// the call.
//
// Replacing the global operators affects the whole test binary, which is fine:
// the counter is only sampled around the region under test.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

namespace testing {

inline std::atomic<std::size_t>& alloc_count() {
  static std::atomic<std::size_t> n{0};
  return n;
}

inline std::atomic<std::size_t>& alloc_bytes() {
  static std::atomic<std::size_t> n{0};
  return n;
}

// Sample the counter, run `fn`, and report how many allocations happened.
template <typename Fn>
std::size_t count_allocations(Fn&& fn) {
  const std::size_t before = alloc_count().load(std::memory_order_relaxed);
  fn();
  return alloc_count().load(std::memory_order_relaxed) - before;
}

}  // namespace testing

// Definitions live in the TU that defines POLICY_DEFINE_COUNTING_ALLOCATOR, so
// the operators exist exactly once in the binary.
#ifdef POLICY_DEFINE_COUNTING_ALLOCATOR

void* operator new(std::size_t size) {
  ::testing::alloc_count().fetch_add(1, std::memory_order_relaxed);
  ::testing::alloc_bytes().fetch_add(size, std::memory_order_relaxed);
  void* p = std::malloc(size == 0 ? 1 : size);
  if (p == nullptr) throw std::bad_alloc();
  return p;
}

void* operator new[](std::size_t size) { return operator new(size); }

void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  ::testing::alloc_count().fetch_add(1, std::memory_order_relaxed);
  ::testing::alloc_bytes().fetch_add(size, std::memory_order_relaxed);
  return std::malloc(size == 0 ? 1 : size);
}

void* operator new[](std::size_t size, const std::nothrow_t& tag) noexcept {
  return operator new(size, tag);
}

void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }

// Over-aligned overloads: SubscriberRecord and the wire messages are
// alignas(64), so anything that heap-allocates one takes these paths.
void* operator new(std::size_t size, std::align_val_t al) {
  ::testing::alloc_count().fetch_add(1, std::memory_order_relaxed);
  ::testing::alloc_bytes().fetch_add(size, std::memory_order_relaxed);
  void* p = std::aligned_alloc(static_cast<std::size_t>(al),
                               ((size + static_cast<std::size_t>(al) - 1) /
                                static_cast<std::size_t>(al)) *
                                   static_cast<std::size_t>(al));
  if (p == nullptr) throw std::bad_alloc();
  return p;
}
void* operator new[](std::size_t size, std::align_val_t al) { return operator new(size, al); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }

#endif  // POLICY_DEFINE_COUNTING_ALLOCATOR
