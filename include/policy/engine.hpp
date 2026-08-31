// The decision path.
//
// Everything here is noexcept, allocation-free, and free of syscalls, locks and
// I/O. `evaluate()` takes an immutable RuleSet snapshot (obtained through RCU),
// a decoded request and an optional subscriber record, and returns a fully
// populated 64-byte decision by value.
//
// The allocation-free property is not a comment — tests/test_engine.cpp runs
// evaluate() under a counting global allocator and asserts the count does not
// move.
#pragma once

#include <cstdint>

#include "policy/rules.hpp"
#include "policy/subscriber_store.hpp"
#include "policy/wire.hpp"

namespace policy {

// Build the 64-bit feature word for a request. Split out from evaluate() so it
// can be unit-tested and printed by the admin "explain" endpoint.
[[nodiscard]] FeatureWord build_features(const RuleSet& rs, const PolicyRequest& req,
                                         const SubscriberRecord* rec) noexcept;

// Which plan bit a request matches. Returns 0 for an unknown subscriber, which
// makes plan-scoped rules skip it and leaves only global rules in play.
[[nodiscard]] std::uint32_t plan_bit_for(const SubscriberRecord* rec) noexcept;

// The decision. Never throws, never allocates, never blocks.
[[nodiscard]] PolicyDecision evaluate(const RuleSet& rs, const PolicyRequest& req,
                                      const SubscriberRecord* rec) noexcept;

// Convenience wrapper: look the subscriber up, then evaluate. This is what the
// server calls.
[[nodiscard]] inline PolicyDecision evaluate(const RuleSet& rs, const SubscriberStore& store,
                                             const PolicyRequest& req) noexcept {
  return evaluate(rs, req, store.find(req.imsi));
}

// A malformed or unversioned datagram still gets a well-formed reply, so a
// buggy client sees DENY/MALFORMED_REQUEST rather than a timeout.
[[nodiscard]] PolicyDecision malformed_decision(std::uint32_t seq, std::uint64_t client_ts_ns,
                                                std::uint32_t policy_version) noexcept;

// Human-readable feature dump for /explain and for test failure output.
// Allocates — never call it on the request path.
[[nodiscard]] std::string describe_features(const RuleSet& rs, FeatureWord f);

}  // namespace policy
