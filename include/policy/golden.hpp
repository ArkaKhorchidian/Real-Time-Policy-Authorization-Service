// Golden decision file: a committed corpus of (request -> expected decision)
// pairs that CI replays on every change.
//
// This is the regression net for the whole decision path. It catches a rule
// reordering, a feature-bit renumbering, an inheritance change, a wire layout
// change and an evaluate() bug — all of which are otherwise easy to make and
// hard to notice, because the service keeps answering, just differently.
//
// The file is plain CSV so a diff is readable in a pull request: when a policy
// change is intentional, the reviewer sees exactly which decisions moved.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "policy/wire.hpp"

namespace policy {

struct GoldenCase {
  PolicyRequest request{};
  PolicyDecision expected{};
  int line = 0;
};

// The CSV column header, written by the generator and required by the reader.
std::string golden_header();

// One row: every request field that affects a decision, then every decision
// field. Fields that carry no policy meaning (seq, timestamps) are omitted.
std::string golden_row(const PolicyRequest& req, const PolicyDecision& dec);

struct GoldenLoadResult {
  std::vector<GoldenCase> cases;
  std::string error;
  [[nodiscard]] bool ok() const { return error.empty(); }
};

GoldenLoadResult load_golden(const std::string& path);

// Compare two decisions on the fields the golden file pins. Returns an empty
// string when they match, or a human-readable description of every difference.
std::string diff_decisions(const PolicyDecision& expected, const PolicyDecision& actual);

}  // namespace policy
