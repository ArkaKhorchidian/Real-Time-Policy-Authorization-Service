// A small, dependency-free parser for the YAML subset the rules file uses.
//
// Why not a library: the rule file is the only YAML this service reads, it is
// authored by operators and reviewed in code review, and pulling libyaml or
// yaml-cpp into a build that otherwise has zero dependencies is a poor trade
// for ~400 lines. The subset is fixed and documented below; anything outside it
// is a parse error with a line number, never a silent misreading.
//
// Supported:
//   * block mappings          key: value
//   * nested blocks by indent (spaces only — tabs are an error)
//   * block sequences         - item        and   - key: value
//   * flow sequences/maps     [a, b]  {k: v}
//   * scalars: bare, 'single' and "double" quoted (with \n \t \\ \" escapes)
//   * comments: '#' to end of line, outside quotes
//   * document markers --- and ...
//   * null spellings: empty value, ~, null
//
// Not supported (rejected with an error, not ignored):
//   * block scalars | and >, anchors/aliases, tags, multiple documents,
//     complex keys, tab indentation
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace policy::yaml {

class Node {
 public:
  enum class Type : std::uint8_t { kNull, kScalar, kMap, kSeq };

  Node() = default;
  explicit Node(Type t, int line) : type_(t), line_(line) {}

  [[nodiscard]] Type type() const noexcept { return type_; }
  [[nodiscard]] int line() const noexcept { return line_; }
  [[nodiscard]] bool is_null() const noexcept { return type_ == Type::kNull; }
  [[nodiscard]] bool is_scalar() const noexcept { return type_ == Type::kScalar; }
  [[nodiscard]] bool is_map() const noexcept { return type_ == Type::kMap; }
  [[nodiscard]] bool is_seq() const noexcept { return type_ == Type::kSeq; }

  [[nodiscard]] const std::string& scalar() const noexcept { return scalar_; }
  [[nodiscard]] const std::vector<Node>& items() const noexcept { return seq_; }
  [[nodiscard]] const std::vector<std::pair<std::string, Node>>& fields() const noexcept {
    return map_;
  }

  // Map lookup. Returns nullptr when absent, so callers distinguish "missing"
  // from "present but empty" — which the rules compiler needs.
  [[nodiscard]] const Node* find(std::string_view key) const noexcept {
    for (const auto& [k, v] : map_) {
      if (k == key) return &v;
    }
    return nullptr;
  }

  [[nodiscard]] bool has(std::string_view key) const noexcept { return find(key) != nullptr; }

  // Typed accessors. Every one returns nullopt rather than a default so the
  // compiler can report "expected an integer at line N" instead of silently
  // applying a zero.
  [[nodiscard]] std::optional<std::int64_t> as_int() const;
  [[nodiscard]] std::optional<std::uint64_t> as_uint() const;
  [[nodiscard]] std::optional<double> as_double() const;
  [[nodiscard]] std::optional<bool> as_bool() const;

  // Byte sizes with SI/IEC suffixes: 20GB, 512MiB, 1_000_000. Case-insensitive.
  // GB is 10^9 and GiB is 2^30, spelled out because operators write both and
  // conflating them is a 7% billing error.
  [[nodiscard]] std::optional<std::uint64_t> as_bytes() const;

  // Bit rates: 50Mbps, 1.5Gbps, 1000 (bare = kbps). Returns kbps.
  [[nodiscard]] std::optional<std::uint32_t> as_kbps() const;

  // Durations: 30s, 15m, 24h, 7d, bare = seconds.
  [[nodiscard]] std::optional<std::uint32_t> as_seconds() const;

  // "HH:MM" -> minutes since midnight.
  [[nodiscard]] std::optional<std::uint16_t> as_time_of_day() const;

  // Percentages: "80%" or "0.8" or "80" -> per-mille (800).
  [[nodiscard]] std::optional<std::uint32_t> as_permille() const;

 private:
  friend class Parser;
  Type type_ = Type::kNull;
  int line_ = 0;
  std::string scalar_;
  std::vector<Node> seq_;
  std::vector<std::pair<std::string, Node>> map_;
};

struct ParseResult {
  Node root;
  std::string error;   // empty on success
  int error_line = 0;

  [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

[[nodiscard]] ParseResult parse(std::string_view text);

}  // namespace policy::yaml
