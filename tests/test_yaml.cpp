// The YAML subset parser: the shapes the rules file uses, and clear errors for
// everything outside the documented subset.
#include "policy/yaml.hpp"
#include "test_framework.hpp"

using namespace policy::yaml;

namespace {
Node parse_ok(const char* text) {
  auto r = parse(text);
  if (!r.ok()) {
    std::fprintf(stderr, "  parse error at line %d: %s\n", r.error_line, r.error.c_str());
  }
  return r.root;
}
}  // namespace

TEST(Yaml, BlockMapping) {
  const Node n = parse_ok("a: 1\nb: hello\nc: true\n");
  REQUIRE(n.is_map());
  CHECK_EQ(n.fields().size(), std::size_t{3});
  REQUIRE(n.find("a") != nullptr);
  CHECK_EQ(n.find("a")->as_int().value_or(-1), std::int64_t{1});
  CHECK_EQ(n.find("b")->scalar(), std::string("hello"));
  CHECK_EQ(n.find("c")->as_bool().value_or(false), true);
  CHECK(n.find("missing") == nullptr);
}

TEST(Yaml, NestedBlocks) {
  const Node n = parse_ok(
      "outer:\n"
      "  inner:\n"
      "    leaf: 42\n"
      "sibling: 7\n");
  REQUIRE(n.is_map());
  const Node* leaf = n.find("outer")->find("inner")->find("leaf");
  REQUIRE(leaf != nullptr);
  CHECK_EQ(leaf->as_int().value_or(0), std::int64_t{42});
  CHECK_EQ(n.find("sibling")->as_int().value_or(0), std::int64_t{7});
}

TEST(Yaml, BlockSequenceAtSameIndentAsKey) {
  const Node n = parse_ok(
      "items:\n"
      "- one\n"
      "- two\n"
      "- three\n");
  const Node* items = n.find("items");
  REQUIRE(items != nullptr && items->is_seq());
  CHECK_EQ(items->items().size(), std::size_t{3});
  CHECK_EQ(items->items()[1].scalar(), std::string("two"));
}

TEST(Yaml, BlockSequenceIndented) {
  const Node n = parse_ok(
      "items:\n"
      "  - one\n"
      "  - two\n");
  const Node* items = n.find("items");
  REQUIRE(items != nullptr && items->is_seq());
  CHECK_EQ(items->items().size(), std::size_t{2});
}

TEST(Yaml, SequenceOfMappings) {
  const Node n = parse_ok(
      "rules:\n"
      "  - id: 1\n"
      "    name: first\n"
      "  - id: 2\n"
      "    name: second\n"
      "    nested:\n"
      "      deep: yes\n");
  const Node* rules = n.find("rules");
  REQUIRE(rules != nullptr && rules->is_seq());
  REQUIRE(rules->items().size() == 2);
  CHECK_EQ(rules->items()[0].find("id")->as_int().value_or(0), std::int64_t{1});
  CHECK_EQ(rules->items()[1].find("name")->scalar(), std::string("second"));
  CHECK_EQ(rules->items()[1].find("nested")->find("deep")->as_bool().value_or(false), true);
}

TEST(Yaml, FlowCollections) {
  const Node n = parse_ok(
      "list: [a, b, c]\n"
      "map: {x: 1, y: 2}\n"
      "nested: [{k: v}, [1, 2]]\n"
      "empty_list: []\n");
  REQUIRE(n.find("list")->is_seq());
  CHECK_EQ(n.find("list")->items().size(), std::size_t{3});
  CHECK_EQ(n.find("list")->items()[2].scalar(), std::string("c"));
  REQUIRE(n.find("map")->is_map());
  CHECK_EQ(n.find("map")->find("y")->as_int().value_or(0), std::int64_t{2});
  REQUIRE(n.find("nested")->is_seq());
  CHECK_EQ(n.find("nested")->items()[0].find("k")->scalar(), std::string("v"));
  CHECK_EQ(n.find("nested")->items()[1].items().size(), std::size_t{2});
  CHECK_EQ(n.find("empty_list")->items().size(), std::size_t{0});
}

TEST(Yaml, CommentsAndDocumentMarkers) {
  const Node n = parse_ok(
      "# leading comment\n"
      "---\n"
      "a: 1   # trailing comment\n"
      "\n"
      "b: \"a # not a comment\"\n"
      "c: 'single # also not'\n"
      "...\n");
  CHECK_EQ(n.find("a")->as_int().value_or(0), std::int64_t{1});
  CHECK_EQ(n.find("b")->scalar(), std::string("a # not a comment"));
  CHECK_EQ(n.find("c")->scalar(), std::string("single # also not"));
}

TEST(Yaml, QuotedScalarsAndEscapes) {
  const Node n = parse_ok(
      "a: \"line\\nbreak\"\n"
      "b: \"quote\\\"inside\"\n"
      "c: 'it''s fine'\n"
      "d: \"has: colon\"\n");
  CHECK_EQ(n.find("a")->scalar(), std::string("line\nbreak"));
  CHECK_EQ(n.find("b")->scalar(), std::string("quote\"inside"));
  CHECK_EQ(n.find("c")->scalar(), std::string("it's fine"));
  CHECK_EQ(n.find("d")->scalar(), std::string("has: colon"));
}

TEST(Yaml, ColonInsideAScalarIsNotAKeySeparator) {
  // "02:00" must stay a scalar, or every time window in the rules file breaks.
  const Node n = parse_ok("start: 02:00\nend: 06:30\n");
  CHECK_EQ(n.find("start")->scalar(), std::string("02:00"));
  CHECK_EQ(n.find("start")->as_time_of_day().value_or(0), std::uint16_t{120});
  CHECK_EQ(n.find("end")->as_time_of_day().value_or(0), std::uint16_t{390});
}

TEST(Yaml, NullSpellings) {
  const Node n = parse_ok("a:\nb: ~\nc: null\n");
  CHECK(n.find("a")->is_null());
  CHECK(n.find("b")->is_null());
  CHECK(n.find("c")->is_null());
}

TEST(Yaml, TypedAccessors) {
  const Node n = parse_ok(
      "bytes_gb: 20GB\n"
      "bytes_gib: 1GiB\n"
      "bytes_plain: 1_000_000\n"
      "rate_m: 50Mbps\n"
      "rate_g: 1.5Gbps\n"
      "rate_bare: 1000\n"
      "dur_d: 30d\n"
      "dur_h: 4h\n"
      "dur_bare: 900\n"
      "pct_sign: 80%\n"
      "pct_frac: 0.8\n"
      "pct_int: 80\n");
  CHECK_EQ(n.find("bytes_gb")->as_bytes().value_or(0), std::uint64_t{20'000'000'000});
  CHECK_EQ(n.find("bytes_gib")->as_bytes().value_or(0), std::uint64_t{1073741824});
  CHECK_EQ(n.find("bytes_plain")->as_bytes().value_or(0), std::uint64_t{1'000'000});
  CHECK_EQ(n.find("rate_m")->as_kbps().value_or(0), 50'000u);
  CHECK_EQ(n.find("rate_g")->as_kbps().value_or(0), 1'500'000u);
  CHECK_EQ(n.find("rate_bare")->as_kbps().value_or(0), 1000u);
  CHECK_EQ(n.find("dur_d")->as_seconds().value_or(0), 2'592'000u);
  CHECK_EQ(n.find("dur_h")->as_seconds().value_or(0), 14400u);
  CHECK_EQ(n.find("dur_bare")->as_seconds().value_or(0), 900u);
  CHECK_EQ(n.find("pct_sign")->as_permille().value_or(0), 800u);
  CHECK_EQ(n.find("pct_frac")->as_permille().value_or(0), 800u);
  CHECK_EQ(n.find("pct_int")->as_permille().value_or(0), 800u);
}

TEST(Yaml, TypedAccessorsRejectGarbage) {
  const Node n = parse_ok("a: notanumber\nb: 10Furlongs\nc: 25:00\nd: [1,2]\n");
  CHECK(!n.find("a")->as_int().has_value());
  CHECK(!n.find("b")->as_bytes().has_value());
  CHECK(!n.find("b")->as_kbps().has_value());
  CHECK(!n.find("c")->as_time_of_day().has_value());
  CHECK(!n.find("d")->as_int().has_value());
  // A trailing suffix must not be silently discarded.
  const Node m = parse_ok("x: 5cats\n");
  CHECK(!m.find("x")->as_double().has_value());
}

TEST(Yaml, BooleanSpellings) {
  const Node n = parse_ok("a: true\nb: yes\nc: on\nd: 1\ne: false\nf: no\ng: off\nh: 0\ni: maybe\n");
  for (const char* k : {"a", "b", "c", "d"}) CHECK(n.find(k)->as_bool().value_or(false));
  for (const char* k : {"e", "f", "g", "h"}) CHECK(!n.find(k)->as_bool().value_or(true));
  CHECK(!n.find("i")->as_bool().has_value());
}

// --- errors ----------------------------------------------------------------

TEST(Yaml, TabIndentationIsAnError) {
  const auto r = parse("a:\n\tb: 1\n");
  CHECK(!r.ok());
  CHECK_MSG(r.error.find("tab") != std::string::npos, r.error);
  CHECK_EQ(r.error_line, 2);
}

TEST(Yaml, UnsupportedConstructsAreRejectedNotIgnored) {
  CHECK(!parse("a: |\n  block scalar\n").ok());
  CHECK(!parse("a: >\n  folded\n").ok());
  CHECK(!parse("a: &anchor 1\n").ok());
  CHECK(!parse("a: *alias\n").ok());
  CHECK(!parse("a: !!str 1\n").ok());
}

TEST(Yaml, MalformedFlowCollections) {
  CHECK(!parse("a: [1, 2\n").ok());
  CHECK(!parse("a: {k: 1\n").ok());
  CHECK(!parse("a: {k 1}\n").ok());
  CHECK(!parse("a: [1, 2] trailing\n").ok());
}

TEST(Yaml, MissingColonIsAnErrorWithALine) {
  const auto r = parse("a: 1\nthis line has no colon\n");
  CHECK(!r.ok());
  CHECK_EQ(r.error_line, 2);
}

TEST(Yaml, EmptyDocumentIsNull) {
  const auto r = parse("");
  CHECK(r.ok());
  CHECK(r.root.is_null());
  const auto c = parse("# only a comment\n");
  CHECK(c.ok());
  CHECK(c.root.is_null());
}
