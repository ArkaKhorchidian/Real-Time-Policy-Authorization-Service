#include "policy/yaml.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>

namespace policy::yaml {
namespace {

std::string_view rtrim(std::string_view s) {
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return s;
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
  return rtrim(s);
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// Strip a trailing comment, respecting quotes. A '#' only starts a comment when
// it is at the start of the line or preceded by whitespace — "a#b" is a scalar.
std::string_view strip_comment(std::string_view line) {
  bool in_single = false, in_double = false;
  for (std::size_t i = 0; i < line.size(); ++i) {
    const char c = line[i];
    if (c == '\'' && !in_double) in_single = !in_single;
    else if (c == '"' && !in_single) in_double = !in_double;
    else if (c == '#' && !in_single && !in_double && (i == 0 || line[i - 1] == ' ' || line[i - 1] == '\t')) {
      return line.substr(0, i);
    }
  }
  return line;
}

// Unquote and unescape a scalar.
std::string unquote(std::string_view s) {
  s = trim(s);
  if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'') {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 1; i + 1 < s.size(); ++i) {
      // YAML single quotes escape only the quote itself, by doubling it.
      if (s[i] == '\'' && i + 2 < s.size() && s[i + 1] == '\'') ++i;
      out += s[i];
    }
    return out;
  }
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 1; i + 1 < s.size(); ++i) {
      if (s[i] == '\\' && i + 2 < s.size()) {
        switch (s[++i]) {
          case 'n': out += '\n'; break;
          case 't': out += '\t'; break;
          case 'r': out += '\r'; break;
          case '0': out += '\0'; break;
          case '\\': out += '\\'; break;
          case '"': out += '"'; break;
          default: out += s[i]; break;
        }
      } else {
        out += s[i];
      }
    }
    return out;
  }
  return std::string(s);
}

struct Line {
  int indent = 0;
  int number = 0;
  std::string text;  // comment-stripped, right-trimmed, leading indent removed
};

}  // namespace

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------
class Parser {
 public:
  explicit Parser(std::string_view text) { split_lines(text); }

  ParseResult run() {
    ParseResult res;
    if (lines_.empty()) {
      res.root = Node(Node::Type::kNull, 1);
      return res;
    }
    std::size_t idx = 0;
    Node root = parse_block(idx, lines_[0].indent);
    if (!error_.empty()) {
      res.error = error_;
      res.error_line = error_line_;
      return res;
    }
    if (idx < lines_.size()) {
      res.error = "unexpected content (check indentation)";
      res.error_line = lines_[idx].number;
      return res;
    }
    res.root = std::move(root);
    return res;
  }

 private:
  void fail(const std::string& msg, int line) {
    if (error_.empty()) {
      error_ = msg;
      error_line_ = line;
    }
  }

  void split_lines(std::string_view text) {
    int number = 0;
    std::size_t pos = 0;
    while (pos <= text.size()) {
      const auto nl = text.find('\n', pos);
      std::string_view raw =
          text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
      ++number;

      int indent = 0;
      std::size_t i = 0;
      for (; i < raw.size(); ++i) {
        if (raw[i] == ' ') ++indent;
        else if (raw[i] == '\t') { fail("tab used for indentation; YAML requires spaces", number); return; }
        else break;
      }
      const std::string_view body = rtrim(strip_comment(raw.substr(i)));
      if (!body.empty() && body != "---" && body != "...") {
        lines_.push_back(Line{indent, number, std::string(body)});
      }

      if (nl == std::string_view::npos) break;
      pos = nl + 1;
    }
  }

  // Parse whatever block starts at lines_[idx] with exactly `indent`.
  Node parse_block(std::size_t& idx, int indent) {
    if (idx >= lines_.size()) return Node(Node::Type::kNull, 0);
    if (is_seq_item(lines_[idx].text)) return parse_seq(idx, indent);
    return parse_map(idx, indent);
  }

  static bool is_seq_item(const std::string& t) {
    return t == "-" || (t.size() >= 2 && t[0] == '-' && (t[1] == ' ' || t[1] == '\t'));
  }

  Node parse_seq(std::size_t& idx, int indent) {
    Node n(Node::Type::kSeq, lines_[idx].number);
    while (idx < lines_.size() && error_.empty()) {
      const Line& ln = lines_[idx];
      if (ln.indent != indent || !is_seq_item(ln.text)) break;

      const std::string_view rest = trim(std::string_view(ln.text).substr(1));
      const int rest_col = indent + 2;

      if (rest.empty()) {
        // "-" alone: the item is the indented block on the following lines.
        ++idx;
        if (idx < lines_.size() && lines_[idx].indent > indent) {
          n.seq_.push_back(parse_block(idx, lines_[idx].indent));
        } else {
          n.seq_.push_back(Node(Node::Type::kNull, ln.number));
        }
        continue;
      }

      if (rest.front() == '[' || rest.front() == '{') {
        n.seq_.push_back(parse_flow(rest, ln.number));
        ++idx;
        continue;
      }

      if (key_split(rest) != std::string_view::npos) {
        // "- key: value": rewrite this line as the first line of a mapping
        // whose indent is the column the key starts at, then parse normally.
        lines_[idx].indent = rest_col;
        lines_[idx].text = std::string(rest);
        n.seq_.push_back(parse_map(idx, rest_col));
        continue;
      }

      n.seq_.push_back(make_scalar(rest, ln.number));
      ++idx;
    }
    return n;
  }

  // Position of the ':' that separates a key from its value, or npos.
  // Skips colons inside quotes and inside flow collections, and requires the
  // colon to be followed by a space or end of line (so "12:30" is a scalar).
  static std::size_t key_split(std::string_view s) {
    bool in_single = false, in_double = false;
    int depth = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
      const char c = s[i];
      if (c == '\'' && !in_double) in_single = !in_single;
      else if (c == '"' && !in_single) in_double = !in_double;
      else if (in_single || in_double) continue;
      else if (c == '[' || c == '{') ++depth;
      else if (c == ']' || c == '}') --depth;
      else if (c == ':' && depth == 0 && (i + 1 == s.size() || s[i + 1] == ' ')) return i;
    }
    return std::string_view::npos;
  }

  Node parse_map(std::size_t& idx, int indent) {
    Node n(Node::Type::kMap, lines_[idx].number);
    while (idx < lines_.size()) {
      const Line& ln = lines_[idx];
      if (ln.indent != indent) {
        if (ln.indent < indent) break;
        fail("unexpected indentation", ln.number);
        break;
      }
      if (is_seq_item(ln.text)) break;

      const std::string_view text = ln.text;
      const std::size_t colon = key_split(text);
      if (colon == std::string_view::npos) {
        fail("expected 'key: value'", ln.number);
        break;
      }

      std::string key = unquote(text.substr(0, colon));
      if (key.empty()) {
        fail("empty key", ln.number);
        break;
      }
      const std::string_view value = trim(text.substr(colon + 1));
      const int line_no = ln.number;
      ++idx;

      if (!value.empty()) {
        if (value.front() == '[' || value.front() == '{') {
          n.map_.emplace_back(std::move(key), parse_flow(value, line_no));
        } else {
          n.map_.emplace_back(std::move(key), make_scalar(value, line_no));
        }
        continue;
      }

      // Empty value: either a nested block, or an explicit null.
      if (idx < lines_.size() && lines_[idx].indent > indent) {
        n.map_.emplace_back(std::move(key), parse_block(idx, lines_[idx].indent));
      } else if (idx < lines_.size() && lines_[idx].indent == indent && is_seq_item(lines_[idx].text)) {
        // A sequence may sit at the same indent as its key — the common style.
        n.map_.emplace_back(std::move(key), parse_seq(idx, indent));
      } else {
        n.map_.emplace_back(std::move(key), Node(Node::Type::kNull, line_no));
      }
    }
    return n;
  }

  Node make_scalar(std::string_view s, int line) {
    s = trim(s);
    if (s.empty() || s == "~" || s == "null" || s == "Null" || s == "NULL") {
      return Node(Node::Type::kNull, line);
    }
    if (s.front() == '|' || s.front() == '>') {
      fail("block scalars (| and >) are not supported", line);
      return Node(Node::Type::kNull, line);
    }
    if (s.front() == '&' || s.front() == '*' || s.front() == '!') {
      fail("anchors, aliases and tags are not supported", line);
      return Node(Node::Type::kNull, line);
    }
    Node n(Node::Type::kScalar, line);
    n.scalar_ = unquote(s);
    return n;
  }

  // Flow collections: [a, b, {k: v}] / {k: v, j: [1, 2]}. Single line only.
  Node parse_flow(std::string_view s, int line) {
    std::size_t pos = 0;
    Node n = parse_flow_value(s, pos, line);
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
    if (pos != s.size()) fail("trailing characters after flow collection", line);
    return n;
  }

  Node parse_flow_value(std::string_view s, std::size_t& pos, int line) {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
    if (pos >= s.size()) {
      fail("unexpected end of flow collection", line);
      return Node(Node::Type::kNull, line);
    }
    if (s[pos] == '[') return parse_flow_seq(s, pos, line);
    if (s[pos] == '{') return parse_flow_map(s, pos, line);
    return make_scalar(read_flow_scalar(s, pos), line);
  }

  static std::string_view read_flow_scalar(std::string_view s, std::size_t& pos) {
    const std::size_t start = pos;
    bool in_single = false, in_double = false;
    while (pos < s.size()) {
      const char c = s[pos];
      if (c == '\'' && !in_double) in_single = !in_single;
      else if (c == '"' && !in_single) in_double = !in_double;
      else if (!in_single && !in_double && (c == ',' || c == ']' || c == '}' || c == ':')) break;
      ++pos;
    }
    return rtrim(s.substr(start, pos - start));
  }

  Node parse_flow_seq(std::string_view s, std::size_t& pos, int line) {
    Node n(Node::Type::kSeq, line);
    ++pos;  // '['
    for (;;) {
      while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
      if (pos >= s.size()) { fail("unterminated flow sequence", line); return n; }
      if (s[pos] == ']') { ++pos; return n; }
      n.seq_.push_back(parse_flow_value(s, pos, line));
      if (!error_.empty()) return n;
      while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
      if (pos < s.size() && s[pos] == ',') { ++pos; continue; }
      if (pos < s.size() && s[pos] == ']') { ++pos; return n; }
      fail("expected ',' or ']' in flow sequence", line);
      return n;
    }
  }

  Node parse_flow_map(std::string_view s, std::size_t& pos, int line) {
    Node n(Node::Type::kMap, line);
    ++pos;  // '{'
    for (;;) {
      while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
      if (pos >= s.size()) { fail("unterminated flow mapping", line); return n; }
      if (s[pos] == '}') { ++pos; return n; }

      std::string key = unquote(read_flow_scalar(s, pos));
      while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
      if (pos >= s.size() || s[pos] != ':') { fail("expected ':' in flow mapping", line); return n; }
      ++pos;
      n.map_.emplace_back(std::move(key), parse_flow_value(s, pos, line));
      if (!error_.empty()) return n;

      while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
      if (pos < s.size() && s[pos] == ',') { ++pos; continue; }
      if (pos < s.size() && s[pos] == '}') { ++pos; return n; }
      fail("expected ',' or '}' in flow mapping", line);
      return n;
    }
  }

  std::vector<Line> lines_;
  std::string error_;
  int error_line_ = 0;
};

ParseResult parse(std::string_view text) {
  Parser p(text);
  return p.run();
}

// ---------------------------------------------------------------------------
// Typed accessors
// ---------------------------------------------------------------------------
namespace {

// Strip '_' separators, which operators use in large byte counts.
std::string despace(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (const char c : s) {
    if (c != '_' && c != ' ') out += c;
  }
  return out;
}

std::optional<double> parse_number(std::string_view s, std::string_view& suffix_out) {
  const std::string t = despace(s);
  if (t.empty()) return std::nullopt;
  const char* begin = t.c_str();
  char* end = nullptr;
  const double v = std::strtod(begin, &end);
  if (end == begin) return std::nullopt;
  static thread_local std::string suffix_store;
  suffix_store.assign(end);
  suffix_out = suffix_store;
  if (!std::isfinite(v)) return std::nullopt;
  return v;
}

}  // namespace

std::optional<std::int64_t> Node::as_int() const {
  if (!is_scalar()) return std::nullopt;
  const std::string t = despace(scalar_);
  if (t.empty()) return std::nullopt;
  const char* begin = t.c_str();
  char* end = nullptr;
  const long long v = std::strtoll(begin, &end, 0);
  if (end == begin || *end != '\0') return std::nullopt;
  return static_cast<std::int64_t>(v);
}

std::optional<std::uint64_t> Node::as_uint() const {
  const auto v = as_int();
  if (!v || *v < 0) return std::nullopt;
  return static_cast<std::uint64_t>(*v);
}

std::optional<double> Node::as_double() const {
  if (!is_scalar()) return std::nullopt;
  std::string_view suffix;
  const auto v = parse_number(scalar_, suffix);
  if (!v || !suffix.empty()) return std::nullopt;
  return v;
}

std::optional<bool> Node::as_bool() const {
  if (!is_scalar()) return std::nullopt;
  const std::string_view s = scalar_;
  if (iequals(s, "true") || iequals(s, "yes") || iequals(s, "on") || s == "1") return true;
  if (iequals(s, "false") || iequals(s, "no") || iequals(s, "off") || s == "0") return false;
  return std::nullopt;
}

std::optional<std::uint64_t> Node::as_bytes() const {
  if (!is_scalar()) return std::nullopt;
  std::string_view suffix;
  const auto v = parse_number(scalar_, suffix);
  if (!v || *v < 0) return std::nullopt;

  double mult = 1.0;
  if (suffix.empty() || iequals(suffix, "B")) mult = 1.0;
  else if (iequals(suffix, "KB")) mult = 1e3;
  else if (iequals(suffix, "MB")) mult = 1e6;
  else if (iequals(suffix, "GB")) mult = 1e9;
  else if (iequals(suffix, "TB")) mult = 1e12;
  else if (iequals(suffix, "KiB")) mult = 1024.0;
  else if (iequals(suffix, "MiB")) mult = 1024.0 * 1024;
  else if (iequals(suffix, "GiB")) mult = 1024.0 * 1024 * 1024;
  else if (iequals(suffix, "TiB")) mult = 1024.0 * 1024 * 1024 * 1024;
  else return std::nullopt;

  const double bytes = *v * mult;
  if (bytes > 1.8e19) return std::nullopt;
  return static_cast<std::uint64_t>(bytes);
}

std::optional<std::uint32_t> Node::as_kbps() const {
  if (!is_scalar()) return std::nullopt;
  std::string_view suffix;
  const auto v = parse_number(scalar_, suffix);
  if (!v || *v < 0) return std::nullopt;

  double kbps = 0;
  if (suffix.empty() || iequals(suffix, "kbps") || iequals(suffix, "kb/s")) kbps = *v;
  else if (iequals(suffix, "bps")) kbps = *v / 1000.0;
  else if (iequals(suffix, "Mbps") || iequals(suffix, "Mb/s")) kbps = *v * 1000.0;
  else if (iequals(suffix, "Gbps") || iequals(suffix, "Gb/s")) kbps = *v * 1e6;
  else return std::nullopt;

  if (kbps > 4.29e9) return std::nullopt;
  return static_cast<std::uint32_t>(kbps);
}

std::optional<std::uint32_t> Node::as_seconds() const {
  if (!is_scalar()) return std::nullopt;
  std::string_view suffix;
  const auto v = parse_number(scalar_, suffix);
  if (!v || *v < 0) return std::nullopt;

  double secs = 0;
  if (suffix.empty() || suffix == "s" || iequals(suffix, "sec")) secs = *v;
  else if (suffix == "m" || iequals(suffix, "min")) secs = *v * 60;
  else if (suffix == "h" || iequals(suffix, "hr")) secs = *v * 3600;
  else if (suffix == "d" || iequals(suffix, "day")) secs = *v * 86400;
  else return std::nullopt;

  if (secs > 4.29e9) return std::nullopt;
  return static_cast<std::uint32_t>(secs);
}

std::optional<std::uint16_t> Node::as_time_of_day() const {
  if (!is_scalar()) return std::nullopt;
  const auto colon = scalar_.find(':');
  if (colon == std::string::npos) return std::nullopt;
  const auto h = std::strtol(scalar_.substr(0, colon).c_str(), nullptr, 10);
  const auto m = std::strtol(scalar_.substr(colon + 1).c_str(), nullptr, 10);
  if (h < 0 || h > 23 || m < 0 || m > 59) return std::nullopt;
  return static_cast<std::uint16_t>(h * 60 + m);
}

std::optional<std::uint32_t> Node::as_permille() const {
  if (!is_scalar()) return std::nullopt;
  std::string_view suffix;
  const auto v = parse_number(scalar_, suffix);
  if (!v || *v < 0) return std::nullopt;

  double permille;
  if (suffix == "%") permille = *v * 10.0;
  else if (suffix.empty() && *v <= 1.0) permille = *v * 1000.0;  // 0.8 -> 800
  else if (suffix.empty()) permille = *v * 10.0;                 // 80 -> 800
  else return std::nullopt;

  if (permille > 100000.0) return std::nullopt;
  return static_cast<std::uint32_t>(permille + 0.5);
}

}  // namespace policy::yaml
