// A ~120-line test framework.
//
// The alternative is vendoring Catch2 or GoogleTest into a project that
// otherwise has zero dependencies, for features this suite does not use. What
// it does need — named cases, non-fatal and fatal assertions, readable failure
// output with values, a filter, and a non-zero exit code — fits here.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace testing {

struct TestCase {
  std::string suite;
  std::string name;
  std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

struct Registrar {
  Registrar(const char* suite, const char* name, std::function<void()> fn) {
    registry().push_back({suite, name, std::move(fn)});
  }
};

// Per-test failure state. A failed CHECK records and continues; a failed
// REQUIRE throws so the rest of the case does not run against broken state.
inline int& failure_count() {
  static int n = 0;
  return n;
}

struct RequireFailed {};

inline void report_failure(const char* file, int line, const std::string& message) {
  ++failure_count();
  std::fprintf(stderr, "  FAIL %s:%d\n    %s\n", file, line, message.c_str());
}

template <typename T>
std::string to_string(const T& v) {
  std::ostringstream os;
  if constexpr (std::is_same_v<T, bool>) {
    os << (v ? "true" : "false");
  } else if constexpr (std::is_same_v<T, std::uint8_t> || std::is_same_v<T, std::int8_t>) {
    os << static_cast<int>(v);
  } else {
    os << v;
  }
  return os.str();
}

inline int run_all(int argc, char** argv) {
  const char* filter = nullptr;
  bool list = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--list") == 0) list = true;
    else if (std::strcmp(argv[i], "--filter") == 0 && i + 1 < argc) filter = argv[++i];
    else if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
      std::printf("Usage: %s [--filter SUBSTRING] [--list]\n", argv[0]);
      return 0;
    }
  }

  int run = 0;
  int failed_cases = 0;
  for (const auto& c : registry()) {
    const std::string full = c.suite + "." + c.name;
    if (filter != nullptr && full.find(filter) == std::string::npos) continue;
    if (list) {
      std::printf("%s\n", full.c_str());
      continue;
    }
    ++run;
    const int before = failure_count();
    std::fprintf(stderr, "[ RUN  ] %s\n", full.c_str());
    try {
      c.fn();
    } catch (const RequireFailed&) {
      // Already reported.
    } catch (const std::exception& e) {
      report_failure(__FILE__, __LINE__, std::string("unexpected exception: ") + e.what());
    } catch (...) {
      report_failure(__FILE__, __LINE__, "unexpected non-standard exception");
    }
    if (failure_count() != before) {
      ++failed_cases;
      std::fprintf(stderr, "[ FAIL ] %s\n", full.c_str());
    } else {
      std::fprintf(stderr, "[  OK  ] %s\n", full.c_str());
    }
  }

  if (list) return 0;
  std::fprintf(stderr, "\n%d case(s) run, %d failed, %d assertion failure(s)\n", run, failed_cases,
               failure_count());
  return failed_cases == 0 ? 0 : 1;
}

}  // namespace testing

#define TEST(suite, name)                                                         \
  static void suite##_##name##_body();                                            \
  static ::testing::Registrar suite##_##name##_reg(#suite, #name,                 \
                                                   suite##_##name##_body);        \
  static void suite##_##name##_body()

#define CHECK_MSG(cond, msg)                                       \
  do {                                                             \
    if (!(cond)) ::testing::report_failure(__FILE__, __LINE__, msg); \
  } while (0)

#define CHECK(cond) CHECK_MSG((cond), "expected: " #cond)

// REQUIRE with a message, for setup steps whose failure needs explaining.
#define REQUIRE_MSG(cond, msg)                                    \
  do {                                                            \
    if (!(cond)) {                                                \
      ::testing::report_failure(__FILE__, __LINE__, (msg));        \
      throw ::testing::RequireFailed{};                           \
    }                                                             \
  } while (0)

#define REQUIRE(cond)                                                     \
  do {                                                                    \
    if (!(cond)) {                                                        \
      ::testing::report_failure(__FILE__, __LINE__, "required: " #cond);   \
      throw ::testing::RequireFailed{};                                    \
    }                                                                     \
  } while (0)

#define CHECK_BINOP(a, b, op)                                                            \
  do {                                                                                   \
    const auto lhs_ = (a);                                                               \
    const auto rhs_ = (b);                                                               \
    if (!(lhs_ op rhs_)) {                                                               \
      ::testing::report_failure(__FILE__, __LINE__,                                      \
                                std::string(#a " " #op " " #b "\n      lhs = ") +        \
                                    ::testing::to_string(lhs_) + "\n      rhs = " +      \
                                    ::testing::to_string(rhs_));                         \
    }                                                                                    \
  } while (0)

#define CHECK_EQ(a, b) CHECK_BINOP(a, b, ==)
#define CHECK_NE(a, b) CHECK_BINOP(a, b, !=)
#define CHECK_LT(a, b) CHECK_BINOP(a, b, <)
#define CHECK_LE(a, b) CHECK_BINOP(a, b, <=)
#define CHECK_GT(a, b) CHECK_BINOP(a, b, >)
#define CHECK_GE(a, b) CHECK_BINOP(a, b, >=)

#define TEST_MAIN()                                        \
  int main(int argc, char** argv) {                        \
    return ::testing::run_all(argc, argv);                 \
  }
