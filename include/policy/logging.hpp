// Structured-ish logging for the control plane.
//
// Nothing here is called from the request path. Workers that need to report
// something increment a counter in metrics.hpp; the control plane turns
// counters into log lines. A log call on the decision path would be a
// syscall, a lock and an allocation in a sub-microsecond budget.
#pragma once

#include <cstdio>
#include <mutex>
#include <string>
#include <string_view>

namespace policy {

enum class LogLevel : int { kTrace = 0, kDebug = 1, kInfo = 2, kWarn = 3, kError = 4, kOff = 5 };

void set_log_level(LogLevel level);
LogLevel log_level();
bool parse_log_level(std::string_view s, LogLevel& out);

// Writes one line to stderr, timestamped and level-tagged, under a mutex so
// lines from different threads do not interleave.
void log_write(LogLevel level, std::string_view message);

namespace detail {
std::string format_va(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
}

#define POLICY_LOG(level, ...)                                    \
  do {                                                            \
    if (static_cast<int>(level) >= static_cast<int>(::policy::log_level())) { \
      ::policy::log_write(level, ::policy::detail::format_va(__VA_ARGS__));   \
    }                                                             \
  } while (0)

#define LOG_TRACE(...) POLICY_LOG(::policy::LogLevel::kTrace, __VA_ARGS__)
#define LOG_DEBUG(...) POLICY_LOG(::policy::LogLevel::kDebug, __VA_ARGS__)
#define LOG_INFO(...) POLICY_LOG(::policy::LogLevel::kInfo, __VA_ARGS__)
#define LOG_WARN(...) POLICY_LOG(::policy::LogLevel::kWarn, __VA_ARGS__)
#define LOG_ERROR(...) POLICY_LOG(::policy::LogLevel::kError, __VA_ARGS__)

}  // namespace policy
