#include "policy/logging.hpp"

#include <atomic>
#include <cstdarg>
#include <ctime>
#include <vector>

namespace policy {
namespace {
std::atomic<int> g_level{static_cast<int>(LogLevel::kInfo)};
std::mutex g_mutex;

const char* level_tag(LogLevel l) {
  switch (l) {
    case LogLevel::kTrace: return "TRACE";
    case LogLevel::kDebug: return "DEBUG";
    case LogLevel::kInfo: return "INFO ";
    case LogLevel::kWarn: return "WARN ";
    case LogLevel::kError: return "ERROR";
    case LogLevel::kOff: return "OFF  ";
  }
  return "?????";
}
}  // namespace

void set_log_level(LogLevel level) { g_level.store(static_cast<int>(level), std::memory_order_relaxed); }

LogLevel log_level() { return static_cast<LogLevel>(g_level.load(std::memory_order_relaxed)); }

bool parse_log_level(std::string_view s, LogLevel& out) {
  if (s == "trace") { out = LogLevel::kTrace; return true; }
  if (s == "debug") { out = LogLevel::kDebug; return true; }
  if (s == "info") { out = LogLevel::kInfo; return true; }
  if (s == "warn" || s == "warning") { out = LogLevel::kWarn; return true; }
  if (s == "error") { out = LogLevel::kError; return true; }
  if (s == "off" || s == "none") { out = LogLevel::kOff; return true; }
  return false;
}

void log_write(LogLevel level, std::string_view message) {
  std::timespec ts{};
  std::timespec_get(&ts, TIME_UTC);
  std::tm tm{};
  const auto secs = static_cast<std::time_t>(ts.tv_sec);
  gmtime_r(&secs, &tm);

  // Sized for the worst case the compiler can prove rather than the 24 bytes
  // this actually produces: a struct tm is just ints as far as the format
  // checker knows, and a truncation warning here would be a real bug elsewhere.
  char stamp[64];
  std::snprintf(stamp, sizeof(stamp), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                static_cast<long>(ts.tv_nsec / 1'000'000));

  const std::lock_guard<std::mutex> lock(g_mutex);
  std::fprintf(stderr, "%s %s %.*s\n", stamp, level_tag(level), static_cast<int>(message.size()),
               message.data());
  std::fflush(stderr);
}

namespace detail {

std::string format_va(const char* fmt, ...) {
  std::va_list ap;
  va_start(ap, fmt);
  std::va_list ap2;
  va_copy(ap2, ap);
  const int n = std::vsnprintf(nullptr, 0, fmt, ap);
  va_end(ap);
  if (n < 0) {
    va_end(ap2);
    return std::string(fmt);
  }
  std::vector<char> buf(static_cast<std::size_t>(n) + 1);
  std::vsnprintf(buf.data(), buf.size(), fmt, ap2);
  va_end(ap2);
  return std::string(buf.data(), static_cast<std::size_t>(n));
}

}  // namespace detail
}  // namespace policy
