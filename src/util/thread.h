 // src/util/thread.h   

#ifndef QUBITCOIN_UTIL_THREAD_H
#define QUBITCOIN_UTIL_THREAD_H

#include <functional>
#include <string>

namespace util {
/**
 * A wrapper for do-something-once thread functions.
 */
void TraceThread(std::string_view thread_name, std::function<void()> thread_func);

} // namespace util

#endif // QUBITCOIN_UTIL_THREAD_H
