// src/util/syserror.h

#ifndef QUBITCOIN_UTIL_SYSERROR_H
#define QUBITCOIN_UTIL_SYSERROR_H

#include <string>

/** Return system error string from errno value. Use this instead of
 * std::strerror, which is not thread-safe. For network errors use
 * NetworkErrorString from sock.h instead.
 */
std::string SysErrorString(int err);

#if defined(WIN32)
std::string Win32ErrorString(int err);
#endif

#endif // QUBITCOIN_UTIL_SYSERROR_H
