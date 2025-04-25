
// src/util/exception.h 

#ifndef QUBITCOIN_UTIL_EXCEPTION_H
#define QUBITCOIN_UTIL_EXCEPTION_H

#include <exception>
#include <string_view>

void PrintExceptionContinue(const std::exception* pex, std::string_view thread_name);

#endif // QUBITCOIN_UTIL_EXCEPTION_H
