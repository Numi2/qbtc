//   2009-present 
//    
//  

#ifndef BITCOIN_CRYPTO_HEX_BASE_H
#define BITCOIN_CRYPTO_HEX_BASE_H

#include <span.h>

#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Convert a span of bytes to a lower-case hexadecimal string.
 */
std::string HexStr(const std::span<const uint8_t> s);
inline std::string HexStr(const std::span<const char> s) { return HexStr(MakeUCharSpan(s)); }
inline std::string HexStr(const std::span<const std::byte> s) { return HexStr(MakeUCharSpan(s)); }

signed char HexDigit(char c);

#endif // BITCOIN_CRYPTO_HEX_BASE_H
