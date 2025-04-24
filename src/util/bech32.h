// Bech32 and Bech32m encoding/decoding (BIP-173, BIP-350)
#ifndef BITCOIN_UTIL_BECH32_H
#define BITCOIN_UTIL_BECH32_H

#include <string>
#include <vector>

namespace bech32 {
/** Encoding constants */
enum class Encoding { BECH32 = 1, BECH32M = 2 };

/**
 * Decode a Bech32 or Bech32m string to its HRP and data values.
 * @param[in] str The bech32 string.
 * @param[out] hrp The human-readable part.
 * @param[out] data The data values (5-bit integers).
 * @param[out] encoding Which encoding was detected (BECH32 or BECH32M).
 * @return True if decoding was successful.
 */
bool Decode(const std::string& str, std::string& hrp, std::vector<int>& data, Encoding& encoding);

/**
 * Encode HRP and data values to a Bech32 or Bech32m string.
 * @param[in] hrp Human-readable part.
 * @param[in] data Data values (5-bit integers).
 * @param[in] encoding BECH32 or BECH32M.
 * @return Encoded bech32 string.
 */
std::string Encode(const std::string& hrp, const std::vector<int>& data, Encoding encoding);
}

/**
 * Convert bits from one size to another.
 * @param[in] in Input bytes.
 * @param[in] frombits Number of input bits.
 * @param[in] tobits Number of output bits.
 * @param[in] pad Whether to pad the last value.
 * @param[out] out Output values.
 * @return True if successful.
 */
bool ConvertBits(const std::vector<unsigned char>& in, int frombits, int tobits, bool pad, std::vector<int>& out);

#endif // BITCOIN_UTIL_BECH32_H