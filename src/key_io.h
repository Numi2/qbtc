// Key I/O: address encoding and decoding for QuBitcoin
#ifndef BITCOIN_KEY_IO_H
#define BITCOIN_KEY_IO_H

#include <addresstype.h>
#include <string>
#include <vector>
#include <util/bech32.h>

/**
 * Encode a CTxDestination to its string address representation.
 * Currently supports only PQC v2 addresses (qbc1p...).
 */
// Encode a destination to a Bech32m address string (PQC v2)
std::string EncodeDestination(const CTxDestination& dest);

/**
 * Decode a string address to CTxDestination.
 * error_msg returns human-readable error on failure.
 * error_locations optionally receives indices of parse errors.
 */
// Decode an address string to a destination, returning CNoDestination on error
CTxDestination DecodeDestination(const std::string& address, std::string& error_msg, std::vector<int>* error_locations);
// Convenience overload: no error info
inline CTxDestination DecodeDestination(const std::string& address) {
    std::string err;
    return DecodeDestination(address, err, nullptr);
}

#endif // BITCOIN_KEY_IO_H