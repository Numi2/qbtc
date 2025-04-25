// Key I/O: address encoding and decoding for QuBitcoin
#ifndef QUBITCOIN_KEY_IO_H
#define QUBITCOIN_KEY_IO_H
// key_io.cpp
#include "key_io.h"
#include <util/bech32.h>          // bech32::Encode/Decode + convertbits
#include <blake3.h>               // blake3_hasher, etc.
#include <script/standard.h>      // CTxDestination, CNoDestination, CKeyID

static const std::string HRP = "qbc";
static const int WIT_VERSION = 1; // encoded as the “p” in “qbc1p…”

std::string EncodeDestination(const CTxDestination& dest) {
    // we only support raw key‐hash destinations:
    const CKeyID* keyid = std::get_if<CKeyID>(&dest);
    if (!keyid) return {};

    // 1) serialize witness version + program
    std::vector<unsigned char> data;
    data.push_back(WIT_VERSION);
    // convert 8-bit bytes to 5-bit groups
    std::vector<unsigned char> prog5;
    bech32::ConvertBits<8,5,/*pad=*/true>(
        prog5,
        keyid->begin(), keyid->end()
    );
    data.insert(data.end(), prog5.begin(), prog5.end());

    // 2) encode as Bech32m
    return bech32::Encode(HRP, data, bech32::Encoding::BECH32M);
}

CTxDestination DecodeDestination(const std::string& address,
                                 std::string& error_msg,
                                 std::vector<int>* error_locations)
{
    // 1) bech32m decode
    std::string hrp_out;
    std::vector<unsigned char> data;
    if (!bech32::Decode(address, hrp_out, data, error_locations)) {
        error_msg = "Bech32 decode failed";
        return CNoDestination();
    }
    if (hrp_out != HRP) {
        error_msg = "Invalid HRP: expected \"" + HRP + "\", got \"" + hrp_out + "\"";
        return CNoDestination();
    }
    if (data.empty()) {
        error_msg = "Empty data section";
        return CNoDestination();
    }

    // 2) extract and check witness version
    int witver = data[0];
    if (witver != WIT_VERSION) {
        error_msg = "Unsupported witness version: " + std::to_string(witver);
        return CNoDestination();
    }

    // 3) convert back from 5-bit to 8-bit
    std::vector<unsigned char> prog5(data.begin()+1, data.end()), prog8;
    if (!bech32::ConvertBits<5,8,/*pad=*/false>(
            prog8,
            prog5.begin(), prog5.end()
        )) {
        error_msg = "Invalid padding in data part";
        return CNoDestination();
    }

    // 4) check length (we use full 32-byte BLAKE3)
    if (prog8.size() != 32) {
        error_msg = "Invalid program length: " + std::to_string(prog8.size());
        return CNoDestination();
    }

    // 5) build the CKeyID and return
    CKeyID keyid;
    std::copy(prog8.begin(), prog8.end(), keyid.begin());
    return keyid;

}

#endif // QUBITCOIN_KEY_IO_H