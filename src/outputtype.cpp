// src/outputtype.cpp

#include <outputtype.h>
#include <dilithium_pubkey.h>
#include <script/signingprovider.h>
#include <script/script.h>
#include <script/standard.h>
#include <blake3.h>
#include <cassert>
#include <optional>
#include <string>
#include <vector>

static const std::string OUTPUT_TYPE_STRING_BECH32M = "bech32m";
static const std::string OUTPUT_TYPE_STRING_UNKNOWN = "unknown";

std::optional<OutputType> ParseOutputType(const std::string& type)
{
    if (type == OUTPUT_TYPE_STRING_BECH32M) {
        return OutputType::BECH32M;
    }
    return std::nullopt;
}

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OutputType::BECH32M: return OUTPUT_TYPE_STRING_BECH32M;
    case OutputType::UNKNOWN: return OUTPUT_TYPE_STRING_UNKNOWN;
    }
    assert(false);
}

static std::vector<unsigned char> Blake3Hash(const void* data, size_t len)
{
    uint8_t out[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (const uint8_t*)data, len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);
    return std::vector<unsigned char>(out, out + BLAKE3_OUT_LEN);
}

CTxDestination GetDestinationForKey(const CDilithiumPubKey& key, OutputType type)
{
    assert(type == OutputType::BECH32M);
    // compute BLAKE3-256 of raw public key bytes
    auto prog = Blake3Hash(key.data(), key.size());
    // witness version 1 (0x51) + program
    return WitnessUnknown{1, prog};
}

std::vector<CTxDestination> GetAllDestinationsForKey(const CDilithiumPubKey& key)
{
    return { GetDestinationForKey(key, OutputType::BECH32M) };
}

CTxDestination AddAndGetDestinationForScript(FlatSigningProvider& keystore, const CScript& script, OutputType type)
{
    assert(type == OutputType::BECH32M);
    // make script spendable
    keystore.scripts.emplace(CScriptID(script), script);
    // compute BLAKE3-256 of script
    auto prog = Blake3Hash(script.data(), script.size());
    return WitnessUnknown{1, prog};
}

std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest)
{
    if (auto w = std::get_if<WitnessUnknown>(&dest)) {
        if (w->version == 1 && w->program.size() == BLAKE3_OUT_LEN) {
            return OutputType::BECH32M;
        }
    }
    return std::nullopt;
}