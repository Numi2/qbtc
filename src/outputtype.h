// src/outputtype.h

#ifndef QUBITCOIN_OUTPUTTYPE_H
#define QUBITCOIN_OUTPUTTYPE_H

#include <addresstype.h>
#include <script/signingprovider.h>
#include <dilithium_pubkey.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

/** Supported address output types on QubitCoin (only native Bech32m). */
enum class OutputType {
    BECH32M,
    UNKNOWN,
};

static constexpr auto OUTPUT_TYPES = std::array<OutputType, 1>{
    OutputType::BECH32M,
};

/** Parse an output‐type label ("bech32m") into an enum. */
std::optional<OutputType> ParseOutputType(const std::string& str);

/** Get the lowercase label for an OutputType. */
const std::string& FormatOutputType(OutputType type);

/**
 * Produce a Bech32m destination ("qbc1p…") for the given Dilithium public key.
 * Caller must have called LearnRelatedScripts beforehand if needed.
 */
CTxDestination GetDestinationForKey(const CDilithiumPubKey& key, OutputType type);

/**  
 * Enumerate all destinations (here, just Bech32m) for a Dilithium key.  
 */
std::vector<CTxDestination> GetAllDestinationsForKey(const CDilithiumPubKey& key);

/**
 * Add the given script to the keystore and return its Bech32m destination.
 */
CTxDestination AddAndGetDestinationForScript(
    FlatSigningProvider& keystore,
    const CScript& script,
    OutputType type);

/** Determine the OutputType (BECH32M or UNKNOWN) from a CTxDestination. */
std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest);

#endif // QUBITCOIN_OUTPUTTYPE_H