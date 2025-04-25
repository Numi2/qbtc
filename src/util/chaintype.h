// src/util/chaintype.h

#ifndef QUBITCOIN_UTIL_CHAINTYPE_H
#define QUBITCOIN_UTIL_CHAINTYPE_H

#include <optional>
#include <string>

enum class ChainType {
    MAIN,
    TESTNET,
    SIGNET,
    REGTEST,
    TESTNET4,
};

std::string ChainTypeToString(ChainType chain);

std::optional<ChainType> ChainTypeFromString(std::string_view chain);

#endif // QUBITCOIN_UTIL_CHAINTYPE_H
