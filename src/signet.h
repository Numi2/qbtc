// src/signet.h

#ifndef QUBITCOIN_SIGNET_H
#define QUBITCOIN_SIGNET_H

#include <consensus/params.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <optional>

/**
 * Verify that a Signet block carries a valid quantum-safe (Dilithium) signature solution.
 */
bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& params);

/**
 * Build the two special transactions for a Signet block:
 *  - m_to_spend: commits to all block data except the Dilithium signature
 *  - m_to_sign:  contains the Dilithium signature itself
 */
class SignetTxs {
    template<class T1, class T2>
    SignetTxs(const T1& to_spend, const T2& to_sign)
        : m_to_spend{to_spend}, m_to_sign{to_sign} {}

public:
    static std::optional<SignetTxs> Create(const CBlock& block, const CScript& challenge);

    CTransaction m_to_spend;
    CTransaction m_to_sign;
};

#endif // QUBITCOIN_SIGNET_H