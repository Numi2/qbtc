// src/pow.h

#ifndef QUBITCOIN_POW_H
#define QUBITCOIN_POW_H

#include <consensus/params.h>
#include <optional>
#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/**
 * Decode compact “nBits” into a 256-bit target.
 * Returns nullopt if overflow, zero or exceeding pow_limit.
 */
std::optional<arith_uint256>
DeriveTarget(unsigned int nBits, const uint256& pow_limit);

/**
 * Compute next difficulty (compact form) for a new block
 *  – based on last index, new header time, and consensus params.
 */
unsigned int GetNextWorkRequired(
    const CBlockIndex* pindexLast,
    const CBlockHeader* pblock,
    const Consensus::Params& params);

/**
 * Core difficulty‐retarget algorithm over a timespan window.
 */
unsigned int CalculateNextWorkRequired(
    const CBlockIndex* pindexLast,
    int64_t nFirstBlockTime,
    const Consensus::Params& params);

/**
 * Verify that a block’s header—hashed with BLAKE3—meets the target in params.
 */
bool CheckProofOfWork(
    const CBlockHeader& block,
    const Consensus::Params& params);

/**
 * Ensure new_nbits is within allowed bounds (×¼…×4 per interval)
 * or identical off‐interval (unless min-diff blocks allowed).
 */
bool PermittedDifficultyTransition(
    const Consensus::Params& params,
    int64_t height,
    uint32_t old_nbits,
    uint32_t new_nbits);

#endif // QUBITCOIN_POW_H