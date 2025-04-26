// src/pow.cpp

#include <pow.h>
#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>
#include <blake3.h>

/** Compute the proof-of-work hash using BLAKE3-256 over the serialized block header.
 *  Every node and every miner must BLAKE3-hash the same 80-byte slice.
 *  Do not include headerPubKey/headerSig (they are part of the full block and
 *  are serialized after the base header) in the hash input, otherwise signing
 *  the header after PoW invalidates the found nonce.
 */
static uint256 GetBlockProofHash(const CBlockHeader& header)
{
    // Serialize only the 80-byte CBlockHeader for proof-of-work hashing
    // Bytes hashed (in this order, little-endian):
    //   - 4 bytes:  nVersion
    //   - 32 bytes: hashPrevBlock
    //   - 32 bytes: hashMerkleRoot
    //   - 4 bytes:  nTime
    //   - 4 bytes:  nBits
    //   - 4 bytes:  nNonce
    // Note: headerPubKey and headerSig fields are part of CBlock and
    // serialized after the header; they are excluded from this hash input
    // so that signing the header post-PoW does not invalidate the nonce.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << header;

    // compute BLAKE3-256 over serialized header
    uint8_t out[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (const uint8_t*)ss.data(), ss.size());
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);

    return uint256(std::vector<unsigned char>(out, out + BLAKE3_OUT_LEN));
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // unchanged difficulty-adjustment interval logic...
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                return nProofOfWorkLimit;
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                pindex = pindex->pprev;
            return pindex->nBits;
        }
        return pindexLast->nBits;
    }

    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    nActualTimespan = std::clamp(nActualTimespan, params.nPowTargetTimespan/4, params.nPowTargetTimespan*4);

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    if (params.enforce_BIP94) {
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (bnNew > bnPowLimit) bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t minTS = params.nPowTargetTimespan/4;
        int64_t maxTS = params.nPowTargetTimespan*4;
        const arith_uint256 pow_limit = UintToArith256(params.powLimit);

        arith_uint256 observed;
        observed.SetCompact(new_nbits);

        // max upward adjustment
        arith_uint256 up = UintToArith256(old_nbits);
        up *= maxTS; up /= params.nPowTargetTimespan;
        if (up > pow_limit) up = pow_limit;
        if (arith_uint256(observed) > up) return false;

        // max downward adjustment
        arith_uint256 down = UintToArith256(old_nbits);
        down *= minTS; down /= params.nPowTargetTimespan;
        if (down > pow_limit) down = pow_limit;
        if (arith_uint256(observed) < down) return false;
    }
    else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params)
{
    uint256 hash = GetBlockProofHash(block);
    auto target = DeriveTarget(block.nBits, params.powLimit);
    if (!target) return false;
    return UintToArith256(hash) <= *target;
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative, fOverflow;
    arith_uint256 bnTarget;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};
    return bnTarget;
}