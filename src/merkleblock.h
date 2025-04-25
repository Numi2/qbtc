
// src/merkleblock.h

#ifndef QUBITCOIN_MERKLEBLOCK_H
#define QUBITCOIN_MERKLEBLOCK_H

#// src/merkle_block.hpp
#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <set>
#include <vector>

#include <serialize.h>
#include <uint256.h>
#include <common/bloom.h>
#include <primitives/block.h>
#include <crypto/blake3.h>
#include <crypto/ripemd160.h>

namespace qubitcoin {
namespace merkle {

using byte  = std::byte;
using Hash  = qubitcoin::crypto::CHash256;
using Uint256 = uint256;

/** Pack bits LSB-first into bytes. */
inline std::vector<byte> BitsToBytes(const std::vector<bool>& bits) noexcept {
    std::vector<byte> out((bits.size() + 7) / 8);
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i]) {
            out[i >> 3] |= static_cast<byte>(1u << (i & 7));
        }
    }
    return out;
}

/** Unpack bytes into LSB-first bits. */
inline std::vector<bool> BytesToBits(const std::vector<byte>& bytes) noexcept {
    std::vector<bool> out(bytes.size() * 8);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = (static_cast<uint8_t>(bytes[i >> 3]) >> (i & 7)) & 1;
    }
    return out;
}

/**
 * Partial Merkle Tree proof.
 * Builds a depth-first bit+hash proof that lets SPV clients
 * recover matched txids + merkle root, using BLAKE3.
 */
class PartialMerkleTree {
    uint32_t                nTx_;
    std::vector<bool>       bits_;
    std::vector<Uint256>    hashes_;
    bool                    bad_{false};

    static uint32_t CalcWidth(uint32_t height, uint32_t nTx) noexcept {
        return (nTx + (1u << height) - 1) >> height;
    }

    Uint256 CalcHash(uint32_t height, uint32_t pos,
                     const std::vector<Uint256>& txids) const {
        if (height == 0) {
            return txids[pos];
        }
        auto left  = CalcHash(height - 1, pos * 2,     txids);
        auto right = (pos * 2 + 1 < CalcWidth(height - 1, nTx_))
                   ? CalcHash(height - 1, pos * 2 + 1, txids)
                   : left;
        return qubitcoin::crypto::Hash256(left, right);
    }

    void TraverseBuild(uint32_t height, uint32_t pos,
                       const std::vector<Uint256>& txids,
                       const std::vector<bool>& match) {
        bool parentMatch = false;
        if (height == 0) {
            parentMatch = match[pos];
        } else {
            // check children
            uint32_t w = CalcWidth(height - 1, nTx_);
            for (uint32_t i = pos*2; i < std::min(pos*2+2, w); ++i) {
                parentMatch |= match[i];
            }
        }
        bits_.push_back(parentMatch);
        if (height == 0 || !parentMatch) {
            hashes_.push_back(CalcHash(height, pos, txids));
        } else {
            TraverseBuild(height-1, pos*2,     txids, match);
            if (pos*2+1 < CalcWidth(height-1, nTx_)) {
                TraverseBuild(height-1, pos*2+1, txids, match);
            }
        }
    }

    Uint256 TraverseExtract(uint32_t height, uint32_t pos,
                            size_t& bitsUsed, size_t& hashUsed,
                            std::vector<Uint256>& outMatch,
                            std::vector<uint32_t>& outIdx) {
        if (bitsUsed >= bits_.size()) { bad_ = true; return {}; }
        bool parentMatch = bits_[bitsUsed++];
        if (height == 0 || !parentMatch) {
            if (hashUsed >= hashes_.size()) { bad_ = true; return {}; }
            Uint256 h = hashes_[hashUsed++];
            if (height == 0 && parentMatch) {
                outMatch.push_back(h);
                outIdx.push_back(pos);
            }
            return h;
        }
        auto left = TraverseExtract(height-1, pos*2, bitsUsed, hashUsed, outMatch, outIdx);
        auto right = (pos*2+1 < CalcWidth(height-1, nTx_))
                   ? TraverseExtract(height-1, pos*2+1, bitsUsed, hashUsed, outMatch, outIdx)
                   : left;
        return qubitcoin::crypto::Hash256(left, right);
    }

public:
    PartialMerkleTree() noexcept = default;

    /** Build from txids+match mask. */
    PartialMerkleTree(const std::vector<Uint256>& txids,
                      const std::vector<bool>& match) :
        nTx_(txids.size())
    {
        // tree height = ceil(log2(nTx_))
        uint32_t h = 0;
        while (CalcWidth(h, nTx_) > 1) ++h;
        bits_.reserve(h * nTx_);
        hashes_.reserve(nTx_);
        TraverseBuild(h, 0, txids, match);
    }

    /**
     * Recover matched txids+indices and return merkle root.
     * Returns zero on error.
     */
    Uint256 ExtractMatches(std::vector<Uint256>& outMatch,
                           std::vector<uint32_t>& outIdx)
    {
        outMatch.clear();
        outIdx.clear();
        uint32_t h = 0;
        while (CalcWidth(h, nTx_) > 1) ++h;
        size_t bitsUsed = 0, hashUsed = 0;
        Uint256 root = TraverseExtract(h, 0, bitsUsed, hashUsed, outMatch, outIdx);
        if (bad_ ||
            hashUsed != hashes_.size() ||
            bitsUsed != bits_.size()) {
            return Uint256{};
        }
        return root;
    }

    uint32_t GetNumTransactions() const noexcept { return nTx_; }

    SERIALIZE_METHODS(PartialMerkleTree, obj) {
        READWRITE(obj.nTx_, obj.hashes_);
        std::vector<byte> b = BitsToBytes(obj.bits_);
        READWRITE(b);
        SER_READ(obj.bits_ = BytesToBits(b));
        SER_READ(obj.bad_ = false);
    }
};


/**
 * Light-client MerkleBlock: header + PartialMerkleTree + matched txs.
 */
class MerkleBlock {
public:
    CBlockHeader                          header;
    PartialMerkleTree                     proof;
    std::vector<std::pair<uint32_t,Uint256>> matches;

    MerkleBlock() noexcept = default;

    /** From block + bloom: marks & proofs matching txs. */
    MerkleBlock(const CBlock& block, CBloomFilter& filter) {
        header = block.GetHeader();
        std::vector<Uint256> txids;
        std::vector<bool>   match;
        txids.reserve(block.vtx.size());
        match.reserve(block.vtx.size());
        for (uint32_t i = 0; i < block.vtx.size(); ++i) {
            auto h = block.vtx[i].GetHash();
            txids.push_back(h);
            bool m = filter.IsRelevantAndUpdate(block.vtx[i]);
            match.push_back(m);
            if (m) matches.emplace_back(i, h);
        }
        proof = PartialMerkleTree(txids, match);
    }

    /** From block + explicit txid set. */
    MerkleBlock(const CBlock& block, const std::set<Txid>& s) {
        header = block.GetHeader();
        std::vector<Uint256> txids;
        std::vector<bool>   match;
        txids.reserve(block.vtx.size());
        match.reserve(block.vtx.size());
        for (uint32_t i = 0; i < block.vtx.size(); ++i) {
            auto h = block.vtx[i].GetHash();
            txids.push_back(h);
            bool m = s.count(h);
            match.push_back(m);
            if (m) matches.emplace_back(i, h);
        }
        proof = PartialMerkleTree(txids, match);
    }

    SERIALIZE_METHODS(MerkleBlock, obj) {
        READWRITE(obj.header, obj.proof);
    }
};

} // namespace merkle
} // namespace qubitcoin

#endif // QUBITCOIN_MERKLEBLOCK_H
