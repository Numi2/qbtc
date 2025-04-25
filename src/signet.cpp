// src/signet.cpp

#include <signet.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <uint256.h>
#include <span.h>
#include <vector>
#include <cstdint>
#include <optional>

#include <dilithium.h>        // CRYSTALS-Dilithium API
#include <hash.h>             // ComputeMerkleRoot
#include <util/strencodings.h>

static constexpr uint8_t SIGNET_HEADER[4] = {0xec, 0xc7, 0xda, 0xa2};

/*
 * Strip out the bytes after SIGNET_HEADER from the witness_commitment script,
 * return them in 'out'.  Returns true if found.
 */
static bool FetchAndClearCommitmentSection(const std::span<const uint8_t> header,
                                           CScript& witness_commitment,
                                           std::vector<uint8_t>& out)
{
    CScript repl;
    bool found = false;
    std::vector<uint8_t> push;
    CScript::const_iterator pc = witness_commitment.begin();
    opcodetype opcode;
    while (witness_commitment.GetOp(pc, opcode, push)) {
        if (!found && push.size() > header.size()
            && std::memcmp(push.data(), header.data(), header.size()) == 0) {
            out.insert(out.end(),
                       push.begin() + header.size(),
                       push.end());
            push.resize(header.size());
            found = true;
        }
        repl << push;
        push.clear();
    }
    if (found) witness_commitment = repl;
    return found;
}

/*
 * Recompute merkle root treating the coinbase as modified_cb.
 */
static uint256 ComputeModifiedMerkleRoot(const CMutableTransaction& cb, const CBlock& block)
{
    std::vector<uint256> leaves(block.vtx.size());
    leaves[0] = cb.GetHash();
    for (size_t i = 1; i < block.vtx.size(); ++i)
        leaves[i] = block.vtx[i]->GetHash();
    return ComputeMerkleRoot(std::move(leaves));
}

std::optional<SignetTxs> SignetTxs::Create(const CBlock& block, const CScript& challenge)
{
    if (block.vtx.empty()) return std::nullopt;
    // Build the two signet tx skeletons
    CMutableTransaction to_spend, to_sign;
    to_spend.version = to_sign.version = 0;
    to_spend.nLockTime = to_sign.nLockTime = 0;
    to_spend.vin.emplace_back(COutPoint(), CScript(OP_0), 0);
    to_spend.vout.emplace_back(0, challenge);
    to_sign.vin.emplace_back(COutPoint(), CScript(), 0);
    to_sign.vout.emplace_back(0, CScript(OP_RETURN));

    // Strip signature blob from coinbase commitment
    CMutableTransaction mod_cb(*block.vtx[0]);
    int idx = GetWitnessCommitmentIndex(block);
    if (idx == NO_WITNESS_COMMITMENT) return std::nullopt;
    std::vector<uint8_t> sig_blob;
    if (FetchAndClearCommitmentSection(SIGNET_HEADER,
                                       mod_cb.vout[idx].scriptPubKey,
                                       sig_blob)) {
        // sig_blob is raw Dilithium signature
        // push into to_sign.vin[0].scriptSig
        to_sign.vin[0].scriptSig << sig_blob;
    }
    // Attach block data to to_spend
    uint256 merkle = ComputeModifiedMerkleRoot(mod_cb, block);
    std::vector<uint8_t> blob;
    VectorWriter vw{blob, 0};
    vw << block.nVersion
       << block.hashPrevBlock
       << merkle
       << block.nTime;
    to_spend.vin[0].scriptSig << blob;
    // link the two txs
    to_sign.vin[0].prevout = COutPoint(to_spend.GetHash(), 0);

    return SignetTxs{to_spend, to_sign};
}

bool CheckSignetBlockSolution(const CBlock& block, const Consensus::Params& p)
{
    if (block.GetHash() == p.hashGenesisBlock) return true;

    CScript challenge(p.signet_challenge.begin(), p.signet_challenge.end());
    auto opt = SignetTxs::Create(block, challenge);
    if (!opt) return false;
    auto& tx = *opt;

    // extract pubkey from challenge (first push)
    CScript::const_iterator pc = challenge.begin();
    opcodetype op;
    std::vector<uint8_t> pubkey;
    challenge.GetOp(pc, op, pubkey);

    // extract signature from to_sign.scriptSig (first push)
    pc = tx.m_to_sign.vin[0].scriptSig.begin();
    std::vector<uint8_t> sig;
    tx.m_to_sign.vin[0].scriptSig.GetOp(pc, op, sig);

    // rebuild block_data
    uint256 merkle = ComputeModifiedMerkleRoot(
        CMutableTransaction(tx.m_to_spend.vin[0].scriptSig.restream().data()), block);
    std::vector<uint8_t> data;
    VectorWriter vw{data, 0};
    vw << block.nVersion
       << block.hashPrevBlock
       << merkle
       << block.nTime;

    // Dilithium verification
    if (!DilithiumVerify(pubkey.data(), pubkey.size(),
                         data.data(), data.size(),
                         sig.data(), sig.size())) {
        return false;
    }
    return true;
}