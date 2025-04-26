#ifndef QUBITCOIN_SCRIPT_INTERPRETER_H
#define QUBITCOIN_SCRIPT_INTERPRETER_H

#pragma once

#include <cstdint>
#include <vector>
#include <optional>

#include <consensus/amount.h>
#include <crypto/blake3.h>
#include <crypto/dilithium.h>
#include <primitives/transaction.h>
#include <script/script_error.h>
#include <span.h>
#include <uint256.h>
// For signature hashing preimage
#include <streams.h>
#include <serialize.h>
#include <vector>
#include <util/blake3_tagged.h>

namespace qubitcoin::script {

//--- sighash flags
enum : uint32_t {
    SIGHASH_ALL            = 1,
    SIGHASH_NONE           = 2,
    SIGHASH_SINGLE         = 3,
    SIGHASH_ANYONECANPAY   = 0x80,
    SIGHASH_DEFAULT        = 0
};

//--- script verification flags (same bit-positions as Bitcoin)
enum : uint32_t {
    SCRIPT_VERIFY_NONE                      = 0,
    SCRIPT_VERIFY_P2SH                      = (1U << 0),
    SCRIPT_VERIFY_CLEANSTACK                = (1U << 8),
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY       = (1U << 9),
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY       = (1U << 10),
    SCRIPT_VERIFY_WITNESS                   = (1U << 11),
    SCRIPT_VERIFY_TAPROOT                   = (1U << 17),
    SCRIPT_VERIFY_END_MARKER                = (1U << 18)
};

//--- Signature hash (BLAKE3-tagged replaces SHA256d)
uint256 SignatureHash(
    const CScript&          scriptCode,
    const CTransaction&     txTo,
    unsigned                nIn,
    uint32_t                nHashType,
    CAmount                 amount,
    uint32_t                flags,
    const PrecomputedTransactionData* cache = nullptr
);

//--- Base signature checker: only Dilithium
class BaseSignatureChecker {
public:
    virtual bool CheckDilithiumSignature(
        std::span<const uint8_t> sig,
        std::span<const uint8_t> pubkey,
        const uint256&           sighash
    ) const = 0;

    virtual bool CheckLockTime(int64_t nLockTime)    const { return false; }
    virtual bool CheckSequence(int64_t nSequence)    const { return false; }
    virtual ~BaseSignatureChecker() = default;
};

//--- Generic tx signature checker using Dilithium::Verify
template <typename T>
class TransactionSignatureChecker : public BaseSignatureChecker {
    const T*    txTo;
    unsigned    nIn;
    CAmount     amount;
    uint32_t    flags;
public:
    TransactionSignatureChecker(
        const T*    txToIn,
        unsigned    nInIn,
        CAmount     amountIn,
        uint32_t    flagsIn
    ) noexcept
      : txTo(txToIn), nIn(nInIn), amount(amountIn), flags(flagsIn) {}

    bool CheckDilithiumSignature(
        std::span<const uint8_t> sig,
        std::span<const uint8_t> pubkey,
        const uint256&           sighash
    ) const override {
        return crypto::Dilithium::Verify(pubkey, sig, sighash);
    }
};

//--- Tagged Blake3 writers for taproot sighash
extern const Blake3Writer HASHER_BLAKE3_TAPSIGHASH;  // tag "TapSighash"
extern const Blake3Writer HASHER_BLAKE3_TAPLEAF;     // tag "TapLeaf"
extern const Blake3Writer HASHER_BLAKE3_TAPBRANCH;   // tag "TapBranch"

//--- Script evaluation
bool EvalScript(
    std::vector<std::vector<uint8_t>>& stack,
    const CScript&                     script,
    uint32_t                           flags,
    const BaseSignatureChecker&       checker,
    ScriptError*                       error = nullptr
);

bool VerifyScript(
    const CScript&                scriptSig,
    const CScript&                scriptPubKey,
    const CScriptWitness*         witness,
    uint32_t                      flags,
    const BaseSignatureChecker&  checker,
    ScriptError*                  error = nullptr
);

/**
 * SignatureHash: Blake3-tagged replacement for BIP-143/SHA256d SIGHASH.
 * Serializes the scriptCode, transaction, input index, hash type, amount, and flags,
 * then computes a Blake3 tagged hash over the preimage.
 */
inline uint256 SignatureHash(
    const CScript&              scriptCode,
    const CTransaction&         txTo,
    unsigned                    nIn,
    uint32_t                    nHashType,
    CAmount                     amount,
    uint32_t                    flags,
    const PrecomputedTransactionData* cache)
{
    // BIP-143 witness v0 Blake3 preimage
    // 1) hashPrevouts
    CDataStream ssPrev(SER_GETHASH, 0);
    for (const auto& txin : txTo.vin) {
        ssPrev << txin.prevout.hash;
        ssPrev << txin.prevout.n;
    }
    auto hp = TaggedBlake3Hash("BIP143/Prevouts", std::vector<uint8_t>(ssPrev.begin(), ssPrev.end()));
    // 2) hashSequence
    CDataStream ssSeq(SER_GETHASH, 0);
    for (const auto& txin : txTo.vin) {
        ssSeq << txin.nSequence;
    }
    auto hs = TaggedBlake3Hash("BIP143/Sequence", std::vector<uint8_t>(ssSeq.begin(), ssSeq.end()));
    // 3) hashOutputs
    CDataStream ssOut(SER_GETHASH, 0);
    for (const auto& txout : txTo.vout) {
        ssOut << txout.nValue;
        ssOut << txout.scriptPubKey;
    }
    auto ho = TaggedBlake3Hash("BIP143/Outputs", std::vector<uint8_t>(ssOut.begin(), ssOut.end()));
    // 4) build final preimage
    CDataStream ss(SER_GETHASH, 0);
    ss << txTo.nVersion;
    ss.write((char*)hp.data(), hp.size());
    ss.write((char*)hs.data(), hs.size());
    // outpoint
    ss << txTo.vin[nIn].prevout.hash;
    ss << txTo.vin[nIn].prevout.n;
    // scriptCode
    ss << scriptCode;
    // value and sequence
    ss << amount;
    ss << txTo.vin[nIn].nSequence;
    // outputs hash
    ss.write((char*)ho.data(), ho.size());
    // locktime and hash type
    ss << txTo.nLockTime;
    ss << nHashType;
    auto final = TaggedBlake3Hash("BIP143/Sighash", std::vector<uint8_t>(ss.begin(), ss.end()));
    return uint256{std::span{final.data(), final.size()}};
}

/**
 * TaprootSignatureHash: Blake3-tagged replacement for BIP-341 taproot sighash.
 * Serializes the transaction, input index, hash type, and execution data,
 * then computes a Blake3 tagged hash over the preimage.
 */
inline uint256 TaprootSignatureHash(
    const CTransaction&                         txTo,
    const ScriptExecutionData&                  execdata,
    unsigned                                    nIn,
    int                                         nHashType,
    SigVersion                                  sigversion,
    const PrecomputedTransactionData&           txdata)
{
    // BIP-341 Taproot signature hash preimage
    bool anyone = (nHashType & SIGHASH_ANYONECANPAY) != 0;
    uint8_t base_type = nHashType & 0x03;

    // 1. hashPrevouts
    std::vector<uint8_t> buf;
    CDataStream ss_prev(SER_GETHASH, 0);
    if (!anyone) {
        for (const auto& txin : txTo.vin) {
            ss_prev << txin.prevout.hash;
            ss_prev << txin.prevout.n;
        }
        buf.assign(ss_prev.begin(), ss_prev.end());
    }
    auto hashPrevouts = anyone
        ? std::vector<uint8_t>(32, 0)
        : TaggedBlake3Hash("TapSighash", buf);

    // 2. hashAmounts
    CDataStream ss_amt(SER_GETHASH, 0);
    if (!anyone) {
        for (size_t i = 0; i < txTo.vin.size(); ++i) {
            ss_amt << txdata.m_spent_outputs[i].nValue;
        }
        buf.assign(ss_amt.begin(), ss_amt.end());
    }
    auto hashAmounts = anyone
        ? std::vector<uint8_t>(32, 0)
        : TaggedBlake3Hash("TapSighash", buf);

    // 3. hashScriptPubKeys
    CDataStream ss_spk(SER_GETHASH, 0);
    if (!anyone) {
        for (size_t i = 0; i < txTo.vin.size(); ++i) {
            ss_spk << txdata.m_spent_outputs[i].scriptPubKey;
        }
        buf.assign(ss_spk.begin(), ss_spk.end());
    }
    auto hashScriptPubKeys = anyone
        ? std::vector<uint8_t>(32, 0)
        : TaggedBlake3Hash("TapSighash", buf);

    // 4. hashSequences
    CDataStream ss_seq(SER_GETHASH, 0);
    if (!anyone) {
        for (const auto& txin : txTo.vin) {
            ss_seq << txin.nSequence;
        }
        buf.assign(ss_seq.begin(), ss_seq.end());
    }
    auto hashSequences = anyone
        ? std::vector<uint8_t>(32, 0)
        : TaggedBlake3Hash("TapSighash", buf);

    // 5. hashOutputs
    CDataStream ss_out(SER_GETHASH, 0);
    if (base_type == SIGHASH_ALL) {
        for (const auto& txout : txTo.vout) {
            ss_out << txout.nValue;
            ss_out << txout.scriptPubKey;
        }
    } else if (base_type == SIGHASH_SINGLE) {
        if (nIn < txTo.vout.size()) {
            const auto& txout = txTo.vout[nIn];
            ss_out << txout.nValue;
            ss_out << txout.scriptPubKey;
        }
    }
    buf.assign(ss_out.begin(), ss_out.end());
    auto hashOutputs = (base_type == SIGHASH_NONE)
        ? std::vector<uint8_t>(32, 0)
        : TaggedBlake3Hash("TapSighash", buf);

    // 6. hashAnnex
    std::vector<uint8_t> hashAnnex(32, 0);
    if (execdata.m_annex_present) {
        CDataStream ss_ann(SER_GETHASH, 0);
        ss_ann << execdata.m_annex;  // annex: raw witness annex data
        auto tmp = std::vector<uint8_t>(ss_ann.begin(), ss_ann.end());
        hashAnnex = TaggedBlake3Hash("TapSighash", tmp);
    }

    // Build full preimage
    CDataStream ss(SER_GETHASH, 0);
    ss << txTo.nVersion;
    ss.write((char*)hashPrevouts.data(), hashPrevouts.size());
    ss.write((char*)hashAmounts.data(), hashAmounts.size());
    ss.write((char*)hashScriptPubKeys.data(), hashScriptPubKeys.size());
    ss.write((char*)hashSequences.data(), hashSequences.size());
    ss.write((char*)hashOutputs.data(), hashOutputs.size());
    ss.write((char*)hashAnnex.data(), hashAnnex.size());
    ss << txTo.nLockTime;
    ss << nHashType;

    // Per-input data
    ss << txTo.vin[nIn].prevout.hash;
    ss << txTo.vin[nIn].prevout.n;
    ss << txdata.m_spent_outputs[nIn].nValue;
    ss << txdata.m_spent_outputs[nIn].scriptPubKey;
    ss << txTo.vin[nIn].nSequence;

    // Annex if present
    if (execdata.m_annex_present) ss << execdata.m_annex;

    // Tapscript path fields (leaf hash + control blocks)
    if (sigversion == SigVersion::TAPSCRIPT) {
        ss << execdata.m_tapleaf_hash;
        for (const auto& cb : execdata.m_control_blocks) ss << cb;
    }

    auto pre = std::vector<uint8_t>(ss.begin(), ss.end());
    auto out = TaggedBlake3Hash("TapSighash", pre);
    return uint256{std::span{out.data(), out.size()}};
}
} // namespace qubitcoin::script
#endif // QUBITCOIN_SCRIPT_INTERPRETER_H