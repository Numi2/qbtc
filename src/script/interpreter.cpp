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

} // namespace qubitcoin::script
#endif // QUBITCOIN_SCRIPT_INTERPRETER_H