// src/script/sign.cpp

#include <script/sign.h>

#include <consensus/amount.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/keyorigin.h>
#include <script/miniscript.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <util/translation.h>
#include <util/vector.h>
#include <pqcrypto/dilithium3.h>     // ← new PQ‐safe API

typedef std::vector<unsigned char> valtype;

/*================================================================================
  MutableTransactionSignatureCreator
================================================================================*/

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(
    const CMutableTransaction& tx, unsigned int input_idx,
    const CAmount& amount, int hash_type)
    : m_txto{tx}
    , nIn{input_idx}
    , nHashType{hash_type}
    , amount{amount}
    , checker{&m_txto, nIn, amount, MissingDataBehavior::FAIL}
    , m_txdata(nullptr)
{}

MutableTransactionSignatureCreator::MutableTransactionSignatureCreator(
    const CMutableTransaction& tx, unsigned int input_idx,
    const CAmount& amount, const PrecomputedTransactionData* txdata,
    int hash_type)
    : m_txto{tx}
    , nIn{input_idx}
    , nHashType{hash_type}
    , amount{amount}
    , checker{txdata
              ? MutableTransactionSignatureChecker{&m_txto, nIn, amount, *txdata, MissingDataBehavior::FAIL}
              : MutableTransactionSignatureChecker{&m_txto, nIn, amount, MissingDataBehavior::FAIL}}
    , m_txdata(txdata)
{}

/**
 * Replace ECDSA with Dilithium3.  Sign the BLAKE3‐based sighash.
 */
bool MutableTransactionSignatureCreator::CreateSig(
    const SigningProvider& provider,
    std::vector<unsigned char>& vchSig,
    const CKeyID& address,
    const CScript& scriptCode,
    SigVersion sigversion) const
{
    assert(sigversion == SigVersion::BASE ||
           sigversion == SigVersion::WITNESS_V0);

    CKey key;
    if (!provider.GetKey(address, key)) return false;

    if (sigversion == SigVersion::WITNESS_V0 && !key.IsCompressed()) return false;
    if (sigversion == SigVersion::WITNESS_V0 && !MoneyRange(amount)) return false;

    const int hashtype = (nHashType == SIGHASH_DEFAULT
                          ? SIGHASH_ALL
                          : nHashType);

    // Compute the Blake3‐tagged sighash
    uint256 hash = SignatureHash(scriptCode, m_txto, nIn, hashtype, amount, sigversion, m_txdata);

    // PQ‐safe signature with Dilithium3
    if (!SignDilithium3(
            key.GetDilithiumSecret().data(),
            hash.begin(),
            hash.size(),
            vchSig)) {
        return false;
    }

    vchSig.push_back((unsigned char)hashtype);
    return true;
}

/**
 * New: Dilithium‐based Taproot signature method.
 */
bool MutableTransactionSignatureCreator::CreateDilithiumSig(
    const SigningProvider& provider,
    std::vector<unsigned char>& sig,
    const XOnlyPubKey& pubkey,
    const uint256* leaf_hash,
    const uint256* merkle_root,
    SigVersion sigversion) const
{
    assert(sigversion == SigVersion::TAPROOT ||
           sigversion == SigVersion::TAPSCRIPT);

    CKey key;
    if (!provider.GetKeyByXOnly(pubkey, key)) return false;

    if (!m_txdata
        || !m_txdata->m_bip341_taproot_ready
        || !m_txdata->m_spent_outputs_ready) {
        return false;
    }

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    if (sigversion == SigVersion::TAPSCRIPT) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF;
        if (!leaf_hash) return false;
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = *leaf_hash;
    }

    // Compute the Blake3‐tagged Taproot sighash
    uint256 hash = TaprootSignatureHash(m_txto, /*…params…*/ execdata, nIn, nHashType, sigversion, *m_txdata);

    // Sign with Dilithium3
    if (!SignDilithium3(
            key.GetDilithiumSecret().data(),
            hash.begin(),
            hash.size(),
            sig)) {
        return false;
    }

    if (nHashType) sig.push_back((unsigned char)nHashType);
    return true;
}

/*================================================================================
  Helpers: GetCScript, GetPubKey, CreateSig (static), CreateTaprootScriptSig, SignTaproot
================================================================================*/

static bool GetCScript(const SigningProvider& provider,
                       const SignatureData& sigdata,
                       const CScriptID& scriptid,
                       CScript& script)
{
    if (provider.GetCScript(scriptid, script)) return true;
    if (CScriptID(sigdata.redeem_script) == scriptid) {
        script = sigdata.redeem_script;
        return true;
    } else if (CScriptID(sigdata.witness_script) == scriptid) {
        script = sigdata.witness_script;
        return true;
    }
    return false;
}

static bool GetPubKey(const SigningProvider& provider,
                      const SignatureData& sigdata,
                      const CKeyID& address,
                      CPubKey& pubkey)
{
    // … unchanged …
    return provider.GetPubKey(address, pubkey);
}

/**
 * For scripts (P2WPKH, P2PKH, etc.) – still calls CreateSig above.
 */
static bool CreateSig(const BaseSignatureCreator& creator,
                      SignatureData& sigdata,
                      const SigningProvider& provider,
                      std::vector<unsigned char>& sig_out,
                      const CPubKey& pubkey,
                      const CScript& scriptcode,
                      SigVersion sigversion)
{
    // … unchanged …
    if (creator.CreateSig(provider, sig_out, keyid, scriptcode, sigversion)) {
        // …
        return true;
    }
    return false;
}

/**
 * Script‐path Taproot: replace Schnorr with Dilithium.
 */
static bool CreateTaprootScriptSig(const BaseSignatureCreator& creator,
                                   SignatureData& sigdata,
                                   const SigningProvider& provider,
                                   std::vector<unsigned char>& sig_out,
                                   const XOnlyPubKey& pubkey,
                                   const uint256& leaf_hash,
                                   SigVersion sigversion)
{
    // … key origin bookkeeping …
    auto lookup = std::make_pair(pubkey, leaf_hash);
    if (creator.CreateDilithiumSig(provider, sig_out, pubkey, &leaf_hash, nullptr, sigversion)) {
        sigdata.taproot_script_sigs[lookup] = sig_out;
        return true;
    }
    return false;
}

/**
 * Key‐path & fallback script‐path Taproot signing:
 * calls CreateDilithiumSig in place of Schnorr.
 */
static bool SignTaproot(const SigningProvider& provider,
                        const BaseSignatureCreator& creator,
                        const WitnessV1Taproot& output,
                        SignatureData& sigdata,
                        std::vector<valtype>& result)
{
    TaprootSpendData spenddata;
    TaprootBuilder builder;
    // … gather spend data …

    // Key‐path
    {
        // … origin bookkeeping …
        std::vector<unsigned char> sig;
        if (sigdata.taproot_key_path_sig.empty() &&
            creator.CreateDilithiumSig(provider, sig, output.internal_key, nullptr, &sigdata.tr_spenddata.merkle_root, SigVersion::TAPROOT)) {
            sigdata.taproot_key_path_sig = sig;
        }
        // … result assignment if key‐path works …
    }

    // Script‐path
    std::vector<std::vector<unsigned char>> best;
    for (auto& [key, ctr_blocks] : sigdata.tr_spenddata.scripts) {
        auto& [script, leaf_ver] = key;
        std::vector<std::vector<unsigned char>> stack;
        if (CreateTaprootScriptSig(provider, creator, provider, stack.emplace_back(), key.first, leaf_ver, SigVersion::TAPSCRIPT)) {
            // … build control‐block + script …
            if (best.empty() || SerializeSize(stack) < SerializeSize(best)) {
                best = stack;
            }
        }
    }
    if (!best.empty()) {
        result = std::move(best);
        return true;
    }
    return false;
}

/*================================================================================
  SignStep, PushAll, ProduceSignature, DataFromTransaction, UpdateInput, MergeSignatureData
================================================================================*/
// … all unchanged from original, aside from replacing CreateSchnorrSig calls
//     in SignStep()’s TAPSCRIPT and TAPROOT paths to CreateDilithiumSig …