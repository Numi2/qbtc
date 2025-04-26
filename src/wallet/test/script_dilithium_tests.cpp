// wallet/test/script_dilithium_tests.cpp
// Tests for the new OP_CHECKDILITHIUMVERIFY opcode and P2WPQC witness version 2

#include <boost/test/unit_test.hpp>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <uint256.h>

using valtype = std::vector<unsigned char>;

// Fake checker that approves all Dilithium signatures
struct FakeDilithiumChecker : public BaseSignatureChecker {
    bool CheckDilithiumSignature(std::span<const uint8_t> sig,
                                 std::span<const uint8_t> pubkey,
                                 const uint256& sighash) const override {
        // Accept any signature for testing
        return true;
    }
};

BOOST_AUTO_TEST_SUITE(script_dilithium_tests)

// Test that OP_CHECKDILITHIUMVERIFY pushes 'true' when checker approves
BOOST_AUTO_TEST_CASE(op_checkdilithiumverify_basic)
{
    // Prepare a dummy script: <sig> <pubkey> OP_CHECKDILITHIUMVERIFY
    valtype sig = {'s','i','g'};
    valtype pubkey = {'p','u','b','k','e','y'};
    CScript script;
    script << sig << pubkey << OP_CHECKDILITHIUMVERIFY;

    std::vector<valtype> stack;
    FakeDilithiumChecker checker;
    ScriptError err;
    bool ok = EvalScript(stack, script, /*flags=*/0, checker, SigVersion::BASE, &err);
    BOOST_CHECK_MESSAGE(ok, ScriptErrorString(err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    // One item on stack (true)
    BOOST_CHECK_EQUAL(stack.size(), 1U);
    BOOST_CHECK(CastToBool(stack[0]));
}

// Test P2WPQC witness version 2 branch
BOOST_AUTO_TEST_CASE(p2wpqc_witness_v2)
{
    // Prepare dummy program (32-byte; BLAKE3 hash length)
    std::vector<unsigned char> program(32, 0x42);
    // Prepare witness stack: [sig, pubkey]
    valtype sig = {'s','i','g'};
    valtype pubkey = {'p','k'};
    CScriptWitness witness;
    witness.stack = {sig, pubkey};

    // Build scriptPubKey: version 2 witness program
    CScript scriptPubKey;
    scriptPubKey << OP_2 << std::vector<unsigned char>(program.begin(), program.end());

    // Execute VerifyScript: scriptSig empty, scriptPubKey, witness
    std::vector<valtype> stack;
    FakeDilithiumChecker checker;
    ScriptError err;
    bool ok = VerifyScript(CScript(), scriptPubKey, &witness, /*flags=*/SCRIPT_VERIFY_WITNESS, checker, &err);
    BOOST_CHECK_MESSAGE(ok, ScriptErrorString(err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()