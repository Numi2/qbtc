#include <boost/test/unit_test.hpp>

#include <crypto/dilithium.h>
#include <crypto/common.h>
#include <hash.h>
#include <random.h>
#include <util/strencodings.h>

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(dilithium_signature_tests)

// Helper function to generate test message
std::vector<uint8_t> GetTestMessage(size_t size = 32) {
    std::vector<uint8_t> message(size);
    GetStrongRandBytes(message.data(), size);
    return message;
}

BOOST_AUTO_TEST_CASE(dilithium_keygen)
{
    // Generate a Dilithium keypair
    Dilithium3KeyPair keypair;
    bool success = GenerateDilithiumKeyPair(keypair);
    
    // Verify key generation succeeded
    BOOST_CHECK(success);
    
    // Check key sizes are correct
    BOOST_CHECK_EQUAL(keypair.publicKey.size(), DILITHIUM3_PUBLICKEY_SIZE);
    BOOST_CHECK_EQUAL(keypair.privateKey.size(), DILITHIUM3_PRIVATEKEY_SIZE);
    
    // Verify keys are not empty
    BOOST_CHECK(!keypair.publicKey.empty());
    BOOST_CHECK(!keypair.privateKey.empty());
    
    // Verify public key differs from private key
    BOOST_CHECK(keypair.publicKey != keypair.privateKey);
}

BOOST_AUTO_TEST_CASE(dilithium_sign_verify)
{
    // Generate a keypair
    Dilithium3KeyPair keypair;
    GenerateDilithiumKeyPair(keypair);
    
    // Create a test message
    std::vector<uint8_t> message = GetTestMessage();
    
    // Sign the message
    std::vector<uint8_t> signature;
    bool signed_success = DilithiumSign(keypair.privateKey, message, signature);
    
    // Verify signing succeeded
    BOOST_CHECK(signed_success);
    BOOST_CHECK_EQUAL(signature.size(), DILITHIUM3_SIGNATURE_SIZE);
    
    // Verify the signature
    bool verify_success = DilithiumVerify(keypair.publicKey, message, signature);
    BOOST_CHECK(verify_success);
    
    // Modify the message and verify signature fails
    message[0] ^= 0x01;
    bool verify_fail = DilithiumVerify(keypair.publicKey, message, signature);
    BOOST_CHECK(!verify_fail);
}

BOOST_AUTO_TEST_CASE(dilithium_multiple_messages)
{
    // Generate a keypair
    Dilithium3KeyPair keypair;
    GenerateDilithiumKeyPair(keypair);
    
    // Sign and verify multiple messages with the same keypair
    for (int i = 0; i < 5; i++) {
        // Create a different test message each time
        std::vector<uint8_t> message = GetTestMessage();
        
        // Sign the message
        std::vector<uint8_t> signature;
        bool signed_success = DilithiumSign(keypair.privateKey, message, signature);
        BOOST_CHECK(signed_success);
        
        // Verify the signature
        bool verify_success = DilithiumVerify(keypair.publicKey, message, signature);
        BOOST_CHECK(verify_success);
    }
}

BOOST_AUTO_TEST_CASE(dilithium_cross_verification)
{
    // Generate two keypairs
    Dilithium3KeyPair keypair1, keypair2;
    GenerateDilithiumKeyPair(keypair1);
    GenerateDilithiumKeyPair(keypair2);
    
    // Create a test message
    std::vector<uint8_t> message = GetTestMessage();
    
    // Sign with first keypair
    std::vector<uint8_t> signature1;
    DilithiumSign(keypair1.privateKey, message, signature1);
    
    // Sign with second keypair
    std::vector<uint8_t> signature2;
    DilithiumSign(keypair2.privateKey, message, signature2);
    
    // Verify signatures
    bool verify1 = DilithiumVerify(keypair1.publicKey, message, signature1);
    bool verify2 = DilithiumVerify(keypair2.publicKey, message, signature2);
    BOOST_CHECK(verify1);
    BOOST_CHECK(verify2);
    
    // Cross-verification should fail
    bool cross_verify1 = DilithiumVerify(keypair1.publicKey, message, signature2);
    bool cross_verify2 = DilithiumVerify(keypair2.publicKey, message, signature1);
    BOOST_CHECK(!cross_verify1);
    BOOST_CHECK(!cross_verify2);
}

BOOST_AUTO_TEST_CASE(dilithium_signature_corruption)
{
    // Generate a keypair
    Dilithium3KeyPair keypair;
    GenerateDilithiumKeyPair(keypair);
    
    // Create a test message
    std::vector<uint8_t> message = GetTestMessage();
    
    // Sign the message
    std::vector<uint8_t> signature;
    DilithiumSign(keypair.privateKey, message, signature);
    
    // Verify original signature
    bool verify_original = DilithiumVerify(keypair.publicKey, message, signature);
    BOOST_CHECK(verify_original);
    
    // Corrupt the signature at different positions and verify it fails
    for (size_t i = 0; i < signature.size(); i += signature.size() / 10) {
        std::vector<uint8_t> corrupted_sig = signature;
        corrupted_sig[i] ^= 0xFF;  // Flip all bits at this position
        
        bool verify_corrupted = DilithiumVerify(keypair.publicKey, message, corrupted_sig);
        BOOST_CHECK(!verify_corrupted);
    }
}

BOOST_AUTO_TEST_CASE(dilithium_known_answer_test)
{
    // Test vector with known keys and expected output
    // These would be replaced with actual test vectors for Dilithium
    
    // Example format (replace with actual KAT values)
    std::string seed_hex = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
    std::vector<uint8_t> seed = ParseHex(seed_hex);
    
    // Generate deterministic keypair from seed
    Dilithium3KeyPair keypair;
    bool success = GenerateDilithiumKeyPairFromSeed(keypair, seed);
    BOOST_CHECK(success);
    
    // Known test message
    std::string message_hex = "54657374204D657373616765"; // "Test Message" in hex
    std::vector<uint8_t> message = ParseHex(message_hex);
    
    // Sign the message
    std::vector<uint8_t> signature;
    DilithiumSign(keypair.privateKey, message, signature);
    
    // Verify the signature
    bool verify = DilithiumVerify(keypair.publicKey, message, signature);
    BOOST_CHECK(verify);
    
    // If we had known answer test vectors, we would compare the generated
    // signature with the expected one:
    // std::string expected_sig_hex = "...known signature from test vector...";
    // std::vector<uint8_t> expected_sig = ParseHex(expected_sig_hex);
    // BOOST_CHECK(signature == expected_sig);
}

BOOST_AUTO_TEST_CASE(dilithium_large_message)
{
    // Generate a keypair
    Dilithium3KeyPair keypair;
    GenerateDilithiumKeyPair(keypair);
    
    // Create a large test message (1 MB)
    std::vector<uint8_t> large_message = GetTestMessage(1024 * 1024);
    
    // Hash the message first (typical approach for large messages)
    uint256 message_hash = Hash(large_message.begin(), large_message.end());
    std::vector<uint8_t> hash_bytes(message_hash.begin(), message_hash.end());
    
    // Sign the hash
    std::vector<uint8_t> signature;
    bool signed_success = DilithiumSign(keypair.privateKey, hash_bytes, signature);
    BOOST_CHECK(signed_success);
    
    // Verify the signature against the hash
    bool verify_success = DilithiumVerify(keypair.publicKey, hash_bytes, signature);
    BOOST_CHECK(verify_success);
}

BOOST_AUTO_TEST_CASE(dilithium_performance_test)
{
    // This test measures the performance of key generation, signing, and verification
    
    // Skip this test in normal test runs as it's meant for benchmarking
    if (!fExtendedTest)
        return;
    
    const int NUM_ITERATIONS = 100;
    
    // Key generation timing
    int64_t keygen_start = GetTimeMillis();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        Dilithium3KeyPair keypair;
        GenerateDilithiumKeyPair(keypair);
    }
    int64_t keygen_time = GetTimeMillis() - keygen_start;
    
    // Generate a keypair for signing/verification tests
    Dilithium3KeyPair keypair;
    GenerateDilithiumKeyPair(keypair);
    
    // Create a test message
    std::vector<uint8_t> message = GetTestMessage();
    
    // Signing timing
    int64_t signing_start = GetTimeMillis();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        std::vector<uint8_t> signature;
        DilithiumSign(keypair.privateKey, message, signature);
    }
    int64_t signing_time = GetTimeMillis() - signing_start;
    
    // Generate a signature for verification tests
    std::vector<uint8_t> signature;
    DilithiumSign(keypair.privateKey, message, signature);
    
    // Verification timing
    int64_t verify_start = GetTimeMillis();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        DilithiumVerify(keypair.publicKey, message, signature);
    }
    int64_t verify_time = GetTimeMillis() - verify_start;
    
    // Log performance results
    LogPrintf("Dilithium-III Performance (%d iterations):\n", NUM_ITERATIONS);
    LogPrintf("Key Generation: %.2f ms per operation\n", (double)keygen_time / NUM_ITERATIONS);
    LogPrintf("Signing: %.2f ms per operation\n", (double)signing_time / NUM_ITERATIONS);
    LogPrintf("Verification: %.2f ms per operation\n", (double)verify_time / NUM_ITERATIONS);
}

BOOST_AUTO_TEST_SUITE_END() 