#include <boost/test/unit_test.hpp>

#include <key.h>
#include <util/strencodings.h>
#include <crypto/dilithium.h>
#include <random.h>
#include <vector>
#include <string>

BOOST_AUTO_TEST_SUITE(quantum_signature_tests)

BOOST_AUTO_TEST_CASE(dilithium_key_generation_test)
{
    // Test key generation
    DilithiumKey key;
    BOOST_CHECK(key.GenerateKey());
    
    // Check that public and private keys are not empty
    std::vector<uint8_t> pubKey = key.GetPubKey();
    std::vector<uint8_t> privKey = key.GetPrivKey();
    
    BOOST_CHECK(!pubKey.empty());
    BOOST_CHECK(!privKey.empty());
    
    // Verify expected key sizes for Dilithium-III
    // Public key should be 1312 bytes
    BOOST_CHECK_EQUAL(pubKey.size(), 1312);
    // Private key should be 2528 bytes
    BOOST_CHECK_EQUAL(privKey.size(), 2528);
}

BOOST_AUTO_TEST_CASE(dilithium_signature_verification_test)
{
    // Generate new key
    DilithiumKey key;
    BOOST_CHECK(key.GenerateKey());
    
    // Create message to sign
    std::string message = "Test message for quantum signature verification";
    std::vector<uint8_t> messageBytes(message.begin(), message.end());
    
    // Sign the message
    std::vector<uint8_t> signature;
    BOOST_CHECK(key.Sign(messageBytes, signature));
    
    // Verify the signature is not empty and has expected size
    // Dilithium-III signatures should be 2420 bytes
    BOOST_CHECK(!signature.empty());
    BOOST_CHECK_EQUAL(signature.size(), 2420);
    
    // Verify the signature with the public key
    bool validSignature = key.Verify(messageBytes, signature);
    BOOST_CHECK(validSignature);
    
    // Test verification with modified message
    messageBytes[0] ^= 0x01; // Flip a bit
    bool invalidSignature = key.Verify(messageBytes, signature);
    BOOST_CHECK(!invalidSignature);
    
    // Reset message and modify signature
    messageBytes[0] ^= 0x01; // Restore original message
    signature[0] ^= 0x01; // Flip a bit in the signature
    invalidSignature = key.Verify(messageBytes, signature);
    BOOST_CHECK(!invalidSignature);
}

BOOST_AUTO_TEST_CASE(dilithium_serialization_test)
{
    // Generate key
    DilithiumKey originalKey;
    BOOST_CHECK(originalKey.GenerateKey());
    
    // Serialize and deserialize public key
    std::vector<uint8_t> pubKey = originalKey.GetPubKey();
    std::string hexPubKey = HexStr(pubKey);
    
    std::vector<uint8_t> deserializedPubKey = ParseHex(hexPubKey);
    BOOST_CHECK_EQUAL_COLLECTIONS(pubKey.begin(), pubKey.end(), 
                                deserializedPubKey.begin(), deserializedPubKey.end());
    
    // Create another key and load the public key
    DilithiumKey importedKey;
    BOOST_CHECK(importedKey.SetPubKey(deserializedPubKey));
    
    // Verify signatures can be verified with imported public key
    std::string message = "Test message for serialization";
    std::vector<uint8_t> messageBytes(message.begin(), message.end());
    
    // Sign with original key
    std::vector<uint8_t> signature;
    BOOST_CHECK(originalKey.Sign(messageBytes, signature));
    
    // Verify with imported key
    bool validSignature = importedKey.Verify(messageBytes, signature);
    BOOST_CHECK(validSignature);
}

BOOST_AUTO_TEST_CASE(dilithium_performance_test)
{
    // This test measures the performance of key generation, signing, and verification
    
    // Key generation time
    int64_t startTime = GetTimeMillis();
    DilithiumKey key;
    BOOST_CHECK(key.GenerateKey());
    int64_t keyGenTime = GetTimeMillis() - startTime;
    
    // Print key generation time
    // printf("Dilithium key generation time: %d ms\n", (int)keyGenTime);
    
    // Create a 1KB message
    std::vector<uint8_t> messageBytes(1024);
    GetRandBytes(messageBytes.data(), messageBytes.size());
    
    // Measure signing time
    startTime = GetTimeMillis();
    std::vector<uint8_t> signature;
    BOOST_CHECK(key.Sign(messageBytes, signature));
    int64_t signTime = GetTimeMillis() - startTime;
    
    // Print signing time
    // printf("Dilithium signing time for 1KB: %d ms\n", (int)signTime);
    
    // Measure verification time
    startTime = GetTimeMillis();
    bool valid = key.Verify(messageBytes, signature);
    int64_t verifyTime = GetTimeMillis() - startTime;
    
    // Print verification time
    // printf("Dilithium verification time for 1KB: %d ms\n", (int)verifyTime);
    
    // Verification should succeed
    BOOST_CHECK(valid);
    
    // Set some reasonable upper bounds for performance on slow systems
    // These values are generous to avoid test failures on very slow systems
    BOOST_CHECK(keyGenTime < 5000);  // Key generation < 5 seconds
    BOOST_CHECK(signTime < 1000);    // Signing < 1 second
    BOOST_CHECK(verifyTime < 1000);  // Verification < 1 second
}

BOOST_AUTO_TEST_CASE(dilithium_batch_verification_test)
{
    const int NUM_KEYS = 5;
    std::vector<DilithiumKey> keys(NUM_KEYS);
    std::vector<std::vector<uint8_t>> messages(NUM_KEYS);
    std::vector<std::vector<uint8_t>> signatures(NUM_KEYS);
    
    // Generate keys and create signatures
    for (int i = 0; i < NUM_KEYS; i++) {
        // Generate key
        BOOST_CHECK(keys[i].GenerateKey());
        
        // Create random message
        messages[i].resize(100 + i * 10); // Different sized messages
        GetRandBytes(messages[i].data(), messages[i].size());
        
        // Sign message
        BOOST_CHECK(keys[i].Sign(messages[i], signatures[i]));
    }
    
    // Verify all signatures individually
    for (int i = 0; i < NUM_KEYS; i++) {
        BOOST_CHECK(keys[i].Verify(messages[i], signatures[i]));
    }
    
    // Verify that signatures don't verify for different messages or keys
    for (int i = 0; i < NUM_KEYS; i++) {
        for (int j = 0; j < NUM_KEYS; j++) {
            if (i != j) {
                // Different message, same key
                BOOST_CHECK(!keys[i].Verify(messages[j], signatures[i]));
                
                // Different key, same message
                BOOST_CHECK(!keys[j].Verify(messages[i], signatures[i]));
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END() 