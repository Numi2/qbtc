#include <boost/test/unit_test.hpp>

#include <crypto/dilithium/dilithium.h>
#include <crypto/dilithium/dilithium_api.h>
#include <crypto/common.h>
#include <util/strencodings.h>
#include <random.h>

#include <array>
#include <vector>
#include <string>

BOOST_AUTO_TEST_SUITE(dilithium_verification_tests)

BOOST_AUTO_TEST_CASE(known_key_generation)
{
    // Test that key generation is deterministic with a fixed seed
    unsigned char seed[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    
    // Generate two keypairs with the same seed
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES> pk1;
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES> sk1;
    
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES> pk2;
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES> sk2;
    
    int ret1 = PQCLEAN_DILITHIUM3_crypto_sign_keypair_from_seed(pk1.data(), sk1.data(), seed);
    int ret2 = PQCLEAN_DILITHIUM3_crypto_sign_keypair_from_seed(pk2.data(), sk2.data(), seed);
    
    // Check return values
    BOOST_CHECK_EQUAL(ret1, 0);
    BOOST_CHECK_EQUAL(ret2, 0);
    
    // Check that both keypairs are identical
    BOOST_CHECK(pk1 == pk2);
    BOOST_CHECK(sk1 == sk2);
}

BOOST_AUTO_TEST_CASE(sign_and_verify)
{
    // Generate a keypair
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES> pk;
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES> sk;
    
    int ret = PQCLEAN_DILITHIUM3_crypto_sign_keypair(pk.data(), sk.data());
    BOOST_CHECK_EQUAL(ret, 0);
    
    // Create a message to sign
    const std::string message = "Quantum resistance is the future of cryptocurrency";
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(message.data());
    size_t msglen = message.size();
    
    // Sign the message
    std::vector<unsigned char> signature(PQCLEAN_DILITHIUM3_CRYPTO_BYTES + msglen);
    unsigned long long siglen = 0;
    
    ret = PQCLEAN_DILITHIUM3_crypto_sign(signature.data(), &siglen, msg, msglen, sk.data());
    BOOST_CHECK_EQUAL(ret, 0);
    BOOST_CHECK_EQUAL(siglen, PQCLEAN_DILITHIUM3_CRYPTO_BYTES + msglen);
    
    // Verify the signature
    std::vector<unsigned char> recovered_msg(siglen);
    unsigned long long recovered_msglen = 0;
    
    ret = PQCLEAN_DILITHIUM3_crypto_sign_open(recovered_msg.data(), &recovered_msglen, 
                                             signature.data(), siglen, pk.data());
    
    // Check that verification succeeded
    BOOST_CHECK_EQUAL(ret, 0);
    BOOST_CHECK_EQUAL(recovered_msglen, msglen);
    
    // Check that the recovered message matches the original
    BOOST_CHECK_EQUAL(std::string(reinterpret_cast<char*>(recovered_msg.data()), recovered_msglen), message);
}

BOOST_AUTO_TEST_CASE(detached_sign_and_verify)
{
    // Generate a keypair
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES> pk;
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES> sk;
    
    int ret = PQCLEAN_DILITHIUM3_crypto_sign_keypair(pk.data(), sk.data());
    BOOST_CHECK_EQUAL(ret, 0);
    
    // Create a message to sign
    const std::string message = "Post-quantum cryptography protects against quantum computers";
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(message.data());
    size_t msglen = message.size();
    
    // Create a detached signature
    std::array<unsigned char, PQCLEAN_DILITHIUM3_CRYPTO_BYTES> signature;
    unsigned long long siglen = 0;
    
    ret = PQCLEAN_DILITHIUM3_crypto_sign_signature(signature.data(), &siglen, 
                                                 msg, msglen, sk.data());
    BOOST_CHECK_EQUAL(ret, 0);
    BOOST_CHECK_EQUAL(siglen, PQCLEAN_DILITHIUM3_CRYPTO_BYTES);
    
    // Verify the detached signature
    ret = PQCLEAN_DILITHIUM3_crypto_sign_verify(signature.data(), siglen, 
                                              msg, msglen, pk.data());
    
    // Check that verification succeeded
    BOOST_CHECK_EQUAL(ret, 0);
}

BOOST_AUTO_TEST_CASE(tampered_signature_fails)
{
    // Generate a keypair
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES> pk;
    std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES> sk;
    
    int ret = PQCLEAN_DILITHIUM3_crypto_sign_keypair(pk.data(), sk.data());
    BOOST_CHECK_EQUAL(ret, 0);
    
    // Create a message to sign
    const std::string message = "This signature will be tampered with";
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(message.data());
    size_t msglen = message.size();
    
    // Create a detached signature
    std::array<unsigned char, PQCLEAN_DILITHIUM3_CRYPTO_BYTES> signature;
    unsigned long long siglen = 0;
    
    ret = PQCLEAN_DILITHIUM3_crypto_sign_signature(signature.data(), &siglen, 
                                                 msg, msglen, sk.data());
    BOOST_CHECK_EQUAL(ret, 0);
    
    // Tamper with the signature by modifying a byte
    signature[siglen / 2] ^= 0x01;
    
    // Verification should fail
    ret = PQCLEAN_DILITHIUM3_crypto_sign_verify(signature.data(), siglen, 
                                              msg, msglen, pk.data());
    
    // Check that verification failed
    BOOST_CHECK_NE(ret, 0);
}

BOOST_AUTO_TEST_CASE(dilithium_wrapper_sign_verify)
{
    // Test our wrapper class
    // Generate a keypair
    CDilithiumKey key;
    bool generated = key.GenerateKeyPair();
    BOOST_CHECK(generated);
    
    // Get the public key
    CDilithiumPubKey pubKey = key.GetPubKey();
    
    // Create a message to sign
    const std::string message = "Testing the Dilithium wrapper class";
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(message.data());
    size_t msglen = message.size();
    
    // Sign the message
    std::vector<unsigned char> signature;
    bool signed_ok = key.Sign(msg, msglen, signature);
    BOOST_CHECK(signed_ok);
    BOOST_CHECK_EQUAL(signature.size(), PQCLEAN_DILITHIUM3_CRYPTO_BYTES);
    
    // Verify the signature
    bool verified = pubKey.Verify(msg, msglen, signature.data(), signature.size());
    BOOST_CHECK(verified);
    
    // Tamper with the signature
    signature[signature.size() / 2] ^= 0x01;
    
    // Verification should fail
    verified = pubKey.Verify(msg, msglen, signature.data(), signature.size());
    BOOST_CHECK(!verified);
}

BOOST_AUTO_TEST_CASE(dilithium_key_serialization)
{
    // Generate a keypair
    CDilithiumKey key1;
    bool generated = key1.GenerateKeyPair();
    BOOST_CHECK(generated);
    
    // Get the public key
    CDilithiumPubKey pubKey1 = key1.GetPubKey();
    
    // Serialize the keys
    std::vector<unsigned char> privSerialized = key1.GetPrivKey();
    std::vector<unsigned char> pubSerialized = pubKey1.GetPubKey();
    
    // Create new keys from serialized data
    CDilithiumKey key2;
    bool loaded = key2.Load(privSerialized.data(), privSerialized.size());
    BOOST_CHECK(loaded);
    
    CDilithiumPubKey pubKey2;
    loaded = pubKey2.Load(pubSerialized.data(), pubSerialized.size());
    BOOST_CHECK(loaded);
    
    // Check that keys match
    BOOST_CHECK(key1.GetPubKey() == key2.GetPubKey());
    BOOST_CHECK(pubKey1 == pubKey2);
    
    // Create a message to sign
    const std::string message = "Testing key serialization";
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(message.data());
    size_t msglen = message.size();
    
    // Sign with the first key
    std::vector<unsigned char> signature;
    bool signed_ok = key1.Sign(msg, msglen, signature);
    BOOST_CHECK(signed_ok);
    
    // Verify with the second key's public key
    bool verified = pubKey2.Verify(msg, msglen, signature.data(), signature.size());
    BOOST_CHECK(verified);
}

BOOST_AUTO_TEST_CASE(dilithium_performance)
{
    // Generate 10 keypairs and measure average time
    int num_iterations = 10;
    int64_t total_keygen_time = 0;
    int64_t total_sign_time = 0;
    int64_t total_verify_time = 0;
    
    for (int i = 0; i < num_iterations; i++) {
        // Key generation
        int64_t start = GetTimeMicros();
        
        std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES> pk;
        std::array<uint8_t, PQCLEAN_DILITHIUM3_CRYPTO_SECRETKEYBYTES> sk;
        PQCLEAN_DILITHIUM3_crypto_sign_keypair(pk.data(), sk.data());
        
        total_keygen_time += GetTimeMicros() - start;
        
        // Create a message
        std::vector<unsigned char> message(64);
        GetRandBytes(message.data(), message.size());
        
        // Signature
        std::array<unsigned char, PQCLEAN_DILITHIUM3_CRYPTO_BYTES> signature;
        unsigned long long siglen = 0;
        
        start = GetTimeMicros();
        PQCLEAN_DILITHIUM3_crypto_sign_signature(signature.data(), &siglen, 
                                               message.data(), message.size(), sk.data());
        total_sign_time += GetTimeMicros() - start;
        
        // Verification
        start = GetTimeMicros();
        PQCLEAN_DILITHIUM3_crypto_sign_verify(signature.data(), siglen, 
                                            message.data(), message.size(), pk.data());
        total_verify_time += GetTimeMicros() - start;
    }
    
    // Calculate averages (in milliseconds)
    double avg_keygen_time = total_keygen_time / (1000.0 * num_iterations);
    double avg_sign_time = total_sign_time / (1000.0 * num_iterations);
    double avg_verify_time = total_verify_time / (1000.0 * num_iterations);
    
    BOOST_TEST_MESSAGE("Dilithium-III Performance:");
    BOOST_TEST_MESSAGE("  Key generation: " << avg_keygen_time << " ms");
    BOOST_TEST_MESSAGE("  Signature: " << avg_sign_time << " ms");
    BOOST_TEST_MESSAGE("  Verification: " << avg_verify_time << " ms");
    
    // We're not making assertions on timing, just reporting
}

BOOST_AUTO_TEST_CASE(serialization_format_check)
{
    // Generate a keypair
    CDilithiumKey key;
    bool generated = key.GenerateKeyPair();
    BOOST_CHECK(generated);
    
    // Get the public key
    CDilithiumPubKey pubKey = key.GetPubKey();
    
    // Serialize the public key
    std::vector<unsigned char> serialized = pubKey.GetPubKey();
    
    // Check the size
    BOOST_CHECK_EQUAL(serialized.size(), PQCLEAN_DILITHIUM3_CRYPTO_PUBLICKEYBYTES);
    
    // Verify serialized format with HexStr for inspection
    std::string hexPubKey = HexStr(serialized);
    BOOST_TEST_MESSAGE("Dilithium-III public key (hex): " << hexPubKey);
    
    // The first bytes should be part of the polynomial coefficients
    // This test just checks the serialization is non-empty and prints it for inspection
    BOOST_CHECK(!hexPubKey.empty());
}

BOOST_AUTO_TEST_SUITE_END() 