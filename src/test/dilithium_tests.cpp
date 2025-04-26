#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>
#include <primitives/qubit.h>
#include <random.h>
#include <key_io.h>
#include <streams.h>

#include <iostream>
#include <vector>

BOOST_AUTO_TEST_SUITE(dilithium_tests)

BOOST_AUTO_TEST_CASE(dilithium_key_generation)
{
    // Generate a new keypair
    CQubitDilithiumSecret key;
    bool generated = key.MakeNewKey();
    
    BOOST_CHECK(generated);
    BOOST_CHECK(!key.GetPubKey().empty());
    BOOST_CHECK(!key.GetPrivKey().empty());
    
    // Verify public key size is correct for Dilithium-III
    BOOST_CHECK_EQUAL(key.GetPubKey().size(), DILITHIUM_PK_SIZE);
    
    // Verify private key size is correct for Dilithium-III
    BOOST_CHECK_EQUAL(key.GetPrivKey().size(), DILITHIUM_SK_SIZE);
}

BOOST_AUTO_TEST_CASE(dilithium_sign_verify)
{
    // Generate a keypair
    CQubitDilithiumSecret key;
    key.MakeNewKey();
    
    // Create a message to sign
    std::string message = "Test message for Dilithium signature verification";
    std::vector<unsigned char> messageBytes(message.begin(), message.end());
    
    // Sign the message
    std::vector<unsigned char> signature;
    bool signed_success = CQubitDilithium::Sign(key.GetPrivKey(), messageBytes, signature);
    
    BOOST_CHECK(signed_success);
    BOOST_CHECK(!signature.empty());
    BOOST_CHECK_EQUAL(signature.size(), DILITHIUM_SIG_SIZE);
    
    // Verify the signature
    bool verified = CQubitDilithium::Verify(
        key.GetPubKey(),
        messageBytes,
        signature
    );
    
    BOOST_CHECK(verified);
    
    // Tamper with the message and verify that signature check fails
    messageBytes[0] ^= 0x01; // Flip a bit in the message
    bool should_fail = CQubitDilithium::Verify(
        key.GetPubKey(),
        messageBytes,
        signature
    );
    
    BOOST_CHECK(!should_fail);
}

BOOST_AUTO_TEST_CASE(dilithium_deterministic_signatures)
{
    // Generate a keypair
    CQubitDilithiumSecret key1;
    key1.MakeNewKey();
    
    // Create a message to sign
    std::string message = "Test message for deterministic signatures";
    std::vector<unsigned char> messageBytes(message.begin(), message.end());
    
    // Sign the message twice with the same key
    std::vector<unsigned char> signature1;
    std::vector<unsigned char> signature2;
    
    bool signed1 = CQubitDilithium::Sign(key1.GetPrivKey(), messageBytes, signature1);
    bool signed2 = CQubitDilithium::Sign(key1.GetPrivKey(), messageBytes, signature2);
    
    BOOST_CHECK(signed1);
    BOOST_CHECK(signed2);
    
    // Dilithium signatures should be deterministic (same for the same message and key)
    BOOST_CHECK(signature1 == signature2);
}

BOOST_AUTO_TEST_CASE(dilithium_serialization)
{
    // Generate a keypair
    CQubitDilithiumSecret key;
    key.MakeNewKey();
    
    // Serialize the public key
    std::vector<unsigned char> pubKeyBytes = key.GetPubKey();
    std::string pubKeyHex = HexStr(pubKeyBytes);
    
    // Deserialize and verify
    std::vector<unsigned char> pubKeyDeserialized = ParseHex(pubKeyHex);
    
    BOOST_CHECK_EQUAL_COLLECTIONS(
        pubKeyBytes.begin(), pubKeyBytes.end(),
        pubKeyDeserialized.begin(), pubKeyDeserialized.end()
    );
    
    // Test serialization of keys to CDataStream
    CDataStream ss(SER_DISK, 0);
    ss << key;
    
    // Deserialize
    CQubitDilithiumSecret key2;
    ss >> key2;
    
    // Verify keys match
    BOOST_CHECK(key.GetPrivKey() == key2.GetPrivKey());
    BOOST_CHECK(key.GetPubKey() == key2.GetPubKey());
}

BOOST_AUTO_TEST_CASE(dilithium_header_signature)
{
    // Generate keypair
    CQubitDilithiumSecret key;
    key.MakeNewKey();
    
    // Create block header fields
    int32_t nVersion = 1;
    uint256 hashPrevBlock = uint256();
    uint256 hashMerkleRoot = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    uint32_t nTime = 1609459200; // 2021-01-01
    uint32_t nBits = 0x1d00ffff;
    uint32_t nNonce = 123456789;
    
    // Create header hash
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << nVersion;
    ss << hashPrevBlock;
    ss << hashMerkleRoot;
    ss << nTime;
    ss << nBits;
    ss << nNonce;
    uint256 headerHash = Hash(ss);
    
    // Sign the header hash
    std::vector<unsigned char> signature;
    std::vector<unsigned char> headerHashBytes(headerHash.begin(), headerHash.end());
    
    bool signed_success = CQubitDilithium::Sign(key.GetPrivKey(), headerHashBytes, signature);
    BOOST_CHECK(signed_success);
    
    // Create QubitHeader with the signature
    CQubitHeader qubitHeader;
    qubitHeader.dilithiumPubKey = key.GetPubKey();
    qubitHeader.dilithiumSignature = signature;
    
    // Verify signature
    bool verified = CQubitDilithium::Verify(
        qubitHeader.dilithiumPubKey,
        headerHashBytes,
        qubitHeader.dilithiumSignature
    );
    
    BOOST_CHECK(verified);
    
    // Verify that the header passes its own validation
    BOOST_CHECK(qubitHeader.IsInitialized());
    BOOST_CHECK(!qubitHeader.dilithiumPubKey.empty());
    BOOST_CHECK(!qubitHeader.dilithiumSignature.empty());
}

// Test basic Dilithium key generation, signing and verification
BOOST_AUTO_TEST_CASE(dilithium_basic_operations)
{
    // Create a message to sign
    const std::string message = "This is a test message for Dilithium signature";
    std::vector<unsigned char> message_bytes(message.begin(), message.end());
    
    // Generate a key pair
    CDilithiumKey key;
    BOOST_CHECK(key.IsValid());
    
    // Export the public key
    std::vector<unsigned char> pubKey = key.GetPubKey();
    BOOST_CHECK(!pubKey.empty());
    
    // Sign the message
    std::vector<unsigned char> signature;
    BOOST_CHECK(key.Sign(message_bytes, signature));
    BOOST_CHECK(!signature.empty());
    
    // Verify the signature
    BOOST_CHECK(CDilithiumKey::Verify(pubKey, message_bytes, signature));
    
    // Check that a modified message fails verification
    std::string altered_message = "This is a MODIFIED test message";
    std::vector<unsigned char> altered_bytes(altered_message.begin(), altered_message.end());
    BOOST_CHECK(!CDilithiumKey::Verify(pubKey, altered_bytes, signature));
    
    // Check that an altered signature fails verification
    if (signature.size() > 0) {
        signature[0] ^= 0x01;  // Flip a bit in the signature
        BOOST_CHECK(!CDilithiumKey::Verify(pubKey, message_bytes, signature));
    }
}

// Test serialization and deserialization of Dilithium keys
BOOST_AUTO_TEST_CASE(dilithium_serialization)
{
    // Generate a key pair
    CDilithiumKey key;
    BOOST_CHECK(key.IsValid());
    
    // Get the public key
    std::vector<unsigned char> pubKey = key.GetPubKey();
    
    // Serialize the private key
    std::vector<unsigned char> privKeyData;
    key.GetPrivateData(privKeyData);
    BOOST_CHECK(!privKeyData.empty());
    
    // Create a new key from the serialized data
    CDilithiumKey key2;
    BOOST_CHECK(key2.SetPrivateData(privKeyData));
    BOOST_CHECK(key2.IsValid());
    
    // Check that both keys have the same public key
    std::vector<unsigned char> pubKey2 = key2.GetPubKey();
    BOOST_CHECK_EQUAL_COLLECTIONS(pubKey.begin(), pubKey.end(), pubKey2.begin(), pubKey2.end());
    
    // Create a message and sign with both keys
    const std::string message = "Test serialization";
    std::vector<unsigned char> message_bytes(message.begin(), message.end());
    
    std::vector<unsigned char> sig1, sig2;
    BOOST_CHECK(key.Sign(message_bytes, sig1));
    BOOST_CHECK(key2.Sign(message_bytes, sig2));
    
    // Both signatures should be valid (although not necessarily identical)
    BOOST_CHECK(CDilithiumKey::Verify(pubKey, message_bytes, sig1));
    BOOST_CHECK(CDilithiumKey::Verify(pubKey, message_bytes, sig2));
}

// Test Dilithium in transactions
BOOST_AUTO_TEST_CASE(dilithium_transaction_signing)
{
    // Create a dilithium key
    CDilithiumKey dilithiumKey;
    BOOST_CHECK(dilithiumKey.IsValid());
    
    // Create a transaction
    CMutableTransaction tx;
    
    // Add an input
    COutPoint outpoint(uint256S("0000000000000000000000000000000000000000000000000000000000000001"), 0);
    CTxIn txin(outpoint);
    tx.vin.push_back(txin);
    
    // Add an output
    CScript scriptPubKey;
    std::vector<unsigned char> pubKey = dilithiumKey.GetPubKey();
    scriptPubKey << OP_RETURN << pubKey;
    CTxOut txout(1000, scriptPubKey);
    tx.vout.push_back(txout);
    
    // Sign the transaction input
    // First, create the data to be signed (hash of the transaction)
    uint256 hash = tx.GetHash();
    std::vector<unsigned char> hashBytes(hash.begin(), hash.end());
    
    // Sign with Dilithium
    std::vector<unsigned char> signature;
    BOOST_CHECK(dilithiumKey.Sign(hashBytes, signature));
    
    // Create a script containing the signature
    CScript scriptSig;
    scriptSig << signature;
    tx.vin[0].scriptSig = scriptSig;
    
    // Verify the signature
    BOOST_CHECK(CDilithiumKey::Verify(pubKey, hashBytes, signature));
}

// Test the size of Dilithium signatures
BOOST_AUTO_TEST_CASE(dilithium_signature_size)
{
    // Create a dilithium key
    CDilithiumKey key;
    BOOST_CHECK(key.IsValid());
    
    // Create a message to sign
    const std::string message = "Test signature size";
    std::vector<unsigned char> message_bytes(message.begin(), message.end());
    
    // Sign the message
    std::vector<unsigned char> signature;
    BOOST_CHECK(key.Sign(message_bytes, signature));
    
    // Check if the signature has the expected size for Dilithium-3
    // Signature size should be around 2701 bytes for Dilithium-3
    // This might slightly vary based on implementation but should be in this range
    BOOST_CHECK(signature.size() >= 2500);
    BOOST_CHECK(signature.size() <= 3000);
    
    // Public key size should be around 1472 bytes for Dilithium-3
    std::vector<unsigned char> pubKey = key.GetPubKey();
    BOOST_CHECK(pubKey.size() >= 1400);
    BOOST_CHECK(pubKey.size() <= 1600);
    
    // Log the actual sizes for reference
    std::cout << "Dilithium signature size: " << signature.size() << " bytes" << std::endl;
    std::cout << "Dilithium public key size: " << pubKey.size() << " bytes" << std::endl;
}

// Test the performance of Dilithium operations
BOOST_AUTO_TEST_CASE(dilithium_performance)
{
    // Create a message to sign (larger message)
    std::string message(1024, 'x');  // 1KB message
    std::vector<unsigned char> message_bytes(message.begin(), message.end());
    
    // Measure key generation time
    auto start = std::chrono::high_resolution_clock::now();
    CDilithiumKey key;
    auto end = std::chrono::high_resolution_clock::now();
    auto key_gen_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::vector<unsigned char> pubKey = key.GetPubKey();
    
    // Measure signing time
    start = std::chrono::high_resolution_clock::now();
    std::vector<unsigned char> signature;
    bool signResult = key.Sign(message_bytes, signature);
    end = std::chrono::high_resolution_clock::now();
    auto sign_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    BOOST_CHECK(signResult);
    
    // Measure verification time
    start = std::chrono::high_resolution_clock::now();
    bool verifyResult = CDilithiumKey::Verify(pubKey, message_bytes, signature);
    end = std::chrono::high_resolution_clock::now();
    auto verify_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    BOOST_CHECK(verifyResult);
    
    // Output results for review
    std::cout << "Dilithium-3 Performance Metrics:" << std::endl;
    std::cout << "Key generation time: " << key_gen_time << " ms" << std::endl;
    std::cout << "Signing time: " << sign_time << " ms" << std::endl;
    std::cout << "Verification time: " << verify_time << " ms" << std::endl;
    
    // While these are not hard assertions, they provide a baseline
    // for performance expectations on modern hardware:
    // - Key generation typically takes < 5ms
    // - Signing typically takes < 10ms
    // - Verification typically takes < 5ms
    // 
    // These numbers can vary widely based on hardware, so we use high values 
    // to avoid false failures in CI environments
    BOOST_CHECK(key_gen_time < 500);  // Very generous limit
    BOOST_CHECK(sign_time < 500);     // Very generous limit
    BOOST_CHECK(verify_time < 500);   // Very generous limit
}

// Test multiple signatures and verifications
BOOST_AUTO_TEST_CASE(dilithium_multiple_operations)
{
    const int NUM_OPERATIONS = 10;
    
    // Create multiple keys and messages
    std::vector<CDilithiumKey> keys(NUM_OPERATIONS);
    std::vector<std::vector<unsigned char>> messages(NUM_OPERATIONS);
    std::vector<std::vector<unsigned char>> signatures(NUM_OPERATIONS);
    std::vector<std::vector<unsigned char>> pubKeys(NUM_OPERATIONS);
    
    // Initialize messages with different content
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        std::string msg = "Test message " + std::to_string(i);
        messages[i].assign(msg.begin(), msg.end());
        pubKeys[i] = keys[i].GetPubKey();
    }
    
    // Sign all messages
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        BOOST_CHECK(keys[i].Sign(messages[i], signatures[i]));
        BOOST_CHECK(!signatures[i].empty());
    }
    
    // Verify all signatures (correct pairs)
    for (int i = 0; i < NUM_OPERATIONS; i++) {
        BOOST_CHECK(CDilithiumKey::Verify(pubKeys[i], messages[i], signatures[i]));
    }
    
    // Verify with incorrect pairs (should fail)
    for (int i = 0; i < NUM_OPERATIONS - 1; i++) {
        // Try to verify with the next message (which wasn't signed with this key)
        BOOST_CHECK(!CDilithiumKey::Verify(pubKeys[i], messages[i+1], signatures[i]));
        
        // Try to verify with the next signature (which doesn't correspond to this message)
        BOOST_CHECK(!CDilithiumKey::Verify(pubKeys[i], messages[i], signatures[i+1]));
    }
}

BOOST_AUTO_TEST_SUITE_END() 