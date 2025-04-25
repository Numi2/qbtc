// wallet/test/pqckeys_tests.cpp
// Tests for Dilithium3 key generation, serialization, signing and verification

#include <boost/test/unit_test.hpp>
#include <openssl/evp.h>
#include <crypto/pqc_keys.h>
#include <vector>

BOOST_AUTO_TEST_SUITE(pqckeys_tests)

BOOST_AUTO_TEST_CASE(dilithium3_key_roundtrip_and_signature)
{
    // Load the PQC provider
    LoadOQSProvider();

    // Generate key pair
    EVP_PKEY* priv = GenerateDilithium3Key();
    BOOST_REQUIRE(priv);

    // Export DER
    auto pub_der = ExportDilithium3PublicKey(priv);
    auto priv_der = ExportDilithium3PrivateKey(priv);
    BOOST_CHECK(!pub_der.empty());
    BOOST_CHECK(!priv_der.empty());

    // Reload keys from DER
    EVP_PKEY* loaded_priv = LoadDilithium3PrivateKey(priv_der.data(), priv_der.size());
    BOOST_REQUIRE(loaded_priv);
    EVP_PKEY* loaded_pub  = LoadDilithium3PublicKey(pub_der.data(), pub_der.size());
    BOOST_REQUIRE(loaded_pub);

    // Message to sign
    std::vector<unsigned char> msg = {0xde, 0xad, 0xbe, 0xef};
    // Sign
    auto sig = SignDilithium3(loaded_priv, msg.data(), msg.size());
    BOOST_REQUIRE(!sig.empty());

    // Verify should succeed
    bool ok = VerifyDilithium3(loaded_pub, sig.data(), sig.size(), msg.data(), msg.size());
    BOOST_CHECK(ok);

    // Modify message should fail
    msg[0] ^= 0xff;
    bool ok2 = VerifyDilithium3(loaded_pub, sig.data(), sig.size(), msg.data(), msg.size());
    BOOST_CHECK(!ok2);

    // Clean up
    EVP_PKEY_free(priv);
    EVP_PKEY_free(loaded_priv);
    EVP_PKEY_free(loaded_pub);
}

BOOST_AUTO_TEST_SUITE_END()