// Tests for CPQCKeyStore: deterministic HD Dilithium3 key derivation and import/export
#include <wallet/pqckeystore.h>
#include <wallet/wallet.h>
#include <wallet/test/wallet_test_fixture.h>
#include <util/strencodings.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

using namespace wallet;

BOOST_FIXTURE_TEST_SUITE(pqckeystore_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(deterministic_key_derivation)
{
    // Set a known seed (32 bytes of 0x42)
    std::vector<unsigned char> seed(32, 0x42);
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.SetPqcSeed(seed);
    }
    WalletBatch batch(m_wallet.GetDatabase());
    // Initialize keystore
    m_wallet.m_pqc_keystore = std::make_unique<CPQCKeyStore>(&m_wallet);
    m_wallet.m_pqc_keystore->Load(batch);
    // Derive first address/keypair
    auto [addr1, pub1, priv1] = m_wallet.GetPQCKeyStore().GetNewPQCAddress();
    // Derive second
    auto [addr2, pub2, priv2] = m_wallet.GetPQCKeyStore().GetNewPQCAddress();
    // They should differ
    BOOST_CHECK(addr1 != addr2);
    BOOST_CHECK(pub1 != pub2);
    BOOST_CHECK(priv1 != priv2);
    // Reset keystore to test deterministic behavior: reload index
    m_wallet.m_pqc_keystore = std::make_unique<CPQCKeyStore>(&m_wallet);
    m_wallet.m_pqc_keystore->Load(batch);
    // Re-derive first two: should match previous
    auto [addr1b, pub1b, priv1b] = m_wallet.GetPQCKeyStore().GetNewPQCAddress();
    auto [addr2b, pub2b, priv2b] = m_wallet.GetPQCKeyStore().GetNewPQCAddress();
    BOOST_CHECK_EQUAL(addr1b, addr1);
    BOOST_CHECK_EQUAL(pub1b, pub1);
    BOOST_CHECK_EQUAL(priv1b, priv1);
    BOOST_CHECK_EQUAL(addr2b, addr2);
    BOOST_CHECK_EQUAL(pub2b, pub2);
    BOOST_CHECK_EQUAL(priv2b, priv2);
}

BOOST_AUTO_TEST_CASE(import_and_spk_man_integration)
{
    // Use prior derived key from deterministic test
    std::vector<unsigned char> seed(32, 0x24);
    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.SetPqcSeed(seed);
    }
    WalletBatch batch(m_wallet.GetDatabase());
    m_wallet.m_pqc_keystore = std::make_unique<CPQCKeyStore>(&m_wallet);
    m_wallet.m_pqc_keystore->Load(batch);
    auto [address, pub_b64, priv_b64] = m_wallet.GetPQCKeyStore().GetNewPQCAddress();
    // Now import into wallet
    bool ok = m_wallet.GetPQCKeyStore().ImportPQCAddress(address, pub_b64, priv_b64);
    BOOST_CHECK(ok);
    // The scriptPubKey should be recognized as IsMine
    CTxDestination dest = DecodeDestination(address);
    BOOST_CHECK(m_wallet.IsMine(dest));
}

BOOST_AUTO_TEST_SUITE_END()