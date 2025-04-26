#include <boost/test/unit_test.hpp>

#include <crypto/blake3.h>
#include <key.h>
#include <key_io.h>
#include <script/script.h>
#include <stdint.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <wallet/wallet.h>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(hd_tests, BasicTestingSetup)

// Test vector data for SLIP-0010 with BLAKE3
struct TestDerivation {
    std::string seed;             // Hex seed
    std::string path;             // Derivation path
    std::string fingerprint;      // Key fingerprint
    std::string pubkey;           // Public key
    std::string chaincode;        // Chain code
};

static std::vector<TestDerivation> test_vectors = {
    {
        "000102030405060708090a0b0c0d0e0f",
        "m/6077'/0'/0'",
        "3442193e",
        "0337cac489d3e344b13b55ce00c5acbe6a1a5ce5df6fa3c1eeab6b95f317a3dd96",
        "5b6cf2a48eb42ca93c7b92317c3488e08c674ed3682a366e781fd5ae068550d0"
    },
    {
        "000102030405060708090a0b0c0d0e0f",
        "m/6077'/0'/1'",
        "3442193e",
        "02c58e55bcd616b86df24d242a3a75a4e4ba8f4cd3ebb0ca037fc67b902b7bef94",
        "db8ef5a60be93b85ce22a2e289a5234651b73e456e1a84b5c992d5a1fa1c1c8c"
    },
    {
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/6077'/0'/0'",
        "bd16bee5",
        "03addf163a878471e41649757fb8eb860c7f55a28c35ca1bfa6da5b0a91d520ee9",
        "4b4e29dfc298359a72a981c12fb419713a7a1badbee44b29442e5bd3bbdf785c"
    }
};

static void RunHDTest(const TestDerivation& test) {
    CExtKey key;
    CExtPubKey pubkey;
    
    // Convert seed to binary
    std::vector<unsigned char> seed = ParseHex(test.seed);
    
    // Derive master key from seed using HMAC-BLAKE3
    key.SetSeedWithBlake3(seed.data(), seed.size());
    pubkey = key.Neuter();
    
    // Parse derivation path
    std::vector<uint32_t> path;
    std::istringstream ss(test.path);
    std::string item;
    
    // Skip 'm/'
    std::getline(ss, item, '/');
    
    while (std::getline(ss, item, '/')) {
        uint32_t child_num = 0;
        if (item.back() == '\'') {
            child_num = std::stoul(item.substr(0, item.size() - 1)) | 0x80000000;
        } else {
            child_num = std::stoul(item);
        }
        path.push_back(child_num);
    }
    
    // Derive child key
    CExtKey child_key = key;
    for (uint32_t child_num : path) {
        CExtKey parent_key = child_key;
        if (!parent_key.Derive(child_key, child_num)) {
            BOOST_ERROR("Could not derive child key");
            return;
        }
    }
    
    CExtPubKey child_pubkey = child_key.Neuter();
    
    // Check that the generated key matches the test vector
    uint32_t fp = child_pubkey.GetFingerprint();
    std::string fp_hex = HexStr(fp);
    
    // Check fingerprint
    BOOST_CHECK_EQUAL(fp_hex, test.fingerprint);
    
    // Check pubkey
    BOOST_CHECK_EQUAL(HexStr(child_pubkey.pubkey), test.pubkey);
    
    // Check chaincode
    BOOST_CHECK_EQUAL(HexStr(child_pubkey.chaincode), test.chaincode);
}

BOOST_AUTO_TEST_CASE(hd_blake3_test)
{
    // Initialize key framework once
    ECC_Start();
    
    // Run tests for each test vector
    for (const auto& test : test_vectors) {
        RunHDTest(test);
    }
    
    ECC_Stop();
}

BOOST_AUTO_TEST_CASE(hd_slip10_path)
{
    // Check that we're using SLIP-0010 compatible paths with m/6077'/coin_type'/account'
    CExtKey key;
    CExtPubKey pubkey;
    
    // Create a random seed
    std::vector<unsigned char> seed(32);
    GetRandBytes(seed.data(), seed.size());
    
    // Derive master key
    key.SetSeedWithBlake3(seed.data(), seed.size());
    
    // Purpose is 6077' for QuBitcoin
    uint32_t purpose = 6077 | 0x80000000;
    // Coin type is 0' for mainnet, 1' for testnet
    uint32_t coin_type = 0 | 0x80000000;
    // Account 0'
    uint32_t account = 0 | 0x80000000;
    // External chain
    uint32_t external_chain = 0;
    // First address
    uint32_t address_index = 0;
    
    // Derive m/6077'/0'/0'/0/0
    CExtKey purpose_key, coin_key, account_key, chain_key, address_key;
    BOOST_CHECK(key.Derive(purpose_key, purpose));
    BOOST_CHECK(purpose_key.Derive(coin_key, coin_type));
    BOOST_CHECK(coin_key.Derive(account_key, account));
    BOOST_CHECK(account_key.Derive(chain_key, external_chain));
    BOOST_CHECK(chain_key.Derive(address_key, address_index));
    
    // Create address
    CPubKey addr_pubkey = address_key.key.GetPubKey();
    CKeyID keyid = addr_pubkey.GetID();
    
    // Verify we can create a valid address
    std::string address = EncodeDestination(keyid);
    BOOST_CHECK(!address.empty());
}

BOOST_AUTO_TEST_CASE(hd_address_checksum)
{
    // Generate 100 random addresses and check that the checksum round-trips correctly
    for (int i = 0; i < 100; i++) {
        CKey key;
        key.MakeNewKey(true);
        CPubKey pubkey = key.GetPubKey();
        
        // Get the associated address
        CKeyID keyid = pubkey.GetID();
        CTxDestination dest = keyid;
        std::string address = EncodeDestination(dest);
        
        // Decode the address
        CTxDestination decoded_dest = DecodeDestination(address);
        std::string reencoded_address = EncodeDestination(decoded_dest);
        
        // Check that the re-encoded address matches the original
        BOOST_CHECK_EQUAL(address, reencoded_address);
    }
}

BOOST_AUTO_TEST_SUITE_END() 