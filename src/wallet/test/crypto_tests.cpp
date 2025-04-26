// Tests for crypto utilities: hex_base, sha3, siphash
#include <boost/test/unit_test.hpp>
#include <crypto/hex_base.h>
#include <crypto/sha3.h>
#include <crypto/siphash.h>
#include <crypto/common.h> // for ReadLE64 if needed
#include <span.h>
#include <uint256.h>
#include <vector>
#include <string>

BOOST_AUTO_TEST_SUITE(crypto_tests)

BOOST_AUTO_TEST_CASE(hex_base_conversion)
{
    std::vector<uint8_t> data = {0x00, 0x1f, 0xff, 0x10, 0xab, 0xcd, 0x12};
    std::string s = HexStr(std::span<const uint8_t>(data.data(), data.size()));
    BOOST_CHECK_EQUAL(s, "001fff10abcd12");
    BOOST_CHECK_EQUAL(HexDigit('0'), 0);
    BOOST_CHECK_EQUAL(HexDigit('9'), 9);
    BOOST_CHECK_EQUAL(HexDigit('a'), 10);
    BOOST_CHECK_EQUAL(HexDigit('f'), 15);
    BOOST_CHECK_EQUAL(HexDigit('A'), -1);
    BOOST_CHECK_EQUAL(HexDigit('z'), -1);
}

BOOST_AUTO_TEST_CASE(sha3_empty)
{
    SHA3_256 hasher;
    std::vector<unsigned char> out(SHA3_256::OUTPUT_SIZE);
    // Empty input
    hasher.Reset().Write(std::span<const unsigned char>(nullptr, 0)).Finalize(std::span<unsigned char>(out.data(), out.size()));
    std::string hex = HexStr(std::span<const uint8_t>(out.data(), out.size()));
    // SHA3-256("")
    BOOST_CHECK_EQUAL(hex, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

BOOST_AUTO_TEST_CASE(siphash_uint256_and_hasher)
{
    uint64_t k0 = 0x0123456789abcdefULL;
    uint64_t k1 = 0xfedcba9876543210ULL;
    // Test value: arbitrary uint256
    uint256 val = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    uint64_t h1 = SipHashUint256(k0, k1, val);
    CSipHasher hasher(k0, k1);
    // Equivalent to SipHashUint256: process each 64-bit word
    for (int i = 0; i < 4; i++) {
        hasher.Write(val.GetUint64(i));
    }
    uint64_t h2 = hasher.Finalize();
    BOOST_CHECK_EQUAL(h1, h2);
}

BOOST_AUTO_TEST_SUITE_END()