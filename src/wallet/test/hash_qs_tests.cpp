// wallet/test/hash_qs_tests.cpp
// Tests for quantum-safe hash wrappers (BLAKE3) in hash.h

#include <boost/test/unit_test.hpp>
#include <hash.h>
#include <primitives/block.h>
#include <streams.h>
#include <serialize.h>
#include <uint256.h>
#include <string>

using namespace qubitcoin::crypto;

BOOST_AUTO_TEST_SUITE(hash_qs_tests)

BOOST_AUTO_TEST_CASE(HashWriter_vs_BlockHeader_GetHash)
{
    // Build a simple block header
    CBlockHeader hdr;
    hdr.SetNull();
    hdr.nVersion = 2;
    hdr.hashPrevBlock = uint256::ONE;
    hdr.hashMerkleRoot = uint256::ZERO;
    hdr.nTime = 1610000000;
    hdr.nBits = 0x1d00ffff;
    hdr.nNonce = 99;
    // Compute via GetHash()
    uint256 h1 = hdr.GetHash();
    // Compute via HashWriter
    HashWriter hw;
    hw << hdr;
    uint256 h2 = hw.getHash();
    BOOST_CHECK_EQUAL(h1, h2);
}

BOOST_AUTO_TEST_CASE(Hash256_overload_two_objects)
{
    // Test Hash256(A,B) equals manual HashWriter
    int a = 123;
    std::string b = "hello";
    uint256 h1 = Hash256(a, b);
    HashWriter hw;
    hw << a;
    hw << b;
    uint256 h2 = hw.getHash();
    BOOST_CHECK_EQUAL(h1, h2);
}

BOOST_AUTO_TEST_SUITE_END()