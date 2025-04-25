// wallet/test/serialization_qs_tests.cpp
// Tests that quantum-safe block header fields serialize/deserialize correctly

#include <boost/test/unit_test.hpp>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <serialize.h>
#include <vector>

BOOST_AUTO_TEST_SUITE(serialization_qs_tests)

BOOST_AUTO_TEST_CASE(block_header_signature_serialization)
{
    // Build a block with post-quantum header fields
    CBlock block;
    block.nVersion = 2;
    block.hashPrevBlock = uint256::ONE;
    block.hashMerkleRoot = uint256::ZERO;
    block.nTime = 1610000000;
    block.nBits = 0x1d00ffff;
    block.nNonce = 99;
    block.headerPubKey = {0x10, 0x20};
    block.headerSig    = {0x30, 0x40, 0x50};
    // Add one dummy transaction
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    block.vtx.push_back(MakeTransactionRef(mtx));

    // Serialize to a data stream
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << block;

    // Deserialize into a new block
    CBlock copy;
    ss >> copy;

    // Compare fields
    BOOST_CHECK_EQUAL(copy.nVersion, block.nVersion);
    BOOST_CHECK_EQUAL(copy.hashPrevBlock, block.hashPrevBlock);
    BOOST_CHECK_EQUAL(copy.hashMerkleRoot, block.hashMerkleRoot);
    BOOST_CHECK_EQUAL(copy.nTime, block.nTime);
    BOOST_CHECK_EQUAL(copy.nBits, block.nBits);
    BOOST_CHECK_EQUAL(copy.nNonce, block.nNonce);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        copy.headerPubKey.begin(), copy.headerPubKey.end(),
        block.headerPubKey.begin(),  block.headerPubKey.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        copy.headerSig.begin(),    copy.headerSig.end(),
        block.headerSig.begin(),    block.headerSig.end());
    BOOST_CHECK_EQUAL(copy.vtx.size(), block.vtx.size());
}

BOOST_AUTO_TEST_SUITE_END()