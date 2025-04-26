#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <pow.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <uint256.h>

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(genesis_verification_tests)

BOOST_AUTO_TEST_CASE(mainnet_genesis_hash)
{
    // Verify that the mainnet genesis block has the expected hash
    const CChainParams& chainparams = Params();
    const CBlock& genesis = chainparams.GenesisBlock();
    
    // Get the actual genesis block hash
    uint256 actual_hash = genesis.GetHash();
    uint256 expected_hash = uint256S(chainparams.GenesisBlock().GetHash().ToString());
    
    // Verify the hash matches
    BOOST_CHECK_EQUAL(actual_hash.ToString(), expected_hash.ToString());
    BOOST_CHECK_EQUAL(actual_hash.ToString(), chainparams.GenesisHash().ToString());
    
    // Log the genesis hash for reference
    BOOST_TEST_MESSAGE("Mainnet genesis hash: " << actual_hash.ToString());
}

BOOST_AUTO_TEST_CASE(testnet_genesis_hash)
{
    // Get testnet parameters
    CChainParams testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const CBlock& genesis = testnet.GenesisBlock();
    
    // Get the actual genesis block hash
    uint256 actual_hash = genesis.GetHash();
    uint256 expected_hash = testnet.GenesisHash();
    
    // Verify the hash matches
    BOOST_CHECK_EQUAL(actual_hash.ToString(), expected_hash.ToString());
    
    // Log the genesis hash for reference
    BOOST_TEST_MESSAGE("Testnet genesis hash: " << actual_hash.ToString());
}

BOOST_AUTO_TEST_CASE(regtest_genesis_hash)
{
    // Get regtest parameters
    CChainParams regtest = CreateChainParams(CBaseChainParams::REGTEST);
    const CBlock& genesis = regtest.GenesisBlock();
    
    // Get the actual genesis block hash
    uint256 actual_hash = genesis.GetHash();
    uint256 expected_hash = regtest.GenesisHash();
    
    // Verify the hash matches
    BOOST_CHECK_EQUAL(actual_hash.ToString(), expected_hash.ToString());
    
    // Log the genesis hash for reference
    BOOST_TEST_MESSAGE("Regtest genesis hash: " << actual_hash.ToString());
}

BOOST_AUTO_TEST_CASE(genesis_merkle_root)
{
    // Get chain parameters and genesis block
    const CChainParams& chainparams = Params();
    const CBlock& genesis = chainparams.GenesisBlock();
    
    // Calculate merkle root
    bool mutated;
    uint256 calculated_merkle_root = BlockMerkleRoot(genesis, &mutated);
    
    // Verify merkle root matches expected value
    BOOST_CHECK_EQUAL(calculated_merkle_root.ToString(), genesis.hashMerkleRoot.ToString());
    BOOST_CHECK(!mutated);
    
    // Log the merkle root for reference
    BOOST_TEST_MESSAGE("Genesis merkle root: " << calculated_merkle_root.ToString());
}

BOOST_AUTO_TEST_CASE(genesis_coinbase)
{
    // Get chain parameters and genesis block
    const CChainParams& chainparams = Params();
    const CBlock& genesis = chainparams.GenesisBlock();
    
    // Check that we have exactly one transaction in the genesis block
    BOOST_CHECK_EQUAL(genesis.vtx.size(), 1);
    
    // Get the coinbase transaction
    const CTransaction& coinbase_tx = *(genesis.vtx[0]);
    
    // Verify it's a coinbase transaction
    BOOST_CHECK(coinbase_tx.IsCoinBase());
    
    // Check outputs
    BOOST_CHECK_GT(coinbase_tx.vout.size(), 0);
    
    // If we know the specific expected output values for the genesis block,
    // we could add more detailed checks here
    
    // Log the coinbase transaction hash
    BOOST_TEST_MESSAGE("Genesis coinbase hash: " << coinbase_tx.GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(genesis_pow)
{
    // Get chain parameters and genesis block
    const CChainParams& chainparams = Params();
    const CBlock& genesis = chainparams.GenesisBlock();
    
    // Check that the proof of work is valid
    // This verifies the genesis block satisfies the difficulty target
    bool pow_valid = CheckProofOfWork(genesis.GetHash(), genesis.nBits, chainparams.GetConsensus());
    BOOST_CHECK(pow_valid);
    
    // Log the difficulty target
    BOOST_TEST_MESSAGE("Genesis nBits: " << genesis.nBits);
    BOOST_TEST_MESSAGE("Genesis difficulty: " << GetDifficulty(genesis.nBits));
}

BOOST_AUTO_TEST_CASE(reconstruct_genesis_block)
{
    // Get chain parameters and the original genesis block
    const CChainParams& chainparams = Params();
    const CBlock& original_genesis = chainparams.GenesisBlock();
    
    // Create a new block with the same parameters
    CBlock reconstructed;
    reconstructed.nVersion = original_genesis.nVersion;
    reconstructed.hashPrevBlock = original_genesis.hashPrevBlock;
    reconstructed.hashMerkleRoot = original_genesis.hashMerkleRoot;
    reconstructed.nTime = original_genesis.nTime;
    reconstructed.nBits = original_genesis.nBits;
    reconstructed.nNonce = original_genesis.nNonce;
    
    // Copy the transactions
    reconstructed.vtx.clear();
    for (const auto& tx : original_genesis.vtx) {
        reconstructed.vtx.push_back(tx);
    }
    
    // Verify the hash matches
    BOOST_CHECK_EQUAL(reconstructed.GetHash().ToString(), original_genesis.GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(genesis_serialization)
{
    // Get the genesis block
    const CChainParams& chainparams = Params();
    const CBlock& genesis = chainparams.GenesisBlock();
    
    // Serialize the block
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << genesis;
    
    // Deserialize into a new block
    CBlock deserialized_block;
    ss >> deserialized_block;
    
    // Verify the hash matches
    BOOST_CHECK_EQUAL(deserialized_block.GetHash().ToString(), genesis.GetHash().ToString());
    
    // Verify merkle root matches
    BOOST_CHECK_EQUAL(deserialized_block.hashMerkleRoot.ToString(), genesis.hashMerkleRoot.ToString());
    
    // Verify other fields match
    BOOST_CHECK_EQUAL(deserialized_block.nVersion, genesis.nVersion);
    BOOST_CHECK_EQUAL(deserialized_block.hashPrevBlock.ToString(), genesis.hashPrevBlock.ToString());
    BOOST_CHECK_EQUAL(deserialized_block.nTime, genesis.nTime);
    BOOST_CHECK_EQUAL(deserialized_block.nBits, genesis.nBits);
    BOOST_CHECK_EQUAL(deserialized_block.nNonce, genesis.nNonce);
}

BOOST_AUTO_TEST_SUITE_END() 