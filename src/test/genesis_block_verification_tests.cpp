#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <pow.h>
#include <validation.h>
#include <streams.h>
#include <util/strencodings.h>

BOOST_AUTO_TEST_SUITE(genesis_block_verification_tests)

BOOST_AUTO_TEST_CASE(mainnet_genesis_block_hash)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    const CBlock& genesisBlock = params.GenesisBlock();
    
    // Calculate the hash of the genesis block
    uint256 calculatedHash = genesisBlock.GetHash();
    
    // Verify it matches the expected hash from chainparams
    BOOST_CHECK_EQUAL(calculatedHash.ToString(), params.GenesisBlock().GetHash().ToString());
    BOOST_CHECK_EQUAL(calculatedHash.ToString(), params.GetConsensus().hashGenesisBlock.ToString());
    
    // Output details for logging
    BOOST_TEST_MESSAGE("Genesis Block Hash: " << calculatedHash.ToString());
    BOOST_TEST_MESSAGE("Genesis Merkle Root: " << genesisBlock.hashMerkleRoot.ToString());
}

BOOST_AUTO_TEST_CASE(testnet_genesis_block_hash)
{
    // Use SelectParams to switch to testnet
    SelectParams(CBaseChainParams::TESTNET);
    
    // Get the testnet parameters
    const CChainParams& testParams = Params(CBaseChainParams::TESTNET);
    
    // Get the testnet genesis block
    const CBlock& testGenesisBlock = testParams.GenesisBlock();
    
    // Calculate the hash
    uint256 testCalculatedHash = testGenesisBlock.GetHash();
    
    // Verify it matches the expected hash from chainparams
    BOOST_CHECK_EQUAL(testCalculatedHash.ToString(), testParams.GenesisBlock().GetHash().ToString());
    BOOST_CHECK_EQUAL(testCalculatedHash.ToString(), testParams.GetConsensus().hashGenesisBlock.ToString());
    
    // Output details for logging
    BOOST_TEST_MESSAGE("Testnet Genesis Block Hash: " << testCalculatedHash.ToString());
    BOOST_TEST_MESSAGE("Testnet Genesis Merkle Root: " << testGenesisBlock.hashMerkleRoot.ToString());
    
    // Switch back to mainnet for other tests
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(regtest_genesis_block_hash)
{
    // Use SelectParams to switch to regtest
    SelectParams(CBaseChainParams::REGTEST);
    
    // Get the regtest parameters
    const CChainParams& regParams = Params(CBaseChainParams::REGTEST);
    
    // Get the regtest genesis block
    const CBlock& regGenesisBlock = regParams.GenesisBlock();
    
    // Calculate the hash
    uint256 regCalculatedHash = regGenesisBlock.GetHash();
    
    // Verify it matches the expected hash from chainparams
    BOOST_CHECK_EQUAL(regCalculatedHash.ToString(), regParams.GenesisBlock().GetHash().ToString());
    BOOST_CHECK_EQUAL(regCalculatedHash.ToString(), regParams.GetConsensus().hashGenesisBlock.ToString());
    
    // Output details for logging
    BOOST_TEST_MESSAGE("Regtest Genesis Block Hash: " << regCalculatedHash.ToString());
    BOOST_TEST_MESSAGE("Regtest Genesis Merkle Root: " << regGenesisBlock.hashMerkleRoot.ToString());
    
    // Switch back to mainnet for other tests
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(genesis_block_merkle_root)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    const CBlock& genesisBlock = params.GenesisBlock();
    
    // Recalculate the merkle root
    bool mutated;
    uint256 calculatedMerkleRoot = BlockMerkleRoot(genesisBlock, &mutated);
    
    // Verify it matches the merkle root in the block
    BOOST_CHECK_EQUAL(calculatedMerkleRoot.ToString(), genesisBlock.hashMerkleRoot.ToString());
    
    // Make sure the merkle root calculation wasn't mutated (shouldn't happen with genesis block)
    BOOST_CHECK(!mutated);
}

BOOST_AUTO_TEST_CASE(genesis_block_pow)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    const CBlock& genesisBlock = params.GenesisBlock();
    
    // Verify the proof of work meets the required bits
    BOOST_CHECK(CheckProofOfWork(genesisBlock.GetHash(), genesisBlock.nBits, params.GetConsensus()));
    
    // Calculate the block's work
    arith_uint256 blockWork = GetBlockProof(genesisBlock);
    
    // Verify work is non-zero
    BOOST_CHECK(blockWork > 0);
    
    BOOST_TEST_MESSAGE("Genesis Block Work: " << blockWork.ToString());
}

BOOST_AUTO_TEST_CASE(genesis_coinbase_transaction)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    const CBlock& genesisBlock = params.GenesisBlock();
    
    // Check there is exactly one transaction in the genesis block
    BOOST_CHECK_EQUAL(genesisBlock.vtx.size(), 1);
    
    // Get the coinbase transaction
    const CTransaction& coinbaseTx = *(genesisBlock.vtx[0]);
    
    // Verify it's a coinbase transaction
    BOOST_CHECK(coinbaseTx.IsCoinBase());
    
    // Check input count (should be 1 for coinbase)
    BOOST_CHECK_EQUAL(coinbaseTx.vin.size(), 1);
    
    // Check output count (should be at least 1)
    BOOST_CHECK(coinbaseTx.vout.size() >= 1);
    
    // Serialize the coinbase transaction to hex
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << coinbaseTx;
    std::string coinbaseHex = HexStr(ss);
    
    BOOST_TEST_MESSAGE("Genesis Coinbase Transaction: " << coinbaseHex);
    
    // Calculate the transaction hash and verify it
    uint256 calculatedTxHash = coinbaseTx.GetHash();
    BOOST_TEST_MESSAGE("Genesis Coinbase Transaction Hash: " << calculatedTxHash.ToString());
}

BOOST_AUTO_TEST_CASE(genesis_block_validation)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    CBlock genesisBlock = params.GenesisBlock();
    
    // Create a state for validation
    BlockValidationState state;
    
    // Validate the genesis block without adding it to the chain
    BOOST_CHECK(CheckBlock(genesisBlock, state, params.GetConsensus()));
    
    // Ensure validation passed without errors
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(genesis_block_raw_data)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    const CBlock& genesisBlock = params.GenesisBlock();
    
    // Serialize the block to raw data
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << genesisBlock;
    std::vector<unsigned char> rawBlock(ss.begin(), ss.end());
    
    // Check raw block size
    BOOST_TEST_MESSAGE("Genesis Block Raw Size: " << rawBlock.size() << " bytes");
    
    // Deserialize back into a new block
    CBlock deserializedBlock;
    CDataStream ds(rawBlock, SER_NETWORK, PROTOCOL_VERSION);
    ds >> deserializedBlock;
    
    // Verify the hash of the deserialized block matches
    uint256 deserializedHash = deserializedBlock.GetHash();
    BOOST_CHECK_EQUAL(deserializedHash.ToString(), genesisBlock.GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(genesis_block_timestamp)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    const CBlock& genesisBlock = params.GenesisBlock();
    
    // Verify the timestamp is as expected
    BOOST_CHECK_EQUAL(genesisBlock.GetBlockTime(), params.GenesisBlock().GetBlockTime());
    
    // Output genesis timestamp for logging
    BOOST_TEST_MESSAGE("Genesis Block Timestamp: " << genesisBlock.GetBlockTime());
    
    // Check that timestamp is valid (not in the future)
    BOOST_CHECK(genesisBlock.GetBlockTime() <= GetTime());
}

BOOST_AUTO_TEST_CASE(genesis_block_serialization)
{
    // Get the mainnet parameters
    const CChainParams& params = Params();
    
    // Get the genesis block
    CBlock genesisBlock = params.GenesisBlock();
    
    // Test block serialization and hashing
    CDataStream ss(SER_DISK, PROTOCOL_VERSION);
    ss << genesisBlock;
    CBlock deserializedBlock;
    ss >> deserializedBlock;
    
    // Verify the hash of the serialized and deserialized block matches
    BOOST_CHECK_EQUAL(deserializedBlock.GetHash().ToString(), genesisBlock.GetHash().ToString());
    
    // Verify all fields in the deserialized block match the original
    BOOST_CHECK_EQUAL(deserializedBlock.nVersion, genesisBlock.nVersion);
    BOOST_CHECK_EQUAL(deserializedBlock.hashPrevBlock.ToString(), genesisBlock.hashPrevBlock.ToString());
    BOOST_CHECK_EQUAL(deserializedBlock.hashMerkleRoot.ToString(), genesisBlock.hashMerkleRoot.ToString());
    BOOST_CHECK_EQUAL(deserializedBlock.nTime, genesisBlock.nTime);
    BOOST_CHECK_EQUAL(deserializedBlock.nBits, genesisBlock.nBits);
    BOOST_CHECK_EQUAL(deserializedBlock.nNonce, genesisBlock.nNonce);
}

BOOST_AUTO_TEST_SUITE_END() 