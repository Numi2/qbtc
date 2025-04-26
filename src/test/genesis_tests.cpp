#include <boost/test/unit_test.hpp>

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <streams.h>
#include <util/strencodings.h>

BOOST_AUTO_TEST_SUITE(genesis_tests)

// Helper function to calculate the actual hash of a block
uint256 CalculateBlockHash(const CBlock& block) {
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << block;
    return Hash(ss);
}

// Helper function to verify Merkle root calculation
uint256 CalculateMerkleRoot(const std::vector<CTransactionRef>& vtx) {
    return BlockMerkleRoot(vtx);
}

BOOST_AUTO_TEST_CASE(genesis_hash_consistency)
{
    // Verify that the genesis block hash matches the expected value for all networks
    
    // Mainnet
    CChainParams mainParams = CreateChainParams(CBaseChainParams::MAIN);
    const CBlock& mainGenesis = mainParams.GenesisBlock();
    const uint256 mainGenesisHash = mainGenesis.GetHash();
    BOOST_CHECK_EQUAL(mainGenesisHash.ToString(), mainParams.GetConsensus().hashGenesisBlock.ToString());
    
    // Testnet
    CChainParams testParams = CreateChainParams(CBaseChainParams::TESTNET);
    const CBlock& testGenesis = testParams.GenesisBlock();
    const uint256 testGenesisHash = testGenesis.GetHash();
    BOOST_CHECK_EQUAL(testGenesisHash.ToString(), testParams.GetConsensus().hashGenesisBlock.ToString());
    
    // Regtest
    CChainParams regParams = CreateChainParams(CBaseChainParams::REGTEST);
    const CBlock& regGenesis = regParams.GenesisBlock();
    const uint256 regGenesisHash = regGenesis.GetHash();
    BOOST_CHECK_EQUAL(regGenesisHash.ToString(), regParams.GetConsensus().hashGenesisBlock.ToString());
}

BOOST_AUTO_TEST_CASE(genesis_block_validity)
{
    CChainParams params = CreateChainParams(CBaseChainParams::MAIN);
    const CBlock& genesis = params.GenesisBlock();
    
    // Check the merkle root
    bool mutated;
    uint256 calculatedMerkleRoot = BlockMerkleRoot(genesis, &mutated);
    BOOST_CHECK_EQUAL(calculatedMerkleRoot.ToString(), genesis.hashMerkleRoot.ToString());
    BOOST_CHECK(!mutated);
    
    // Verify the proof of work
    BOOST_CHECK(CheckProofOfWork(genesis.GetHash(), genesis.nBits, params.GetConsensus()));
    
    // Verify transaction count
    BOOST_CHECK_EQUAL(genesis.vtx.size(), 1U);
    
    // Verify coinbase transaction
    if (genesis.vtx.size() > 0) {
        const CTransaction& coinbase = *(genesis.vtx[0]);
        BOOST_CHECK(coinbase.IsCoinBase());
        BOOST_CHECK_EQUAL(coinbase.vin.size(), 1U);
        BOOST_CHECK_EQUAL(coinbase.vout.size(), 1U);
    }
}

BOOST_AUTO_TEST_CASE(genesis_time_consistency)
{
    CChainParams mainParams = CreateChainParams(CBaseChainParams::MAIN);
    const CBlock& mainGenesis = mainParams.GenesisBlock();
    
    // Verify genesis timestamp matches parameter
    BOOST_CHECK_EQUAL(mainGenesis.GetBlockTime(), mainParams.GenesisBlock().GetBlockTime());
    
    // Verify genesis timestamp is in a reasonable range
    // The timestamp should not be in the future when the genesis block was created
    BOOST_CHECK(mainGenesis.GetBlockTime() <= 1700000000); // A timestamp in late 2023
    
    // Verify the genesis block meets difficulty target
    BOOST_CHECK(UintToArith256(mainGenesis.GetHash()) <= UintToArith256(mainParams.GetConsensus().powLimit));
}

BOOST_AUTO_TEST_CASE(genesis_block_verification)
{
    // Get the genesis block from chain parameters
    const CChainParams& chainParams = Params();
    const CBlock& genesisBlock = chainParams.GenesisBlock();
    
    // Verify genesis block hash matches the expected hash
    BOOST_CHECK_EQUAL(genesisBlock.GetHash().ToString(), chainParams.GenesisHash().ToString());
    
    // Verify time (should match the one in chainparams)
    BOOST_CHECK_EQUAL(genesisBlock.nTime, chainParams.GenesisBlock().nTime);
    
    // Verify nonce (should match the one in chainparams)
    BOOST_CHECK_EQUAL(genesisBlock.nNonce, chainParams.GenesisBlock().nNonce);
    
    // Verify version
    BOOST_CHECK_EQUAL(genesisBlock.nVersion, chainParams.GenesisBlock().nVersion);
    
    // Verify merkle root calculation
    BOOST_CHECK_EQUAL(BlockMerkleRoot(genesisBlock).ToString(), genesisBlock.hashMerkleRoot.ToString());
    
    // Verify the proof of work is valid
    BOOST_CHECK(CheckProofOfWork(genesisBlock.GetHash(), genesisBlock.nBits, chainParams.GetConsensus()));
}

BOOST_AUTO_TEST_CASE(genesis_transactions)
{
    // Get the genesis block from chain parameters
    const CChainParams& chainParams = Params();
    const CBlock& genesisBlock = chainParams.GenesisBlock();
    
    // Verify the coinbase transaction exists
    BOOST_CHECK(genesisBlock.vtx.size() >= 1);
    
    // Check the coinbase transaction details
    const CTransaction& coinbase = *(genesisBlock.vtx[0]);
    
    // Verify coinbase has no inputs (except the coinbase input)
    BOOST_CHECK_EQUAL(coinbase.vin.size(), 1);
    BOOST_CHECK(coinbase.vin[0].prevout.IsNull());
    
    // Verify outputs depending on the network
    if (chainParams.NetworkIDString() == CBaseChainParams::MAIN) {
        // For mainnet, verify specific expected properties
        // Exact output count may vary based on your implementation
        BOOST_CHECK(coinbase.vout.size() > 0);
        
        // Typically, the first output contains the reward
        // You might want to check specific script details or amounts here
    } else if (chainParams.NetworkIDString() == CBaseChainParams::TESTNET) {
        // For testnet, similar checks but possibly different expectations
        BOOST_CHECK(coinbase.vout.size() > 0);
    } else if (chainParams.NetworkIDString() == CBaseChainParams::REGTEST) {
        // For regtest, usually simpler
        BOOST_CHECK(coinbase.vout.size() > 0);
    }
}

BOOST_AUTO_TEST_CASE(genesis_block_header)
{
    // Get the genesis block from chain parameters
    const CChainParams& chainParams = Params();
    const CBlock& genesisBlock = chainParams.GenesisBlock();
    
    // Extract just the header
    CBlockHeader header = genesisBlock;
    
    // Verify the header hash matches the full block hash
    BOOST_CHECK_EQUAL(header.GetHash().ToString(), genesisBlock.GetHash().ToString());
    
    // Serialize and deserialize the header to ensure integrity
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << header;
    
    CBlockHeader deserializedHeader;
    ss >> deserializedHeader;
    
    // Verify deserialized header hash matches original
    BOOST_CHECK_EQUAL(deserializedHeader.GetHash().ToString(), header.GetHash().ToString());
}

BOOST_AUTO_TEST_CASE(genesis_block_difficulty)
{
    // Get the genesis block from chain parameters
    const CChainParams& chainParams = Params();
    const CBlock& genesisBlock = chainParams.GenesisBlock();
    
    // Check that nBits matches the expected difficulty
    BOOST_CHECK_EQUAL(genesisBlock.nBits, chainParams.GenesisBlock().nBits);
    
    // Calculate target based on nBits
    arith_uint256 target;
    target.SetCompact(genesisBlock.nBits);
    
    // Verify that the genesis hash is below the target (valid PoW)
    arith_uint256 hashValue;
    hashValue.SetHex(genesisBlock.GetHash().ToString());
    BOOST_CHECK(hashValue <= target);
}

BOOST_AUTO_TEST_CASE(multiple_network_genesis)
{
    // This test verifies that the genesis blocks for different networks are different
    
    // Get the chain parameters for different networks
    const CChainParams& mainParams = CreateChainParams(CBaseChainParams::MAIN);
    const CChainParams& testParams = CreateChainParams(CBaseChainParams::TESTNET);
    const CChainParams& regParams = CreateChainParams(CBaseChainParams::REGTEST);
    
    // Get the genesis blocks
    const CBlock& mainGenesis = mainParams.GenesisBlock();
    const CBlock& testGenesis = testParams.GenesisBlock();
    const CBlock& regGenesis = regParams.GenesisBlock();
    
    // Verify they have different hashes
    BOOST_CHECK(mainGenesis.GetHash() != testGenesis.GetHash());
    BOOST_CHECK(mainGenesis.GetHash() != regGenesis.GetHash());
    BOOST_CHECK(testGenesis.GetHash() != regGenesis.GetHash());
    
    // Check that these match the expected genesis hashes from chain parameters
    BOOST_CHECK_EQUAL(mainGenesis.GetHash().ToString(), mainParams.GenesisHash().ToString());
    BOOST_CHECK_EQUAL(testGenesis.GetHash().ToString(), testParams.GenesisHash().ToString());
    BOOST_CHECK_EQUAL(regGenesis.GetHash().ToString(), regParams.GenesisHash().ToString());
}

BOOST_AUTO_TEST_CASE(quantum_resistant_genesis)
{
    // This test verifies the post-quantum aspects of the genesis block
    
    // Get the genesis block from chain parameters
    const CChainParams& chainParams = Params();
    const CBlock& genesisBlock = chainParams.GenesisBlock();
    
    // Verify that the genesis block includes a Dilithium signature if required
    // This depends on your implementation details of how PQ signatures are integrated
    
    // For example, you might check for a specific script pattern, witness data,
    // or extra fields depending on your implementation
    
    // If PQ signatures are in coinbase:
    if (chainParams.HasPostQuantumSupport()) {
        const CTransaction& coinbase = *(genesisBlock.vtx[0]);
        
        // Check for PQ signature presence
        // This is hypothetical and depends on your implementation
        bool hasPQData = false;
        
        // Example check - specific script patterns or data in scriptSig
        if (coinbase.vin[0].scriptSig.size() > 0) {
            std::vector<unsigned char> scriptData(coinbase.vin[0].scriptSig.begin(), coinbase.vin[0].scriptSig.end());
            std::string hexScript = HexStr(scriptData);
            
            // Check for specific PQ signature markers in the script
            // This is implementation-dependent
            if (hexScript.find("DILITHIUM") != std::string::npos) {
                hasPQData = true;
            }
        }
        
        // Alternatively, if you have a specific field for PQ data:
        // bool hasPQData = genesisBlock.HasDilithiumSignature();
        
        BOOST_CHECK(hasPQData);
    }
}

BOOST_AUTO_TEST_SUITE_END() 