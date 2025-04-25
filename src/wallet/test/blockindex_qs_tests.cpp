// wallet/test/blockindex_qs_tests.cpp
// Test Round-Trip of Dilithium3 headerPubKey and headerSig via BlockTreeDB

#include <boost/test/unit_test.hpp>
#include <node/blockstorage.h>        // kernel::BlockTreeDB
#include <kernel/chainparams.h>       // Params()
#include <util/fs.h>                  // fs::path
#include <util/signalinterrupt.h>     // util::SignalInterrupt
#include <dbwrapper.h>                // CDBWrapper, CDBBatch
#include <chain.h>                    // uint256
#include <cstdint>
#include <map>
#include <memory>
#include <vector>
#include <utility>

// Test fixture for basic chain setup
#include <test/util/setup_common.h>

using namespace kernel;

BOOST_FIXTURE_TEST_SUITE(blockindex_qs_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(header_pubkey_sig_roundtrip)
{
    // Prepare in-memory LevelDB for block index
    fs::path tmpdir = GetDataDir() / "qs_blkidx";
    if (fs::exists(tmpdir)) fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);
    DBParams params{tmpdir, /*cache_bytes=*/1 << 20, /*memory_only=*/true, /*wipe_data=*/true};
    CDBWrapper wrapper(params);
    kernel::BlockTreeDB btdb(params);

    // Create a CDiskBlockIndex with sample header fields
    CDiskBlockIndex diskidx;
    diskidx.nHeight = 7;
    diskidx.nStatus = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
    diskidx.nTx = 1;
    diskidx.nFile = diskidx.nDataPos = diskidx.nUndoPos = 0;
    diskidx.nVersion = CBlockHeader().nVersion;
    diskidx.hashPrev = uint256::ONE;
    diskidx.hashMerkleRoot = uint256::ZERO;
    diskidx.nTime = 123456;
    diskidx.nBits = 0x1d00ffff;
    diskidx.nNonce = 42;
    diskidx.headerPubKey = {0x01, 0x02, 0x03};
    diskidx.headerSig    = {0xAA, 0xBB};
    uint256 blockhash = diskidx.ConstructBlockHash();

    // Write to DB
    {
        CDBBatch batch(wrapper);
        // Write under the same key prefix as BlockTreeDB (DB_BLOCK_INDEX = 'b')
        batch.Write(std::make_pair(uint8_t('b'), blockhash), diskidx);
        wrapper.WriteBatch(batch, /*fSync=*/true);
    }

    // Prepare map to receive loaded CBlockIndex
    std::map<uint256, std::unique_ptr<CBlockIndex>> idxmap;
    auto insert = [&](const uint256& h) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        auto up = std::make_unique<CBlockIndex>();
        CBlockIndex* ptr = up.get();
        idxmap.emplace(h, std::move(up));
        return ptr;
    };

    util::SignalInterrupt interrupt;
    // Load from DB
    {
        LOCK(cs_main);
        bool ok = btdb.LoadBlockIndexGuts(Params().GetConsensus(), insert, interrupt);
        BOOST_CHECK(ok);
    }

    auto it = idxmap.find(blockhash);
    BOOST_REQUIRE(it != idxmap.end());
    CBlockIndex* loaded = it->second.get();
    // Check that headerPubKey and headerSig round-trip correctly
    BOOST_CHECK_EQUAL_COLLECTIONS(
        loaded->headerPubKey.begin(), loaded->headerPubKey.end(),
        diskidx.headerPubKey.begin(),  diskidx.headerPubKey.end());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        loaded->headerSig.begin(),    loaded->headerSig.end(),
        diskidx.headerSig.begin(),    diskidx.headerSig.end());
}

BOOST_AUTO_TEST_SUITE_END()