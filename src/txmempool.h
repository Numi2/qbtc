// src/txmempool.h

#ifndef QUBITCOIN_TXMEMPOOL_H
#define QUBITCOIN_TXMEMPOOL_H

#include <coins.h>
#include <consensus/amount.h>
#include <indirectmap.h>
#include <kernel/cs_main.h>
#include <kernel/mempool_entry.h>          // IWYU pragma: export
#include <kernel/mempool_limits.h>         // IWYU pragma: export
#include <kernel/mempool_options.h>        // IWYU pragma: export
#include <kernel/mempool_removal_reason.h> // IWYU pragma: export
#include <policy/feerate.h>
#include <policy/packages.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <util/epochguard.h>
#include <util/hasher.h>
#include <util/result.h>
#include <util/feefrac.h>

#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/indexed_by.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/tag.hpp>
#include <boost/multi_index_container.hpp>

#include <atomic>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

class CChain;
class ValidationSignals;

struct bilingual_str;

/** Fake height value used in Coin to signify they are only in the mempool */
static const uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF;

bool TestLockPointValidity(CChain& active_chain, const LockPoints& lp) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

struct mempoolentry_txid {
    using result_type = uint256;
    result_type operator()(const CTxMemPoolEntry &e) const { return e.GetTx().GetHash(); }
    result_type operator()(const CTransactionRef& tx) const { return tx->GetHash(); }
};

struct mempoolentry_wtxid {
    using result_type = uint256;
    result_type operator()(const CTxMemPoolEntry &e) const { return e.GetTx().GetWitnessHash(); }
    result_type operator()(const CTransactionRef& tx) const { return tx->GetWitnessHash(); }
};

class CompareTxMemPoolEntryByDescendantScore {
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const {
        double af, asz, bf, bsz;
        GetModFeeAndSize(a, af, asz);
        GetModFeeAndSize(b, bf, bsz);
        double f1 = af * bsz, f2 = bf * asz;
        if (f1 == f2) return a.GetTime() >= b.GetTime();
        return f1 < f2;
    }
    void GetModFeeAndSize(const CTxMemPoolEntry &e, double &fee, double &size) const {
        double f1 = (double)e.GetModifiedFee() * e.GetSizeWithDescendants();
        double f2 = (double)e.GetModFeesWithDescendants() * e.GetTxSize();
        if (f2 > f1) { fee = e.GetModFeesWithDescendants(); size = e.GetSizeWithDescendants(); }
        else       { fee = e.GetModifiedFee();           size = e.GetTxSize(); }
    }
};

class CompareTxMemPoolEntryByScore {
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const {
        double f1 = (double)a.GetFee() * b.GetTxSize();
        double f2 = (double)b.GetFee() * a.GetTxSize();
        if (f1 == f2) return b.GetTx().GetHash() < a.GetTx().GetHash();
        return f1 > f2;
    }
};

class CompareTxMemPoolEntryByEntryTime {
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const {
        return a.GetTime() < b.GetTime();
    }
};

class CompareTxMemPoolEntryByAncestorFee {
public:
    template<typename T>
    bool operator()(const T& a, const T& b) const {
        double af, asz, bf, bsz;
        GetModFeeAndSize(a, af, asz);
        GetModFeeAndSize(b, bf, bsz);
        double f1 = af * bsz, f2 = bf * asz;
        if (f1 == f2) return a.GetTx().GetHash() < b.GetTx().GetHash();
        return f1 > f2;
    }
    template<typename T>
    void GetModFeeAndSize(const T &e, double &fee, double &size) const {
        double f1 = (double)e.GetModifiedFee() * e.GetSizeWithAncestors();
        double f2 = (double)e.GetModFeesWithAncestors() * e.GetTxSize();
        if (f1 > f2) { fee = e.GetModFeesWithAncestors(); size = e.GetSizeWithAncestors(); }
        else         { fee = e.GetModifiedFee();           size = e.GetTxSize(); }
    }
};

struct descendant_score {};
struct entry_time {};
struct ancestor_score {};
struct index_by_wtxid {};

struct TxMempoolInfo {
    CTransactionRef tx;
    std::chrono::seconds m_time;
    CAmount fee;
    int32_t vsize;
    int64_t nFeeDelta;
};

/**
 * CTxMemPool stores valid transactions that may be included in the next block.
 * It tracks fees, sizes, ancestors/descendants, and supports prioritisation,
 * trimming, expiry, reorg handling, and conflict resolution.
 */
class CTxMemPool {
protected:
    std::atomic<unsigned int> nTransactionsUpdated{0};

    uint64_t totalTxSize GUARDED_BY(cs){0};
    CAmount m_total_fee GUARDED_BY(cs){0};
    uint64_t cachedInnerUsage GUARDED_BY(cs){0};

    mutable int64_t lastRollingFeeUpdate GUARDED_BY(cs){GetTime()};
    mutable bool blockSinceLastRollingFeeBump GUARDED_BY(cs){false};
    mutable double rollingMinimumFeeRate GUARDED_BY(cs){0};
    mutable Epoch m_epoch GUARDED_BY(cs){};

    mutable uint64_t m_sequence_number GUARDED_BY(cs){1};

    void trackPackageRemoved(const CFeeRate& rate) EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool m_load_tried GUARDED_BY(cs){false};

    CFeeRate GetMinFee(size_t sizelimit) const;

public:
    static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12;

    struct CTxMemPoolEntry_Indices : boost::multi_index::indexed_by<
        boost::multi_index::hashed_unique<mempoolentry_txid, SaltedTxidHasher>,
        boost::multi_index::hashed_unique<boost::multi_index::tag<index_by_wtxid>, mempoolentry_wtxid, SaltedTxidHasher>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<descendant_score>, boost::multi_index::identity<CTxMemPoolEntry>, CompareTxMemPoolEntryByDescendantScore>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<entry_time>, boost::multi_index::identity<CTxMemPoolEntry>, CompareTxMemPoolEntryByEntryTime>,
        boost::multi_index::ordered_non_unique<boost::multi_index::tag<ancestor_score>, boost::multi_index::identity<CTxMemPoolEntry>, CompareTxMemPoolEntryByAncestorFee>
    > {};

    using indexed_transaction_set = boost::multi_index_container<CTxMemPoolEntry, CTxMemPoolEntry_Indices>;

    mutable RecursiveMutex cs;
    indexed_transaction_set mapTx GUARDED_BY(cs);
    std::vector<CTransactionRef> txns_randomized GUARDED_BY(cs);

    using txiter = indexed_transaction_set::nth_index<0>::type::const_iterator;
    typedef std::set<txiter, CompareIteratorByHash> setEntries;

    using Limits = kernel::MemPoolLimits;
    using Options = kernel::MemPoolOptions;

    indirectmap<COutPoint, const CTransaction*> mapNextTx GUARDED_BY(cs);
    std::map<uint256, CAmount> mapDeltas GUARDED_BY(cs);

    const Options m_opts;

    explicit CTxMemPool(Options opts, bilingual_str& error);

    void check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    void removeRecursive(const CTransaction& tx, MemPoolRemovalReason reason) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void removeForReorg(CChain& chain, std::function<bool(txiter)> filter) EXCLUSIVE_LOCKS_REQUIRED(cs, cs_main);
    void removeConflicts(const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight) EXCLUSIVE_LOCKS_REQUIRED(cs);

    bool CompareDepthAndScore(const uint256& a, const uint256& b, bool wtxid=false);
    bool isSpent(const COutPoint& outpoint) const;
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);
    bool HasNoInputsOf(const CTransaction& tx) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    void PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta);
    void ApplyDelta(const uint256& hash, CAmount &nFeeDelta) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    void ClearPrioritisation(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs);

    struct delta_info { bool in_mempool; CAmount delta; std::optional<CAmount> modified_fee; uint256 txid; };
    std::vector<delta_info> GetPrioritisedTransactions() const EXCLUSIVE_LOCKS_REQUIRED(!cs);

    const CTransaction* GetConflictTx(const COutPoint& prevout) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    std::optional<txiter> GetIter(const uint256& txid) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    setEntries GetIterSet(const std::set<Txid>& hashes) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    std::vector<txiter> GetIterVec(const std::vector<uint256>& txids) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    void UpdateTransactionsFromBlock(const std::vector<uint256>& v, unsigned int height) EXCLUSIVE_LOCKS_REQUIRED(cs, cs_main) LOCKS_EXCLUDED(m_epoch);

    util::Result<setEntries> CalculateMemPoolAncestors(const CTxMemPoolEntry& entry, const Limits& limits, bool search=true) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    setEntries AssumeCalculateMemPoolAncestors(std::string_view fn, const CTxMemPoolEntry &entry, const Limits& limits, bool search=true) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::vector<txiter> GatherClusters(const std::vector<uint256>& txids) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    util::Result<void> CheckPackageLimits(const Package& package, int64_t total_vsize) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    void CalculateDescendants(txiter it, setEntries& d) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    CFeeRate GetMinFee() const { return GetMinFee(m_opts.max_size_bytes); }

    void TrimToSize(size_t sizelimit, std::vector<COutPoint>* pv=nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs);
    int Expire(std::chrono::seconds time) EXCLUSIVE_LOCKS_REQUIRED(cs);

    void GetTransactionAncestry(const uint256& txid, size_t& anc, size_t& desc, size_t* ancsize=nullptr, CAmount* ancfees=nullptr) const;

    bool GetLoadTried() const;
    void SetLoadTried(bool tried);

    unsigned long size() const { LOCK(cs); return mapTx.size(); }
    uint64_t GetTotalTxSize() const EXCLUSIVE_LOCKS_REQUIRED(cs) { return totalTxSize; }
    CAmount GetTotalFee() const EXCLUSIVE_LOCKS_REQUIRED(cs) { return m_total_fee; }
    bool exists(const GenTxid& gtxid) const EXCLUSIVE_LOCKS_REQUIRED(cs);

    const CTxMemPoolEntry* GetEntry(const Txid& txid) const LIFETIMEBOUND EXCLUSIVE_LOCKS_REQUIRED(cs);
    CTransactionRef get(const uint256& hash) const;
    txiter get_iter_from_wtxid(const uint256& wtxid) const EXCLUSIVE_LOCKS_REQUIRED(cs);
    TxMempoolInfo info(const GenTxid& gtxid) const;
    TxMempoolInfo info_for_relay(const GenTxid& gtxid, uint64_t last_seq) const;
    std::vector<CTxMemPoolEntryRef> entryAll() const EXCLUSIVE_LOCKS_REQUIRED(cs);
    std::vector<TxMempoolInfo> infoAll() const;
    size_t DynamicMemoryUsage() const;

    void AddUnbroadcastTx(const uint256& txid) { LOCK(cs); if (exists(GenTxid::Txid(txid))) m_unbroadcast_txids.insert(txid); }
    void RemoveUnbroadcastTx(const uint256& txid, bool unchecked=false);
    std::set<uint256> GetUnbroadcastTxs() const { LOCK(cs); return m_unbroadcast_txids; }
    bool IsUnbroadcastTx(const uint256& txid) const EXCLUSIVE_LOCKS_REQUIRED(cs) { return m_unbroadcast_txids.count(txid); }

    uint64_t GetAndIncrementSequence() const EXCLUSIVE_LOCKS_REQUIRED(cs) { return m_sequence_number++; }
    uint64_t GetSequence() const EXCLUSIVE_LOCKS_REQUIRED(cs) { return m_sequence_number; }

    std::optional<std::string> CheckConflictTopology(const setEntries& conflicts);

    class ChangeSet {
    public:
        explicit ChangeSet(CTxMemPool* pool) : m_pool(pool) {}
        ~ChangeSet() EXCLUSIVE_LOCKS_REQUIRED(m_pool->cs) { m_pool->m_have_changeset = false; }
        ChangeSet(const ChangeSet&) = delete;
        ChangeSet& operator=(const ChangeSet&) = delete;
        using TxHandle = CTxMemPool::txiter;
        TxHandle StageAddition(const CTransactionRef& tx, CAmount fee, int64_t time, unsigned int height, uint64_t seq, bool spends_coinbase, int64_t sigops, LockPoints lp);
        void StageRemoval(txiter it) { m_to_remove.insert(it); }
        const setEntries& GetRemovals() const { return m_to_remove; }
        util::Result<setEntries> CalculateMemPoolAncestors(TxHandle tx, const Limits& limits);
        std::vector<CTransactionRef> GetAddedTxns() const;
        util::Result<std::pair<std::vector<FeeFrac>, std::vector<FeeFrac>>> CalculateChunksForRBF();
        size_t GetTxCount() const { return m_entry_vec.size(); }
        const CTransaction& GetAddedTxn(size_t idx) const { return m_entry_vec[idx]->GetTx(); }
        void Apply() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    private:
        CTxMemPool* m_pool;
        indexed_transaction_set m_to_add;
        std::vector<txiter> m_entry_vec;
        std::map<txiter, setEntries, CompareIteratorByHash> m_ancestors;
        setEntries m_to_remove;
        friend class CTxMemPool;
    };
    std::unique_ptr<ChangeSet> GetChangeSet() EXCLUSIVE_LOCKS_REQUIRED(cs) {
        Assume(!m_have_changeset);
        m_have_changeset = true;
        return std::make_unique<ChangeSet>(this);
    }

private:
    void Apply(ChangeSet* cs) EXCLUSIVE_LOCKS_REQUIRED(cs->m_pool->cs);
    void addNewTransaction(txiter it) EXCLUSIVE_LOCKS_REQUIRED(cs);
    void addNewTransaction(txiter it, setEntries& anc) EXCLUSIVE_LOCKS_REQUIRED(cs);

    std::set<uint256> m_unbroadcast_txids GUARDED_BY(cs);
    bool m_have_changeset GUARDED_BY(cs){false};
};

class CCoinsViewMemPool : public CCoinsViewBacked {
    std::unordered_map<COutPoint, Coin, SaltedOutpointHasher> m_temp_added;
    mutable std::unordered_set<COutPoint, SaltedOutpointHasher> m_non_base_coins;
protected:
    const CTxMemPool& mempool;
public:
    CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn);
    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    void PackageAddTransaction(const CTransactionRef& tx);
    std::unordered_set<COutPoint, SaltedOutpointHasher> GetNonBaseCoins() const { return m_non_base_coins; }
    void Reset();
};

#endif // QUBITCOIN_TXMEMPOOL_H