#include <monitoring/collectors.h>
#include <logging.h>
#include <util/time.h>
#include <pow.h>
#include <policy/fees.h>

namespace qubitcoin {
namespace monitoring {

MetricsCollectorManager* MetricsCollectorManager::instance = nullptr;

MetricsCollectorManager& MetricsCollectorManager::Instance() {
    if (!instance) {
        instance = new MetricsCollectorManager();
    }
    return *instance;
}

bool MetricsCollectorManager::Initialize(ChainstateManager* chainman, CTxMemPool* mempool, CConnman* connman) {
    consensus_metrics = std::make_unique<ConsensusMetrics>(chainman);
    mempool_metrics = std::make_unique<MempoolMetrics>(mempool);
    mining_metrics = std::make_unique<MiningMetrics>();
    network_metrics = std::make_unique<NetworkMetrics>(connman);
    
    // Start the HTTP server for Prometheus
    if (!MetricsRegistry::Instance().Start()) {
        LogPrintf("Failed to start Prometheus metrics server\n");
        return false;
    }
    
    // Start all collectors
    consensus_metrics->Start();
    mempool_metrics->Start();
    mining_metrics->Start();
    network_metrics->Start();
    
    LogPrintf("Metrics collectors initialized and started\n");
    return true;
}

void MetricsCollectorManager::Shutdown() {
    // Stop all collectors
    if (consensus_metrics) consensus_metrics->Stop();
    if (mempool_metrics) mempool_metrics->Stop();
    if (mining_metrics) mining_metrics->Stop();
    if (network_metrics) network_metrics->Stop();
    
    MetricsRegistry::Instance().Stop();
    LogPrintf("Metrics collectors shut down\n");
}

// ConsensusMetrics implementation
ConsensusMetrics::ConsensusMetrics(ChainstateManager* chainman) : chainman(chainman) {
    auto& registry = MetricsRegistry::Instance();
    
    chain_height = registry.CreateGauge(
        "qubitcoin_blockchain_height", 
        "Current blockchain height (number of blocks)"
    );
    
    chain_difficulty = registry.CreateGauge(
        "qubitcoin_blockchain_difficulty", 
        "Current blockchain difficulty"
    );
    
    chain_median_time = registry.CreateGauge(
        "qubitcoin_blockchain_median_time", 
        "Median time of the current tip block"
    );
    
    total_tx_count = registry.CreateCounter(
        "qubitcoin_blockchain_total_transactions", 
        "Total number of transactions in the blockchain"
    );
    
    verification_progress = registry.CreateGauge(
        "qubitcoin_blockchain_verification_progress", 
        "Current blockchain verification progress (0.0-1.0)"
    );
    
    // Histogram with buckets from 0 to 1200 seconds (20 minutes) for block interval
    std::vector<double> interval_buckets = {60, 120, 180, 240, 300, 360, 420, 480, 540, 600, 900, 1200};
    block_interval_histogram = registry.CreateHistogram(
        "qubitcoin_blockchain_block_interval_seconds", 
        "Time between consecutive blocks in seconds",
        interval_buckets
    );
    
    last_block_time = registry.CreateGauge(
        "qubitcoin_blockchain_last_block_time", 
        "Timestamp of the last block"
    );
    
    last_block_size = registry.CreateGauge(
        "qubitcoin_blockchain_last_block_size_bytes", 
        "Size of the last block in bytes"
    );
    
    last_block_weight = registry.CreateGauge(
        "qubitcoin_blockchain_last_block_weight", 
        "Weight of the last block"
    );
    
    last_block_tx_count = registry.CreateGauge(
        "qubitcoin_blockchain_last_block_tx_count", 
        "Number of transactions in the last block"
    );
}

void ConsensusMetrics::CollectMetrics() {
    if (!chainman) return;
    
    auto active_chain = chainman->ActiveChain();
    CBlockIndex* tip = active_chain.Tip();
    if (!tip) return;
    
    chain_height->Set(tip->nHeight);
    
    arith_uint256 diffTarget;
    diffTarget.SetCompact(tip->nBits);
    double difficulty = GetDifficulty(tip);
    chain_difficulty->Set(difficulty);
    
    chain_median_time->Set(tip->GetMedianTimePast());
    
    // Calculate total transaction count (approximate if needed)
    // This is a counter, so we only want to set it once
    if (total_tx_count->Get() == 0) {
        CBlockIndex* block = tip;
        int64_t txcount = 0;
        int height = tip->nHeight;
        
        // Sample blocks to estimate total tx count for efficiency
        const int SAMPLE_INTERVAL = 100;
        int samples = 0;
        double tx_per_block_avg = 0;
        
        while (block && samples < 1000) {
            if (block->nHeight % SAMPLE_INTERVAL == 0 || block->nHeight == height) {
                txcount += block->nTx;
                samples++;
                if (block->nHeight < SAMPLE_INTERVAL) break;
            }
            tx_per_block_avg = static_cast<double>(txcount) / samples;
            block = block->pprev;
        }
        
        // Estimate total based on average
        int64_t estimate = static_cast<int64_t>(tx_per_block_avg * (height + 1));
        total_tx_count->Add(estimate);
    }
    
    // Verification progress
    verification_progress->Set(chainman->m_blockman.m_block_tree_db->CalculatePercentage());
    
    // Compute block interval if we have at least 2 blocks
    if (tip->pprev) {
        int64_t interval = tip->GetBlockTime() - tip->pprev->GetBlockTime();
        block_interval_histogram->Observe(interval);
    }
    
    // Last block stats
    last_block_time->Set(tip->GetBlockTime());
    last_block_size->Set(tip->nSize);
    last_block_weight->Set(tip->nWeight);
    last_block_tx_count->Set(tip->nTx);
}

// MempoolMetrics implementation
MempoolMetrics::MempoolMetrics(CTxMemPool* mempool) : mempool(mempool) {
    auto& registry = MetricsRegistry::Instance();
    
    mempool_size = registry.CreateGauge(
        "qubitcoin_mempool_size", 
        "Number of transactions in the mempool"
    );
    
    mempool_bytes = registry.CreateGauge(
        "qubitcoin_mempool_bytes", 
        "Size of the mempool in bytes"
    );
    
    mempool_usage = registry.CreateGauge(
        "qubitcoin_mempool_bytes_usage", 
        "Memory usage of the mempool in bytes"
    );
    
    mempool_max_size = registry.CreateGauge(
        "qubitcoin_mempool_max_bytes", 
        "Maximum allowed size of the mempool in bytes"
    );
    
    // Fee histogram with buckets (in satoshis per KB)
    std::vector<double> fee_buckets = {1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000};
    mempool_fee_histogram = registry.CreateHistogram(
        "qubitcoin_mempool_fee_satoshis_per_kb", 
        "Distribution of transaction fees in the mempool (satoshis per KB)",
        fee_buckets
    );
    
    mempool_min_fee = registry.CreateGauge(
        "qubitcoin_mempool_min_fee_satoshis_per_kb", 
        "Minimum fee to enter the mempool (satoshis per KB)"
    );
    
    mempool_total_fee = registry.CreateGauge(
        "qubitcoin_mempool_total_fee_btc", 
        "Total fees in the mempool (in BTC)"
    );
    
    mempool_max_memory = registry.CreateGauge(
        "qubitcoin_mempool_max_memory_bytes", 
        "Maximum memory usage allowed for the mempool"
    );
    
    mempool_dynamic_usage = registry.CreateGauge(
        "qubitcoin_mempool_dynamic_usage_bytes", 
        "Current dynamic memory usage of the mempool"
    );
}

void MempoolMetrics::CollectMetrics() {
    if (!mempool) return;
    
    LOCK(mempool->cs);
    
    mempool_size->Set(mempool->size());
    mempool_bytes->Set(mempool->GetTotalTxSize());
    mempool_usage->Set(mempool->GetTotalTxCount());
    mempool_max_size->Set(mempool->m_opts.max_size_bytes);
    
    // Fee metrics
    CAmount total_fees = 0;
    for (const auto& entry : mempool->mapTx) {
        total_fees += entry.GetFee();
        // Add to fee histogram (convert to satoshis per KB)
        double fee_per_kb = entry.GetFeeRate().GetFeePerK();
        mempool_fee_histogram->Observe(fee_per_kb);
    }
    
    // Convert total fees from satoshi to BTC
    mempool_total_fee->Set(total_fees / COIN);
    
    // Get minimum fee rate in sat/KB
    CFeeRate min_rate = mempool->GetMinFee();
    mempool_min_fee->Set(min_rate.GetFeePerK());
    
    mempool_max_memory->Set(mempool->m_opts.max_size_bytes);
    mempool_dynamic_usage->Set(mempool->DynamicMemoryUsage());
}

// MiningMetrics implementation
MiningMetrics::MiningMetrics() {
    auto& registry = MetricsRegistry::Instance();
    
    blocks_mined = registry.CreateCounter(
        "qubitcoin_miner_blocks_mined", 
        "Total number of blocks mined by this node"
    );
    
    hash_power = registry.CreateGauge(
        "qubitcoin_miner_hash_rate", 
        "Current hash rate of the local miner in hashes per second"
    );
    
    network_hash_power_estimate = registry.CreateGauge(
        "qubitcoin_network_hash_rate_estimate", 
        "Estimated network hash rate in hashes per second"
    );
    
    network_difficulty = registry.CreateGauge(
        "qubitcoin_network_difficulty", 
        "Current network difficulty"
    );
    
    miner_revenue = registry.CreateGauge(
        "qubitcoin_miner_revenue_btc", 
        "Total miner revenue (block subsidy + fees) in BTC for the last block"
    );
    
    template_size = registry.CreateGauge(
        "qubitcoin_miner_template_size_bytes", 
        "Size of the current block template in bytes"
    );
    
    template_txcount = registry.CreateGauge(
        "qubitcoin_miner_template_tx_count", 
        "Number of transactions in the current block template"
    );
    
    template_weight = registry.CreateGauge(
        "qubitcoin_miner_template_weight", 
        "Weight of the current block template"
    );
    
    template_fees = registry.CreateGauge(
        "qubitcoin_miner_template_fees_btc", 
        "Total fees in the current block template in BTC"
    );
}

void MiningMetrics::CollectMetrics() {
    // Some metrics require updates from outside (hash power, blocks found)
    // Network difficulty and hash rate can be estimated from chain data
    CBlockIndex* tip = chainman->ActiveChain().Tip();
    if (!tip) return;
    
    double difficulty = GetDifficulty(tip);
    network_difficulty->Set(difficulty);
    
    // Estimate network hash rate (hashes/second)
    // Formula: difficulty * 2^32 / average_block_time
    double avg_block_time = 600; // 10 minutes in seconds
    if (tip->pprev) {
        // Calculate average block time from last 144 blocks (approximately one day)
        CBlockIndex* block = tip;
        int count = 0;
        int64_t time_diff = 0;
        CBlockIndex* start_block = nullptr;
        
        while (block && count < 144) {
            if (count == 0) {
                start_block = block;
            } else {
                time_diff += start_block->GetBlockTime() - block->GetBlockTime();
            }
            block = block->pprev;
            count++;
        }
        
        if (count > 1) {
            avg_block_time = static_cast<double>(time_diff) / (count - 1);
        }
    }
    
    double hash_rate_estimate = difficulty * 4294967296.0 / avg_block_time;
    network_hash_power_estimate->Set(hash_rate_estimate);
}

void MiningMetrics::IncrementBlocksMined() {
    blocks_mined->Inc();
}

void MiningMetrics::SetHashPower(double hashrate) {
    hash_power->Set(hashrate);
}

void MiningMetrics::UpdateBlockTemplate(size_t txcount, size_t size, size_t weight, CAmount fees) {
    template_size->Set(size);
    template_txcount->Set(txcount);
    template_weight->Set(weight);
    template_fees->Set(fees / COIN);
}

// NetworkMetrics implementation
NetworkMetrics::NetworkMetrics(CConnman* connman) : connman(connman) {
    auto& registry = MetricsRegistry::Instance();
    
    connected_peers = registry.CreateGauge(
        "qubitcoin_p2p_connected_peers", 
        "Number of currently connected peers"
    );
    
    inbound_peers = registry.CreateGauge(
        "qubitcoin_p2p_inbound_peers", 
        "Number of inbound peer connections"
    );
    
    outbound_peers = registry.CreateGauge(
        "qubitcoin_p2p_outbound_peers", 
        "Number of outbound peer connections"
    );
    
    block_relay_only_peers = registry.CreateGauge(
        "qubitcoin_p2p_block_relay_only_peers", 
        "Number of block-relay-only peer connections"
    );
    
    addr_processed = registry.CreateGauge(
        "qubitcoin_p2p_addr_processed", 
        "Number of peer addresses processed"
    );
    
    addr_rate_limited = registry.CreateGauge(
        "qubitcoin_p2p_addr_rate_limited", 
        "Number of peer addresses rate limited"
    );
    
    bytes_recv = registry.CreateCounter(
        "qubitcoin_p2p_bytes_received_total", 
        "Total bytes received from P2P network"
    );
    
    bytes_sent = registry.CreateCounter(
        "qubitcoin_p2p_bytes_sent_total", 
        "Total bytes sent to P2P network"
    );
    
    msgs_recv = registry.CreateCounter(
        "qubitcoin_p2p_messages_received_total", 
        "Total P2P messages received"
    );
    
    msgs_sent = registry.CreateCounter(
        "qubitcoin_p2p_messages_sent_total", 
        "Total P2P messages sent"
    );
}

void NetworkMetrics::CollectMetrics() {
    if (!connman) return;
    
    // Get network statistics
    int total = 0;
    int inbound = 0;
    int outbound = 0;
    int block_relay = 0;
    
    connman->ForEachNode([&](CNode* node) {
        total++;
        if (node->IsInboundConn()) inbound++;
        else outbound++;
        if (node->IsBlockOnlyConn()) block_relay++;
    });
    
    connected_peers->Set(total);
    inbound_peers->Set(inbound);
    outbound_peers->Set(outbound);
    block_relay_only_peers->Set(block_relay);
    
    // Traffic stats
    bytes_recv->Add(connman->GetTotalBytesRecv() - bytes_recv->Get());
    bytes_sent->Add(connman->GetTotalBytesSent() - bytes_sent->Get());
    msgs_recv->Add(connman->GetTotalRecvMsg() - msgs_recv->Get());
    msgs_sent->Add(connman->GetTotalSendMsg() - msgs_sent->Get());
}

}} // namespace qubitcoin::monitoring 