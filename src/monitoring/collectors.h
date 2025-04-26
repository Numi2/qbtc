#ifndef QUBITCOIN_MONITORING_COLLECTORS_H
#define QUBITCOIN_MONITORING_COLLECTORS_H

#include <monitoring/metrics.h>
#include <chain.h>
#include <txmempool.h>
#include <validation.h>
#include <net.h>

#include <memory>
#include <thread>
#include <atomic>

namespace qubitcoin {
namespace monitoring {

/**
 * Base class for periodic metric collectors
 */
class MetricCollector {
protected:
    std::unique_ptr<std::thread> collector_thread;
    std::atomic<bool> running;
    std::chrono::seconds interval;

    virtual void CollectMetrics() = 0;
    
    void ThreadFunction() {
        while (running) {
            CollectMetrics();
            std::this_thread::sleep_for(interval);
        }
    }

public:
    MetricCollector(std::chrono::seconds interval = std::chrono::seconds(10))
        : running(false), interval(interval) {}
    
    virtual ~MetricCollector() {
        Stop();
    }
    
    void Start() {
        if (running) return;
        running = true;
        collector_thread = std::make_unique<std::thread>(&MetricCollector::ThreadFunction, this);
    }
    
    void Stop() {
        if (!running) return;
        running = false;
        if (collector_thread && collector_thread->joinable()) {
            collector_thread->join();
        }
    }
};

/**
 * Collects metrics about the blockchain and consensus state
 */
class ConsensusMetrics : public MetricCollector {
private:
    ChainstateManager* chainman;
    std::shared_ptr<Gauge> chain_height;
    std::shared_ptr<Gauge> chain_difficulty;
    std::shared_ptr<Gauge> chain_median_time;
    std::shared_ptr<Counter> total_tx_count;
    std::shared_ptr<Gauge> verification_progress;
    std::shared_ptr<Histogram> block_interval_histogram;
    std::shared_ptr<Gauge> last_block_time;
    std::shared_ptr<Gauge> last_block_size;
    std::shared_ptr<Gauge> last_block_weight;
    std::shared_ptr<Gauge> last_block_tx_count;

protected:
    void CollectMetrics() override;

public:
    ConsensusMetrics(ChainstateManager* chainman);
    ~ConsensusMetrics() override = default;
};

/**
 * Collects metrics about the memory pool
 */
class MempoolMetrics : public MetricCollector {
private:
    CTxMemPool* mempool;
    std::shared_ptr<Gauge> mempool_size;
    std::shared_ptr<Gauge> mempool_bytes;
    std::shared_ptr<Gauge> mempool_usage;
    std::shared_ptr<Gauge> mempool_max_size;
    std::shared_ptr<Histogram> mempool_fee_histogram;
    std::shared_ptr<Gauge> mempool_min_fee;
    std::shared_ptr<Gauge> mempool_total_fee;
    std::shared_ptr<Gauge> mempool_max_memory;
    std::shared_ptr<Gauge> mempool_dynamic_usage;

protected:
    void CollectMetrics() override;

public:
    MempoolMetrics(CTxMemPool* mempool);
    ~MempoolMetrics() override = default;
};

/**
 * Collects metrics about mining and block creation
 */
class MiningMetrics : public MetricCollector {
private:
    std::shared_ptr<Counter> blocks_mined;
    std::shared_ptr<Gauge> hash_power;
    std::shared_ptr<Gauge> network_hash_power_estimate;
    std::shared_ptr<Gauge> network_difficulty;
    std::shared_ptr<Gauge> miner_revenue;
    std::shared_ptr<Gauge> template_size;
    std::shared_ptr<Gauge> template_txcount;
    std::shared_ptr<Gauge> template_weight;
    std::shared_ptr<Gauge> template_fees;

protected:
    void CollectMetrics() override;

public:
    MiningMetrics();
    ~MiningMetrics() override = default;
    
    // Methods to increment counters/gauges from mining code
    void IncrementBlocksMined();
    void SetHashPower(double hashrate);
    void UpdateBlockTemplate(size_t txcount, size_t size, size_t weight, CAmount fees);
};

/**
 * Collects metrics about the P2P network
 */
class NetworkMetrics : public MetricCollector {
private:
    CConnman* connman;
    std::shared_ptr<Gauge> connected_peers;
    std::shared_ptr<Gauge> inbound_peers;
    std::shared_ptr<Gauge> outbound_peers;
    std::shared_ptr<Gauge> block_relay_only_peers;
    std::shared_ptr<Gauge> addr_processed;
    std::shared_ptr<Gauge> addr_rate_limited;
    std::shared_ptr<Counter> bytes_recv;
    std::shared_ptr<Counter> bytes_sent;
    std::shared_ptr<Counter> msgs_recv;
    std::shared_ptr<Counter> msgs_sent;

protected:
    void CollectMetrics() override;

public:
    NetworkMetrics(CConnman* connman);
    ~NetworkMetrics() override = default;
};

/**
 * Manager for all metrics collectors
 */
class MetricsCollectorManager {
private:
    static MetricsCollectorManager* instance;
    
    std::unique_ptr<ConsensusMetrics> consensus_metrics;
    std::unique_ptr<MempoolMetrics> mempool_metrics;
    std::unique_ptr<MiningMetrics> mining_metrics;
    std::unique_ptr<NetworkMetrics> network_metrics;
    
public:
    static MetricsCollectorManager& Instance();
    
    // Start metrics collection after components are initialized
    bool Initialize(ChainstateManager* chainman, CTxMemPool* mempool, CConnman* connman);
    
    // Stop collectors - called during shutdown
    void Shutdown();
    
    // Get references to individual collectors
    ConsensusMetrics* GetConsensusMetrics() { return consensus_metrics.get(); }
    MempoolMetrics* GetMempoolMetrics() { return mempool_metrics.get(); }
    MiningMetrics* GetMiningMetrics() { return mining_metrics.get(); }
    NetworkMetrics* GetNetworkMetrics() { return network_metrics.get(); }
};

}} // namespace qubitcoin::monitoring

#endif // QUBITCOIN_MONITORING_COLLECTORS_H 