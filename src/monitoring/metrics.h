#ifndef QUBITCOIN_MONITORING_METRICS_H
#define QUBITCOIN_MONITORING_METRICS_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

/**
 * Prometheus monitoring system integration for QuBitcoin.
 * This class provides metrics collection and HTTP exposure via Prometheus format.
 */
namespace qubitcoin {
namespace monitoring {

enum class MetricType {
    COUNTER,     // Monotonically increasing value
    GAUGE,       // Value that can go up and down
    HISTOGRAM    // Statistical distribution of values
};

class MetricBase {
protected:
    std::string name;
    std::string help;
    MetricType type;
    std::unordered_map<std::string, std::string> labels;

public:
    MetricBase(const std::string& name, const std::string& help, MetricType type)
        : name(name), help(help), type(type) {}
    
    virtual ~MetricBase() = default;
    
    const std::string& GetName() const { return name; }
    const std::string& GetHelp() const { return help; }
    MetricType GetType() const { return type; }
    
    void AddLabel(const std::string& key, const std::string& value) {
        labels[key] = value;
    }
    
    // Format this metric for Prometheus exposition
    virtual std::string Format() const = 0;
};

class Counter : public MetricBase {
private:
    std::atomic<int64_t> value;

public:
    Counter(const std::string& name, const std::string& help)
        : MetricBase(name, help, MetricType::COUNTER), value(0) {}
    
    void Inc() { value++; }
    void Add(int64_t v) { value += v; }
    int64_t Get() const { return value.load(); }
    
    std::string Format() const override;
};

class Gauge : public MetricBase {
private:
    std::atomic<double> value;

public:
    Gauge(const std::string& name, const std::string& help)
        : MetricBase(name, help, MetricType::GAUGE), value(0) {}
    
    void Set(double v) { value = v; }
    void Inc() { value++; }
    void Dec() { value--; }
    void Add(double v) { value += v; }
    void Sub(double v) { value -= v; }
    double Get() const { return value.load(); }
    
    std::string Format() const override;
};

class Histogram : public MetricBase {
private:
    std::vector<double> buckets;
    std::vector<std::atomic<uint64_t>> bucket_counts;
    std::atomic<double> sum;
    std::atomic<uint64_t> count;
    mutable std::mutex mutex;

public:
    Histogram(const std::string& name, const std::string& help, const std::vector<double>& buckets)
        : MetricBase(name, help, MetricType::HISTOGRAM), buckets(buckets), 
          bucket_counts(buckets.size() + 1), sum(0), count(0) {}
    
    void Observe(double value);
    std::string Format() const override;
};

/**
 * Registry for all Prometheus metrics in the system
 */
class MetricsRegistry {
private:
    std::vector<std::shared_ptr<MetricBase>> metrics;
    mutable std::mutex mutex;
    
    // Singleton instance
    static MetricsRegistry* instance;
    
    // HTTP server thread
    std::unique_ptr<std::thread> server_thread;
    bool running;
    int port;

public:
    MetricsRegistry() : running(false), port(9642) {}
    ~MetricsRegistry();
    
    static MetricsRegistry& Instance();
    
    std::shared_ptr<Counter> CreateCounter(const std::string& name, const std::string& help);
    std::shared_ptr<Gauge> CreateGauge(const std::string& name, const std::string& help);
    std::shared_ptr<Histogram> CreateHistogram(
        const std::string& name, 
        const std::string& help, 
        const std::vector<double>& buckets);
    
    // Register an existing metric
    void Register(std::shared_ptr<MetricBase> metric);
    
    // Start the HTTP server on the given port
    bool Start(int port = 9642);
    
    // Stop the HTTP server
    void Stop();
    
    // Generate the complete metrics output in Prometheus format
    std::string GetMetricsOutput() const;
};

}} // namespace qubitcoin::monitoring

#endif // QUBITCOIN_MONITORING_METRICS_H 