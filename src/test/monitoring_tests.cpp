#include <boost/test/unit_test.hpp>

#include <monitoring/monitoring.h>
#include <monitoring/metrics.h>
#include <util/system.h>
#include <validation.h>
#include <chainparams.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <utiltime.h>
#include <thread>
#include <random>
#include <util/time.h>
#include <key.h>

#include <vector>
#include <string>

#include <monitoring/monitoring_counter.h>
#include <monitoring/monitoring_gauge.h>
#include <monitoring/monitoring_histogram.h>
#include <monitoring/monitoring_percentiles.h>
#include <monitoring/monitoring_registry.h>

BOOST_AUTO_TEST_SUITE(monitoring_tests)

// Test basic metric recording and retrieval
BOOST_AUTO_TEST_CASE(monitoring_basic_metrics)
{
    // Initialize monitoring system
    monitoring::MonitoringSystem& monitor = monitoring::MonitoringSystem::GetInstance();
    
    // Clear any existing metrics to ensure clean test state
    monitor.Reset();
    
    // Record a simple counter metric
    const std::string metricName = "test_counter";
    monitor.RecordMetric(metricName, 1);
    monitor.RecordMetric(metricName, 1);
    monitor.RecordMetric(metricName, 1);
    
    // Verify the counter value
    monitoring::Metric metric = monitor.GetMetric(metricName);
    BOOST_CHECK_EQUAL(metric.name, metricName);
    BOOST_CHECK_EQUAL(metric.value, 3);
    BOOST_CHECK_EQUAL(metric.type, monitoring::MetricType::COUNTER);
    
    // Test gauge metric
    const std::string gaugeMetric = "test_gauge";
    monitor.RecordGauge(gaugeMetric, 10);
    monitor.RecordGauge(gaugeMetric, 20);  // This should overwrite the previous value
    
    metric = monitor.GetMetric(gaugeMetric);
    BOOST_CHECK_EQUAL(metric.name, gaugeMetric);
    BOOST_CHECK_EQUAL(metric.value, 20);
    BOOST_CHECK_EQUAL(metric.type, monitoring::MetricType::GAUGE);
    
    // Test histogram metric
    const std::string histogramMetric = "test_histogram";
    monitor.RecordHistogram(histogramMetric, 5);
    monitor.RecordHistogram(histogramMetric, 10);
    monitor.RecordHistogram(histogramMetric, 15);
    
    metric = monitor.GetMetric(histogramMetric);
    BOOST_CHECK_EQUAL(metric.name, histogramMetric);
    BOOST_CHECK_EQUAL(metric.type, monitoring::MetricType::HISTOGRAM);
    
    // Check histogram statistics
    monitoring::HistogramStats stats = monitor.GetHistogramStats(histogramMetric);
    BOOST_CHECK_EQUAL(stats.count, 3);
    BOOST_CHECK_EQUAL(stats.min, 5);
    BOOST_CHECK_EQUAL(stats.max, 15);
    BOOST_CHECK_CLOSE(stats.mean, 10.0, 0.001);  // Use BOOST_CHECK_CLOSE for floating point comparisons
}

// Test transaction monitoring metrics
BOOST_AUTO_TEST_CASE(transaction_monitoring)
{
    // Initialize monitoring system
    monitoring::MonitoringSystem& monitor = monitoring::MonitoringSystem::GetInstance();
    monitor.Reset();
    
    // Create test transactions
    CMutableTransaction tx1;
    tx1.vin.resize(1);
    tx1.vout.resize(1);
    tx1.vout[0].nValue = 50 * COIN;
    
    CMutableTransaction tx2;
    tx2.vin.resize(2);
    tx2.vout.resize(2);
    tx2.vout[0].nValue = 25 * COIN;
    tx2.vout[1].nValue = 25 * COIN;
    
    // Record transaction metrics
    monitor.RecordTransaction(MakeTransactionRef(tx1));
    monitor.RecordTransaction(MakeTransactionRef(tx2));
    
    // Check transaction count
    monitoring::Metric txCountMetric = monitor.GetMetric("transactions.count");
    BOOST_CHECK_EQUAL(txCountMetric.value, 2);
    
    // Check input count
    monitoring::Metric txInputMetric = monitor.GetMetric("transactions.inputs");
    BOOST_CHECK_EQUAL(txInputMetric.value, 3);  // 1 from tx1 + 2 from tx2
    
    // Check output count
    monitoring::Metric txOutputMetric = monitor.GetMetric("transactions.outputs");
    BOOST_CHECK_EQUAL(txOutputMetric.value, 3);  // 1 from tx1 + 2 from tx2
    
    // Check value transferred
    monitoring::Metric valueMetric = monitor.GetMetric("transactions.value");
    BOOST_CHECK_EQUAL(valueMetric.value, 100 * COIN);  // 50 from tx1 + 50 from tx2
}

// Test performance metrics recording
BOOST_AUTO_TEST_CASE(performance_monitoring)
{
    // Initialize monitoring system
    monitoring::MonitoringSystem& monitor = monitoring::MonitoringSystem::GetInstance();
    monitor.Reset();
    
    // Create a performance timer for a block validation operation
    {
        monitoring::PerformanceTimer timer("block.validation");
        
        // Simulate work by sleeping
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Check that the timer recorded a duration
    monitoring::Metric blockValidationMetric = monitor.GetMetric("performance.block.validation");
    BOOST_CHECK(blockValidationMetric.value > 0);
    
    // Create multiple timers for transaction validation
    for (int i = 0; i < 5; i++) {
        monitoring::PerformanceTimer timer("tx.validation");
        
        // Simulate work with random duration
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(5, 15);
        std::this_thread::sleep_for(std::chrono::milliseconds(distrib(gen)));
    }
    
    // Check transaction validation performance histogram
    monitoring::Metric txValidationMetric = monitor.GetMetric("performance.tx.validation");
    BOOST_CHECK_EQUAL(txValidationMetric.type, monitoring::MetricType::HISTOGRAM);
    
    monitoring::HistogramStats txStats = monitor.GetHistogramStats("performance.tx.validation");
    BOOST_CHECK_EQUAL(txStats.count, 5);
    BOOST_CHECK(txStats.min >= 5);
    BOOST_CHECK(txStats.max <= 15);
}

// Test alert threshold monitoring
BOOST_AUTO_TEST_CASE(monitoring_alerts)
{
    // Initialize monitoring system
    monitoring::MonitoringSystem& monitor = monitoring::MonitoringSystem::GetInstance();
    monitor.Reset();
    
    // Set up an alert threshold for a test metric
    const std::string metricName = "test.alert.metric";
    monitor.SetAlertThreshold(metricName, 10, monitoring::AlertPriority::WARNING);
    monitor.SetAlertThreshold(metricName, 20, monitoring::AlertPriority::CRITICAL);
    
    // Record values below threshold (should not trigger alert)
    monitor.RecordGauge(metricName, 5);
    BOOST_CHECK_EQUAL(monitor.GetActiveAlerts().size(), 0);
    
    // Record value above warning threshold
    monitor.RecordGauge(metricName, 15);
    auto alerts = monitor.GetActiveAlerts();
    BOOST_CHECK_EQUAL(alerts.size(), 1);
    BOOST_CHECK_EQUAL(alerts[0].priority, monitoring::AlertPriority::WARNING);
    
    // Record value above critical threshold
    monitor.RecordGauge(metricName, 25);
    alerts = monitor.GetActiveAlerts();
    BOOST_CHECK_EQUAL(alerts.size(), 1);
    BOOST_CHECK_EQUAL(alerts[0].priority, monitoring::AlertPriority::CRITICAL);
    
    // Reset the value below thresholds
    monitor.RecordGauge(metricName, 5);
    BOOST_CHECK_EQUAL(monitor.GetActiveAlerts().size(), 0);
}

// Test concurrent metric recording
BOOST_AUTO_TEST_CASE(concurrent_monitoring)
{
    // Initialize monitoring system
    monitoring::MonitoringSystem& monitor = monitoring::MonitoringSystem::GetInstance();
    monitor.Reset();
    
    // Create multiple threads that record metrics simultaneously
    const int NUM_THREADS = 10;
    const int RECORDS_PER_THREAD = 1000;
    std::vector<std::thread> threads;
    
    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([i, &monitor, RECORDS_PER_THREAD]() {
            std::string metricName = "concurrent.test." + std::to_string(i);
            for (int j = 0; j < RECORDS_PER_THREAD; j++) {
                monitor.RecordMetric(metricName, 1);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify that each thread's counter has the correct value
    for (int i = 0; i < NUM_THREADS; i++) {
        std::string metricName = "concurrent.test." + std::to_string(i);
        monitoring::Metric metric = monitor.GetMetric(metricName);
        BOOST_CHECK_EQUAL(metric.value, RECORDS_PER_THREAD);
    }
}

// Test system resource monitoring
BOOST_AUTO_TEST_CASE(system_resource_monitoring)
{
    // Initialize monitoring system
    monitoring::MonitoringSystem& monitor = monitoring::MonitoringSystem::GetInstance();
    monitor.Reset();
    
    // Trigger system resource monitoring update
    monitor.UpdateSystemMetrics();
    
    // Check that memory usage metrics are recorded
    monitoring::Metric memoryMetric = monitor.GetMetric("system.memory.used");
    BOOST_CHECK(memoryMetric.value > 0);
    
    // Check CPU usage metrics
    monitoring::Metric cpuMetric = monitor.GetMetric("system.cpu.usage");
    BOOST_CHECK(cpuMetric.value >= 0);
    
    // Check disk usage metrics
    monitoring::Metric diskMetric = monitor.GetMetric("system.disk.usage");
    BOOST_CHECK(diskMetric.value > 0);
}

// Test network metrics
BOOST_AUTO_TEST_CASE(network_monitoring)
{
    // Initialize monitoring system
    monitoring::MonitoringSystem& monitor = monitoring::MonitoringSystem::GetInstance();
    monitor.Reset();
    
    // Simulate peer connections
    monitor.RecordMetric("network.peers.connected", 5);
    
    // Simulate network traffic
    monitor.RecordMetric("network.bytes.received", 1024);
    monitor.RecordMetric("network.bytes.sent", 2048);
    
    // Check peer count
    monitoring::Metric peerMetric = monitor.GetMetric("network.peers.connected");
    BOOST_CHECK_EQUAL(peerMetric.value, 5);
    
    // Check network traffic
    monitoring::Metric recvMetric = monitor.GetMetric("network.bytes.received");
    BOOST_CHECK_EQUAL(recvMetric.value, 1024);
    
    monitoring::Metric sentMetric = monitor.GetMetric("network.bytes.sent");
    BOOST_CHECK_EQUAL(sentMetric.value, 2048);
}

BOOST_AUTO_TEST_CASE(monitoring_init_test)
{
    MonitoringSystem monitor;
    BOOST_CHECK(monitor.Initialize());
    BOOST_CHECK(monitor.IsInitialized());
    
    // Check default values
    BOOST_CHECK_EQUAL(monitor.GetSystemStatus(), MONITORING_OK);
    BOOST_CHECK_EQUAL(monitor.GetErrorCount(), 0);
    
    // Cleanup
    monitor.Shutdown();
    BOOST_CHECK(!monitor.IsInitialized());
}

BOOST_AUTO_TEST_CASE(monitoring_metrics_test)
{
    MonitoringSystem monitor;
    BOOST_CHECK(monitor.Initialize());
    
    // Test adding metrics
    monitor.RecordMetric("test_metric_1", 100);
    monitor.RecordMetric("test_metric_2", 200);
    
    // Verify metrics
    BOOST_CHECK_EQUAL(monitor.GetMetricValue("test_metric_1"), 100);
    BOOST_CHECK_EQUAL(monitor.GetMetricValue("test_metric_2"), 200);
    
    // Test non-existent metric
    BOOST_CHECK_EQUAL(monitor.GetMetricValue("non_existent"), 0);
    
    // Test updating metrics
    monitor.RecordMetric("test_metric_1", 150);
    BOOST_CHECK_EQUAL(monitor.GetMetricValue("test_metric_1"), 150);
    
    // Cleanup
    monitor.Shutdown();
}

BOOST_AUTO_TEST_CASE(monitoring_error_handling_test)
{
    MonitoringSystem monitor;
    BOOST_CHECK(monitor.Initialize());
    
    // Test error logging
    monitor.LogError("Test error 1");
    BOOST_CHECK_EQUAL(monitor.GetErrorCount(), 1);
    
    monitor.LogError("Test error 2");
    BOOST_CHECK_EQUAL(monitor.GetErrorCount(), 2);
    
    // Test system status changes
    BOOST_CHECK_EQUAL(monitor.GetSystemStatus(), MONITORING_WARNING);
    
    // Simulate critical error
    for (int i = 0; i < 8; i++) {
        monitor.LogError("Critical error simulation");
    }
    
    // After 10 errors, system should be in critical state
    BOOST_CHECK_EQUAL(monitor.GetErrorCount(), 10);
    BOOST_CHECK_EQUAL(monitor.GetSystemStatus(), MONITORING_CRITICAL);
    
    // Test error clearing
    monitor.ClearErrors();
    BOOST_CHECK_EQUAL(monitor.GetErrorCount(), 0);
    BOOST_CHECK_EQUAL(monitor.GetSystemStatus(), MONITORING_OK);
    
    // Cleanup
    monitor.Shutdown();
}

BOOST_AUTO_TEST_CASE(monitoring_performance_metrics_test)
{
    MonitoringSystem monitor;
    BOOST_CHECK(monitor.Initialize());
    
    // Start tracking a performance metric
    monitor.StartPerformanceTimer("block_validation");
    
    // Simulate work with sleep
    MilliSleep(50);
    
    // End tracking
    int64_t duration = monitor.EndPerformanceTimer("block_validation");
    
    // Verify timing (should be at least 50ms, allowing some margin)
    BOOST_CHECK(duration >= 45);
    
    // Check stored performance metric
    BOOST_CHECK(monitor.GetPerformanceMetric("block_validation") >= 45);
    
    // Cleanup
    monitor.Shutdown();
}

BOOST_AUTO_TEST_CASE(monitoring_alert_system_test)
{
    MonitoringSystem monitor;
    BOOST_CHECK(monitor.Initialize());
    
    // Test alert generation
    monitor.SetAlertThreshold("test_metric", 100);
    monitor.RecordMetric("test_metric", 50);
    
    // Should not trigger alert
    BOOST_CHECK(!monitor.HasActiveAlerts());
    
    // Now exceed threshold
    monitor.RecordMetric("test_metric", 150);
    
    // Should trigger alert
    BOOST_CHECK(monitor.HasActiveAlerts());
    
    // Get active alerts
    std::vector<MonitoringAlert> alerts = monitor.GetActiveAlerts();
    BOOST_CHECK_EQUAL(alerts.size(), 1);
    
    if (!alerts.empty()) {
        BOOST_CHECK_EQUAL(alerts[0].metricName, "test_metric");
        BOOST_CHECK_EQUAL(alerts[0].currentValue, 150);
        BOOST_CHECK_EQUAL(alerts[0].thresholdValue, 100);
    }
    
    // Clear alerts
    monitor.ClearAlerts();
    BOOST_CHECK(!monitor.HasActiveAlerts());
    
    // Cleanup
    monitor.Shutdown();
}

// Helper class for testing metrics collection
class TestMetricsCollector : public IMetricsCollector {
public:
    struct MetricEntry {
        std::string name;
        std::string value;
        int64_t timestamp;
    };
    
    std::vector<MetricEntry> collectedMetrics;
    
    void RecordMetric(const std::string& name, const std::string& value, int64_t timestamp) override {
        collectedMetrics.push_back({name, value, timestamp});
    }
    
    void Reset() {
        collectedMetrics.clear();
    }
};

BOOST_AUTO_TEST_CASE(basic_metrics_collection)
{
    // Create a test metrics collector
    auto collector = std::make_shared<TestMetricsCollector>();
    
    // Create the monitoring system with our test collector
    MonitoringSystem monitoring(collector);
    
    // Record a metric
    int64_t timestamp = GetTimeMillis();
    monitoring.RecordMetric("test_metric", "100", timestamp);
    
    // Verify the metric was recorded
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 1);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].name, "test_metric");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "100");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].timestamp, timestamp);
    
    // Reset and test multiple metrics
    collector->Reset();
    
    // Record multiple metrics
    monitoring.RecordMetric("memory_usage", "1024", timestamp);
    monitoring.RecordMetric("cpu_usage", "50", timestamp + 100);
    monitoring.RecordMetric("network_connections", "25", timestamp + 200);
    
    // Verify all metrics were recorded
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 3);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].name, "memory_usage");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "1024");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[1].name, "cpu_usage");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[1].value, "50");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[2].name, "network_connections");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[2].value, "25");
}

BOOST_AUTO_TEST_CASE(performance_metrics)
{
    // Create a test metrics collector
    auto collector = std::make_shared<TestMetricsCollector>();
    
    // Create the monitoring system with our test collector
    MonitoringSystem monitoring(collector);
    
    // Test the performance metrics recorder
    {
        PerformanceMetric perfMetric(&monitoring, "transaction_validation");
        // Simulate work
        MilliSleep(10);
        perfMetric.Record();
    }
    
    // Verify at least one metric was recorded with the correct name
    BOOST_REQUIRE(!collector->collectedMetrics.empty());
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].name, "perf.transaction_validation");
    
    // Verify the value is a number representing milliseconds
    int64_t duration;
    BOOST_CHECK(ParseInt64(collector->collectedMetrics[0].value, &duration));
    BOOST_CHECK(duration >= 10); // Should be at least 10ms
    
    // Test nested performance metrics
    collector->Reset();
    
    {
        PerformanceMetric outerMetric(&monitoring, "block_processing");
        // Simulate some work
        MilliSleep(5);
        
        {
            PerformanceMetric innerMetric(&monitoring, "script_verification");
            // Simulate more intensive work
            MilliSleep(15);
            innerMetric.Record();
        }
        
        outerMetric.Record();
    }
    
    // Should have two metrics recorded
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 2);
    
    // Check the inner metric was recorded first
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].name, "perf.script_verification");
    int64_t innerDuration;
    BOOST_CHECK(ParseInt64(collector->collectedMetrics[0].value, &innerDuration));
    BOOST_CHECK(innerDuration >= 15);
    
    // Check the outer metric was recorded second
    BOOST_CHECK_EQUAL(collector->collectedMetrics[1].name, "perf.block_processing");
    int64_t outerDuration;
    BOOST_CHECK(ParseInt64(collector->collectedMetrics[1].value, &outerDuration));
    BOOST_CHECK(outerDuration >= 20); // At least 5ms + 15ms
}

BOOST_AUTO_TEST_CASE(counter_metrics)
{
    // Create a test metrics collector
    auto collector = std::make_shared<TestMetricsCollector>();
    
    // Create the monitoring system with our test collector
    MonitoringSystem monitoring(collector);
    
    // Create a counter metric
    CounterMetric txCounter(&monitoring, "transactions_validated");
    
    // Increment the counter
    txCounter.Increment();
    txCounter.Record();
    
    // Verify the metric was recorded
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 1);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].name, "counter.transactions_validated");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "1");
    
    // Increment multiple times
    collector->Reset();
    
    txCounter.Increment();
    txCounter.Increment();
    txCounter.Increment();
    txCounter.Record();
    
    // Verify the accumulated count
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 1);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "4"); // 1 + 3 = 4
    
    // Test increment by specific value
    collector->Reset();
    
    txCounter.IncrementBy(10);
    txCounter.Record();
    
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 1);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "14"); // 4 + 10 = 14
}

BOOST_AUTO_TEST_CASE(gauge_metrics)
{
    // Create a test metrics collector
    auto collector = std::make_shared<TestMetricsCollector>();
    
    // Create the monitoring system with our test collector
    MonitoringSystem monitoring(collector);
    
    // Create a gauge metric
    GaugeMetric memUsage(&monitoring, "memory_usage_mb");
    
    // Set the gauge value
    memUsage.Set(512);
    memUsage.Record();
    
    // Verify the metric was recorded
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 1);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].name, "gauge.memory_usage_mb");
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "512");
    
    // Update the gauge value
    collector->Reset();
    
    memUsage.Set(768);
    memUsage.Record();
    
    // Verify the updated value
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 1);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "768");
    
    // Test increment and decrement
    collector->Reset();
    
    memUsage.Increment();  // 769
    memUsage.Increment();  // 770
    memUsage.Decrement();  // 769
    memUsage.Record();
    
    BOOST_REQUIRE_EQUAL(collector->collectedMetrics.size(), 1);
    BOOST_CHECK_EQUAL(collector->collectedMetrics[0].value, "769");
}

BOOST_AUTO_TEST_CASE(histogram_metrics)
{
    // Create a test metrics collector
    auto collector = std::make_shared<TestMetricsCollector>();
    
    // Create the monitoring system with our test collector
    MonitoringSystem monitoring(collector);
    
    // Create a histogram metric
    HistogramMetric txSizeHistogram(&monitoring, "transaction_size");
    
    // Add values to the histogram
    txSizeHistogram.Observe(250);
    txSizeHistogram.Observe(300);
    txSizeHistogram.Observe(400);
    txSizeHistogram.Observe(250);
    txSizeHistogram.Record();
    
    // Verify the metrics recorded
    // A histogram typically records multiple values (count, sum, and possibly percentiles)
    BOOST_REQUIRE(collector->collectedMetrics.size() >= 2);
    
    // Find metrics by name
    bool foundCount = false;
    bool foundSum = false;
    
    for (const auto& metric : collector->collectedMetrics) {
        if (metric.name == "histogram.transaction_size.count") {
            BOOST_CHECK_EQUAL(metric.value, "4");
            foundCount = true;
        }
        else if (metric.name == "histogram.transaction_size.sum") {
            BOOST_CHECK_EQUAL(metric.value, "1200"); // 250 + 300 + 400 + 250 = 1200
            foundSum = true;
        }
    }
    
    BOOST_CHECK(foundCount);
    BOOST_CHECK(foundSum);
}

BOOST_AUTO_TEST_CASE(counter_test)
{
    // Create a monitoring registry
    monitoring::Registry registry("test_registry");
    
    // Create a counter
    auto counter = registry.AddCounter("test_counter", "Test counter description");
    
    // Initial value should be 0
    BOOST_CHECK_EQUAL(counter->Value(), 0);
    
    // Increment by 1
    counter->Increment();
    BOOST_CHECK_EQUAL(counter->Value(), 1);
    
    // Increment by 5
    counter->Increment(5);
    BOOST_CHECK_EQUAL(counter->Value(), 6);
    
    // Test that counter never decreases
    counter->Increment(-1);  // This should be ignored or clamped to 0
    BOOST_CHECK(counter->Value() >= 6);
    
    // Reset counter
    counter->Reset();
    BOOST_CHECK_EQUAL(counter->Value(), 0);
}

BOOST_AUTO_TEST_CASE(gauge_test)
{
    // Create a monitoring registry
    monitoring::Registry registry("test_registry");
    
    // Create a gauge
    auto gauge = registry.AddGauge("test_gauge", "Test gauge description");
    
    // Initial value should be 0
    BOOST_CHECK_EQUAL(gauge->Value(), 0);
    
    // Set to 10
    gauge->Set(10);
    BOOST_CHECK_EQUAL(gauge->Value(), 10);
    
    // Decrement by 3
    gauge->Decrement(3);
    BOOST_CHECK_EQUAL(gauge->Value(), 7);
    
    // Increment by 5
    gauge->Increment(5);
    BOOST_CHECK_EQUAL(gauge->Value(), 12);
    
    // Reset gauge
    gauge->Reset();
    BOOST_CHECK_EQUAL(gauge->Value(), 0);
}

BOOST_AUTO_TEST_CASE(histogram_test)
{
    // Create a monitoring registry
    monitoring::Registry registry("test_registry");
    
    // Create a histogram with specific buckets
    std::vector<double> buckets = {1, 5, 10, 50, 100, 500, 1000};
    auto histogram = registry.AddHistogram("test_histogram", "Test histogram description", buckets);
    
    // Add some observations
    histogram->Observe(3);
    histogram->Observe(7);
    histogram->Observe(15);
    histogram->Observe(90);
    histogram->Observe(200);
    
    // Test count
    BOOST_CHECK_EQUAL(histogram->Count(), 5);
    
    // Test sum
    BOOST_CHECK_EQUAL(histogram->Sum(), 315);
    
    // Test bucket counts
    BOOST_CHECK_EQUAL(histogram->BucketCount(0), 1);  // Values <= 1: should be 0
    BOOST_CHECK_EQUAL(histogram->BucketCount(1), 2);  // Values <= 5: should be 1
    BOOST_CHECK_EQUAL(histogram->BucketCount(2), 3);  // Values <= 10: should be 2
    BOOST_CHECK_EQUAL(histogram->BucketCount(3), 3);  // Values <= 50: should be 2
    BOOST_CHECK_EQUAL(histogram->BucketCount(4), 4);  // Values <= 100: should be 4
    BOOST_CHECK_EQUAL(histogram->BucketCount(5), 5);  // Values <= 500: should be 5
    BOOST_CHECK_EQUAL(histogram->BucketCount(6), 5);  // Values <= 1000: should be 5
    
    // Reset histogram
    histogram->Reset();
    BOOST_CHECK_EQUAL(histogram->Count(), 0);
    BOOST_CHECK_EQUAL(histogram->Sum(), 0);
}

BOOST_AUTO_TEST_CASE(percentile_test)
{
    // Create a monitoring registry
    monitoring::Registry registry("test_registry");
    
    // Create percentiles tracker with specific quantiles
    std::vector<double> quantiles = {0.5, 0.9, 0.99};
    auto percentiles = registry.AddPercentiles("test_percentiles", "Test percentiles description", quantiles);
    
    // Add some observations
    for (int i = 1; i <= 100; i++) {
        percentiles->Observe(i);
    }
    
    // Check the count and sum
    BOOST_CHECK_EQUAL(percentiles->Count(), 100);
    BOOST_CHECK_EQUAL(percentiles->Sum(), 5050);  // Sum of 1 to 100
    
    // Check the quantiles with some tolerance
    double p50 = percentiles->Quantile(0);  // First quantile (50th percentile)
    double p90 = percentiles->Quantile(1);  // Second quantile (90th percentile)
    double p99 = percentiles->Quantile(2);  // Third quantile (99th percentile)
    
    BOOST_CHECK_CLOSE(p50, 50, 10);  // Within 10% of 50
    BOOST_CHECK_CLOSE(p90, 90, 10);  // Within 10% of 90
    BOOST_CHECK_CLOSE(p99, 99, 10);  // Within 10% of 99
    
    // Reset percentiles
    percentiles->Reset();
    BOOST_CHECK_EQUAL(percentiles->Count(), 0);
    BOOST_CHECK_EQUAL(percentiles->Sum(), 0);
}

BOOST_AUTO_TEST_CASE(registry_test)
{
    // Create a monitoring registry
    monitoring::Registry registry("test_registry");
    
    // Add metrics
    auto counter1 = registry.AddCounter("counter1", "First counter");
    auto counter2 = registry.AddCounter("counter2", "Second counter");
    auto gauge = registry.AddGauge("gauge", "Test gauge");
    
    // Set some values
    counter1->Increment(5);
    counter2->Increment(10);
    gauge->Set(15);
    
    // Get metrics by name
    auto retrievedCounter1 = registry.GetCounter("counter1");
    auto retrievedCounter2 = registry.GetCounter("counter2");
    auto retrievedGauge = registry.GetGauge("gauge");
    
    // Verify they exist and have correct values
    BOOST_CHECK(retrievedCounter1 != nullptr);
    BOOST_CHECK(retrievedCounter2 != nullptr);
    BOOST_CHECK(retrievedGauge != nullptr);
    
    BOOST_CHECK_EQUAL(retrievedCounter1->Value(), 5);
    BOOST_CHECK_EQUAL(retrievedCounter2->Value(), 10);
    BOOST_CHECK_EQUAL(retrievedGauge->Value(), 15);
    
    // Try to get a non-existent metric
    auto nonExistentCounter = registry.GetCounter("non_existent");
    BOOST_CHECK(nonExistentCounter == nullptr);
    
    // Reset all metrics
    registry.ResetAllMetrics();
    
    BOOST_CHECK_EQUAL(retrievedCounter1->Value(), 0);
    BOOST_CHECK_EQUAL(retrievedCounter2->Value(), 0);
    BOOST_CHECK_EQUAL(retrievedGauge->Value(), 0);
}

BOOST_AUTO_TEST_CASE(performance_measurement)
{
    // Create a monitoring registry
    monitoring::Registry registry("perf_registry");
    
    // Create a histogram for measuring durations
    std::vector<double> buckets = {0.1, 0.5, 1, 5, 10, 50, 100, 500, 1000};
    auto histogram = registry.AddHistogram("operation_duration_ms", "Operation duration in milliseconds", buckets);
    
    // Perform a series of operations and measure their durations
    for (int i = 0; i < 100; i++) {
        int64_t startTime = GetTimeMillis();
        
        // Simulate some work
        std::this_thread::sleep_for(std::chrono::milliseconds(i % 10));
        
        int64_t duration = GetTimeMillis() - startTime;
        histogram->Observe(duration);
    }
    
    // Verify we have 100 observations
    BOOST_CHECK_EQUAL(histogram->Count(), 100);
    
    // Verify sum is reasonable (some positive number)
    BOOST_CHECK(histogram->Sum() > 0);
    
    // Check distribution across buckets
    for (size_t i = 0; i < buckets.size(); i++) {
        BOOST_TEST_MESSAGE("Bucket <= " << buckets[i] << "ms: " << histogram->BucketCount(i) << " items");
    }
}

BOOST_AUTO_TEST_CASE(concurrent_access)
{
    // Create a monitoring registry
    monitoring::Registry registry("concurrent_registry");
    
    // Create a counter
    auto counter = registry.AddCounter("concurrent_counter", "Counter for concurrent access test");
    
    // Spawn multiple threads to increment the counter
    const int numThreads = 10;
    const int incrementsPerThread = 1000;
    
    std::vector<std::thread> threads;
    
    for (int i = 0; i < numThreads; i++) {
        threads.emplace_back([&counter, incrementsPerThread]() {
            for (int j = 0; j < incrementsPerThread; j++) {
                counter->Increment();
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify the counter has been incremented correctly
    BOOST_CHECK_EQUAL(counter->Value(), numThreads * incrementsPerThread);
}

BOOST_AUTO_TEST_CASE(metric_labels)
{
    // Create a monitoring registry
    monitoring::Registry registry("labels_registry");
    
    // Create counters with different labels
    auto counter1 = registry.AddCounter("labeled_counter", "Counter with labels", {{"service", "rpc"}, {"method", "getblock"}});
    auto counter2 = registry.AddCounter("labeled_counter", "Counter with labels", {{"service", "rpc"}, {"method", "getblockcount"}});
    auto counter3 = registry.AddCounter("labeled_counter", "Counter with labels", {{"service", "p2p"}, {"method", "recv"}});
    
    // Increment counters
    counter1->Increment(5);
    counter2->Increment(10);
    counter3->Increment(15);
    
    // Verify counters have different values
    BOOST_CHECK_EQUAL(counter1->Value(), 5);
    BOOST_CHECK_EQUAL(counter2->Value(), 10);
    BOOST_CHECK_EQUAL(counter3->Value(), 15);
    
    // Get the set of all counters with the base name
    auto counters = registry.GetCountersWithName("labeled_counter");
    
    // Verify we have 3 counters
    BOOST_CHECK_EQUAL(counters.size(), 3);
    
    // Sum the values of all counters
    int64_t sum = 0;
    for (const auto& counter : counters) {
        sum += counter->Value();
    }
    
    BOOST_CHECK_EQUAL(sum, 30);
}

BOOST_AUTO_TEST_CASE(monitoring_registry_singleton)
{
    // Get the global registry
    auto& globalRegistry = monitoring::Registry::GetGlobalRegistry();
    
    // Create a counter
    auto counter = globalRegistry.AddCounter("global_counter", "Counter in global registry");
    
    // Increment the counter
    counter->Increment(42);
    
    // Verify the counter has the expected value
    BOOST_CHECK_EQUAL(counter->Value(), 42);
    
    // Get the same counter from the global registry again
    auto sameCounter = globalRegistry.GetCounter("global_counter");
    
    // Verify it's the same counter with the same value
    BOOST_CHECK(sameCounter != nullptr);
    BOOST_CHECK_EQUAL(sameCounter->Value(), 42);
}

BOOST_AUTO_TEST_SUITE_END() 