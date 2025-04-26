#include <boost/test/unit_test.hpp>

#include <config.h>
#include <metrics/metrics.h>
#include <metrics/metric_service.h>
#include <util/system.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

// Helper class for testing metrics
class MetricsTestHelper {
public:
    static void ResetMetricsSystem() {
        MetricService::GetInstance().Reset();
    }
    
    static std::vector<Metric> GetAllMetrics() {
        return MetricService::GetInstance().GetAllMetrics();
    }
    
    static Metric* FindMetricByName(const std::string& name) {
        auto metrics = GetAllMetrics();
        for (auto& metric : metrics) {
            if (metric.GetName() == name) {
                return new Metric(metric);
            }
        }
        return nullptr;
    }
};

BOOST_AUTO_TEST_SUITE(monitoring_metrics_tests)

BOOST_AUTO_TEST_CASE(metrics_initialization)
{
    // Reset the metrics system before testing
    MetricsTestHelper::ResetMetricsSystem();
    
    // Initialize the metrics system
    bool initialized = InitializeMetricsSystem();
    BOOST_CHECK(initialized);
    
    // Verify basic system metrics are created
    auto metrics = MetricsTestHelper::GetAllMetrics();
    BOOST_CHECK(!metrics.empty());
    
    // Look for some expected system metrics
    Metric* uptime = MetricsTestHelper::FindMetricByName("system.uptime");
    BOOST_CHECK(uptime != nullptr);
    if (uptime) {
        BOOST_CHECK_GE(uptime->GetValue(), 0);
        delete uptime;
    }
}

BOOST_AUTO_TEST_CASE(counter_metrics)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Create a counter metric
    CounterMetric counter("test.counter", "Test counter");
    
    // Initial value should be 0
    BOOST_CHECK_EQUAL(counter.GetValue(), 0);
    
    // Increment the counter
    counter.Increment();
    BOOST_CHECK_EQUAL(counter.GetValue(), 1);
    
    // Increment by a specific amount
    counter.Increment(5);
    BOOST_CHECK_EQUAL(counter.GetValue(), 6);
    
    // Reset the counter
    counter.Reset();
    BOOST_CHECK_EQUAL(counter.GetValue(), 0);
    
    // Find the metric in the global registry
    Metric* found = MetricsTestHelper::FindMetricByName("test.counter");
    BOOST_CHECK(found != nullptr);
    if (found) {
        BOOST_CHECK_EQUAL(found->GetValue(), 0);
        delete found;
    }
}

BOOST_AUTO_TEST_CASE(gauge_metrics)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Create a gauge metric
    GaugeMetric gauge("test.gauge", "Test gauge");
    
    // Initial value should be 0
    BOOST_CHECK_EQUAL(gauge.GetValue(), 0);
    
    // Set the gauge value
    gauge.Set(42);
    BOOST_CHECK_EQUAL(gauge.GetValue(), 42);
    
    // Decrease the gauge
    gauge.Decrease(12);
    BOOST_CHECK_EQUAL(gauge.GetValue(), 30);
    
    // Increase the gauge
    gauge.Increase(5);
    BOOST_CHECK_EQUAL(gauge.GetValue(), 35);
    
    // Find the metric in the global registry
    Metric* found = MetricsTestHelper::FindMetricByName("test.gauge");
    BOOST_CHECK(found != nullptr);
    if (found) {
        BOOST_CHECK_EQUAL(found->GetValue(), 35);
        delete found;
    }
}

BOOST_AUTO_TEST_CASE(histogram_metrics)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Create a histogram metric
    HistogramMetric histogram("test.histogram", "Test histogram");
    
    // Add some values
    histogram.Observe(5);
    histogram.Observe(10);
    histogram.Observe(15);
    histogram.Observe(20);
    histogram.Observe(25);
    
    // Check count and sum
    BOOST_CHECK_EQUAL(histogram.GetCount(), 5);
    BOOST_CHECK_EQUAL(histogram.GetSum(), 75);
    
    // Find the metric in the global registry
    Metric* found = MetricsTestHelper::FindMetricByName("test.histogram");
    BOOST_CHECK(found != nullptr);
    if (found) {
        BOOST_CHECK_EQUAL(found->GetType(), MetricType::HISTOGRAM);
        delete found;
    }
}

BOOST_AUTO_TEST_CASE(timer_metrics)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Create a timer metric
    TimerMetric timer("test.timer", "Test timer");
    
    // Start the timer
    timer.Start();
    
    // Simulate some work
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Stop the timer
    timer.Stop();
    
    // Check the recorded duration
    BOOST_CHECK_GT(timer.GetDurationMs(), 0);
    BOOST_CHECK_GE(timer.GetDurationMs(), 50);
    
    // Find the metric in the global registry
    Metric* found = MetricsTestHelper::FindMetricByName("test.timer");
    BOOST_CHECK(found != nullptr);
    if (found) {
        BOOST_CHECK_EQUAL(found->GetType(), MetricType::TIMER);
        delete found;
    }
}

BOOST_AUTO_TEST_CASE(metrics_labeling)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Create a labeled counter
    CounterMetric counter("test.labeled_counter", "Test labeled counter");
    counter.AddLabel("category", "test");
    counter.AddLabel("env", "test_env");
    
    // Increment the counter
    counter.Increment();
    BOOST_CHECK_EQUAL(counter.GetValue(), 1);
    
    // Check labels
    auto labels = counter.GetLabels();
    BOOST_CHECK_EQUAL(labels.size(), 2);
    BOOST_CHECK_EQUAL(labels["category"], "test");
    BOOST_CHECK_EQUAL(labels["env"], "test_env");
}

BOOST_AUTO_TEST_CASE(metrics_serialization)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Create different types of metrics
    CounterMetric counter("test.counter", "Test counter");
    counter.Increment(42);
    
    GaugeMetric gauge("test.gauge", "Test gauge");
    gauge.Set(123);
    
    // Get JSON representation
    std::string json = MetricService::GetInstance().GetMetricsAsJson();
    
    // Basic validation of JSON format
    BOOST_CHECK(json.find("test.counter") != std::string::npos);
    BOOST_CHECK(json.find("test.gauge") != std::string::npos);
    BOOST_CHECK(json.find("42") != std::string::npos);
    BOOST_CHECK(json.find("123") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(metrics_reporting)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Enable metrics reporting
    gArgs.ForceSetArg("-enablemetrics", "1");
    gArgs.ForceSetArg("-metricsendpoint", "http://localhost:8888/metrics");
    
    // Initialize metrics with reporting
    bool initialized = InitializeMetricsSystem();
    BOOST_CHECK(initialized);
    
    // Check reporting is enabled
    BOOST_CHECK(IsMetricsReportingEnabled());
}

BOOST_AUTO_TEST_CASE(bitcoin_specific_metrics)
{
    // Reset the metrics system
    MetricsTestHelper::ResetMetricsSystem();
    
    // Initialize Bitcoin-specific metrics
    InitializeBitcoinMetrics();
    
    // Check for expected Bitcoin metrics
    Metric* peers = MetricsTestHelper::FindMetricByName("bitcoin.peers.connected");
    BOOST_CHECK(peers != nullptr);
    if (peers) delete peers;
    
    Metric* blocks = MetricsTestHelper::FindMetricByName("bitcoin.blocks.count");
    BOOST_CHECK(blocks != nullptr);
    if (blocks) delete blocks;
    
    Metric* mempool = MetricsTestHelper::FindMetricByName("bitcoin.mempool.size");
    BOOST_CHECK(mempool != nullptr);
    if (mempool) delete mempool;
}

BOOST_AUTO_TEST_SUITE_END() 