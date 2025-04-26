// src/monitoring/tests/metrics_tests.cpp
// Tests for Prometheus monitoring metrics

#include <boost/test/unit_test.hpp>
#include <monitoring/metrics.h>

using namespace qubitcoin::monitoring;

BOOST_AUTO_TEST_SUITE(metrics_tests)

BOOST_AUTO_TEST_CASE(metrics_registry_singleton)
{
    // Verify that we get the same registry instance
    MetricsRegistry& registry1 = MetricsRegistry::Instance();
    MetricsRegistry& registry2 = MetricsRegistry::Instance();
    
    // Check that both references point to the same object
    BOOST_CHECK_EQUAL(&registry1, &registry2);
}

BOOST_AUTO_TEST_CASE(counter_basic_operations)
{
    auto& registry = MetricsRegistry::Instance();
    
    // Create a test counter
    Counter* counter = registry.CreateCounter("test_counter", "Test counter for unit tests");
    BOOST_REQUIRE(counter != nullptr);
    
    // Initial value should be zero
    BOOST_CHECK_EQUAL(counter->Get(), 0);
    
    // Increment operations
    counter->Inc();
    BOOST_CHECK_EQUAL(counter->Get(), 1);
    
    counter->Add(5);
    BOOST_CHECK_EQUAL(counter->Get(), 6);
    
    // Format output and check it follows Prometheus format
    std::string output = counter->Format();
    BOOST_CHECK(output.find("# HELP test_counter Test counter for unit tests") != std::string::npos);
    BOOST_CHECK(output.find("# TYPE test_counter counter") != std::string::npos);
    BOOST_CHECK(output.find("test_counter 6") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(gauge_basic_operations)
{
    auto& registry = MetricsRegistry::Instance();
    
    // Create a test gauge
    Gauge* gauge = registry.CreateGauge("test_gauge", "Test gauge for unit tests");
    BOOST_REQUIRE(gauge != nullptr);
    
    // Initial value should be zero
    BOOST_CHECK_EQUAL(gauge->Get(), 0.0);
    
    // Set operations
    gauge->Set(10.5);
    BOOST_CHECK_EQUAL(gauge->Get(), 10.5);
    
    // Increment/decrement
    gauge->Inc();
    BOOST_CHECK_EQUAL(gauge->Get(), 11.5);
    
    gauge->Dec();
    BOOST_CHECK_EQUAL(gauge->Get(), 10.5);
    
    // Add/subtract
    gauge->Add(2.5);
    BOOST_CHECK_EQUAL(gauge->Get(), 13.0);
    
    gauge->Sub(3.0);
    BOOST_CHECK_EQUAL(gauge->Get(), 10.0);
}

BOOST_AUTO_TEST_CASE(histogram_basic_operations)
{
    auto& registry = MetricsRegistry::Instance();
    
    // Create a histogram with buckets [1, 5, 10, 50, 100, +Inf]
    std::vector<double> buckets = {1, 5, 10, 50, 100};
    Histogram* hist = registry.CreateHistogram("test_histogram", 
                                              "Test histogram for unit tests",
                                              buckets);
    BOOST_REQUIRE(hist != nullptr);
    
    // Observe some values
    hist->Observe(0.5);  // Should go in 1 bucket
    hist->Observe(3.0);  // Should go in 5 bucket
    hist->Observe(7.5);  // Should go in 10 bucket
    hist->Observe(20.0); // Should go in 50 bucket
    hist->Observe(75.0); // Should go in 100 bucket
    hist->Observe(150.0); // Should go in +Inf bucket
    
    // Check the formatted output has all buckets and correct count
    std::string output = hist->Format();
    BOOST_CHECK(output.find("# HELP test_histogram Test histogram for unit tests") != std::string::npos);
    BOOST_CHECK(output.find("# TYPE test_histogram histogram") != std::string::npos);
    
    // Check bucket counts and sum
    BOOST_CHECK(output.find("test_histogram_bucket{le=\"1\"} 1") != std::string::npos);
    BOOST_CHECK(output.find("test_histogram_bucket{le=\"5\"} 2") != std::string::npos);
    BOOST_CHECK(output.find("test_histogram_bucket{le=\"10\"} 3") != std::string::npos);
    BOOST_CHECK(output.find("test_histogram_bucket{le=\"50\"} 4") != std::string::npos);
    BOOST_CHECK(output.find("test_histogram_bucket{le=\"100\"} 5") != std::string::npos);
    BOOST_CHECK(output.find("test_histogram_bucket{le=\"+Inf\"} 6") != std::string::npos);
    
    // Check sum (0.5 + 3.0 + 7.5 + 20.0 + 75.0 + 150.0 = 256.0)
    BOOST_CHECK(output.find("test_histogram_sum 256") != std::string::npos);
    BOOST_CHECK(output.find("test_histogram_count 6") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END() 