#include <monitoring/metrics.h>
#include <httpserver.h>
#include <logging.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <algorithm>
#include <sstream>

namespace qubitcoin {
namespace monitoring {

MetricsRegistry* MetricsRegistry::instance = nullptr;

std::string Counter::Format() const {
    std::ostringstream ss;
    ss << "# HELP " << name << " " << help << "\n";
    ss << "# TYPE " << name << " counter\n";
    
    ss << name;
    if (!labels.empty()) {
        ss << "{";
        bool first = true;
        for (const auto& label : labels) {
            if (!first) ss << ",";
            ss << label.first << "=\"" << label.second << "\"";
            first = false;
        }
        ss << "}";
    }
    ss << " " << value.load() << "\n";
    return ss.str();
}

std::string Gauge::Format() const {
    std::ostringstream ss;
    ss << "# HELP " << name << " " << help << "\n";
    ss << "# TYPE " << name << " gauge\n";
    
    ss << name;
    if (!labels.empty()) {
        ss << "{";
        bool first = true;
        for (const auto& label : labels) {
            if (!first) ss << ",";
            ss << label.first << "=\"" << label.second << "\"";
            first = false;
        }
        ss << "}";
    }
    ss << " " << value.load() << "\n";
    return ss.str();
}

void Histogram::Observe(double value) {
    std::lock_guard<std::mutex> lock(mutex);
    sum += value;
    count++;
    
    // Increment the appropriate bucket
    for (size_t i = 0; i < buckets.size(); i++) {
        if (value <= buckets[i]) {
            bucket_counts[i]++;
            return;
        }
    }
    
    // If we get here, increment the +Inf bucket
    bucket_counts[buckets.size()]++;
}

std::string Histogram::Format() const {
    std::ostringstream ss;
    ss << "# HELP " << name << " " << help << "\n";
    ss << "# TYPE " << name << " histogram\n";
    
    std::string label_str;
    if (!labels.empty()) {
        std::ostringstream label_ss;
        label_ss << "{";
        bool first = true;
        for (const auto& label : labels) {
            if (!first) label_ss << ",";
            label_ss << label.first << "=\"" << label.second << "\"";
            first = false;
        }
        label_ss << "}";
        label_str = label_ss.str();
    }
    
    std::lock_guard<std::mutex> lock(mutex);
    
    // Output bucket metrics
    uint64_t cumulative = 0;
    for (size_t i = 0; i < buckets.size(); i++) {
        cumulative += bucket_counts[i].load();
        ss << name << "_bucket{";
        if (!label_str.empty()) {
            ss << label_str.substr(1, label_str.size() - 2) << ",";
        }
        ss << "le=\"" << buckets[i] << "\"} " << cumulative << "\n";
    }
    
    // +Inf bucket
    cumulative += bucket_counts[buckets.size()].load();
    ss << name << "_bucket{";
    if (!label_str.empty()) {
        ss << label_str.substr(1, label_str.size() - 2) << ",";
    }
    ss << "le=\"+Inf\"} " << cumulative << "\n";
    
    // Sum and count
    ss << name << "_sum" << label_str << " " << sum.load() << "\n";
    ss << name << "_count" << label_str << " " << count.load() << "\n";
    
    return ss.str();
}

MetricsRegistry& MetricsRegistry::Instance() {
    if (!instance) {
        instance = new MetricsRegistry();
    }
    return *instance;
}

MetricsRegistry::~MetricsRegistry() {
    Stop();
}

std::shared_ptr<Counter> MetricsRegistry::CreateCounter(const std::string& name, const std::string& help) {
    std::lock_guard<std::mutex> lock(mutex);
    auto counter = std::make_shared<Counter>(name, help);
    metrics.push_back(counter);
    return counter;
}

std::shared_ptr<Gauge> MetricsRegistry::CreateGauge(const std::string& name, const std::string& help) {
    std::lock_guard<std::mutex> lock(mutex);
    auto gauge = std::make_shared<Gauge>(name, help);
    metrics.push_back(gauge);
    return gauge;
}

std::shared_ptr<Histogram> MetricsRegistry::CreateHistogram(
    const std::string& name, 
    const std::string& help, 
    const std::vector<double>& buckets) {
    std::lock_guard<std::mutex> lock(mutex);
    auto histogram = std::make_shared<Histogram>(name, help, buckets);
    metrics.push_back(histogram);
    return histogram;
}

void MetricsRegistry::Register(std::shared_ptr<MetricBase> metric) {
    std::lock_guard<std::mutex> lock(mutex);
    metrics.push_back(metric);
}

// Handler class for HTTP metrics endpoint
class MetricsHandler : public HTTPClosure {
private:
    bool ProcessRequest(HTTPRequest* req, const std::string& path) {
        std::string metrics = MetricsRegistry::Instance().GetMetricsOutput();
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, metrics);
        return true;
    }
};

bool MetricsRegistry::Start(int port) {
    if (running) return true;
    
    this->port = port;
    running = true;
    
    // Register the Prometheus metrics endpoint
    HTTPRequestHandler handler(HTTPClosure::Create(new MetricsHandler()));
    if (!RegisterHTTPHandler("/metrics", handler, false)) {
        LogPrintf("Failed to register metrics HTTP handler\n");
        return false;
    }
    
    LogPrintf("Prometheus metrics exporter started on port %d\n", port);
    return true;
}

void MetricsRegistry::Stop() {
    if (!running) return;
    
    running = false;
    if (server_thread) {
        server_thread->join();
        server_thread.reset();
    }
}

std::string MetricsRegistry::GetMetricsOutput() const {
    std::lock_guard<std::mutex> lock(mutex);
    std::ostringstream ss;
    
    for (const auto& metric : metrics) {
        ss << metric->Format() << "\n";
    }
    
    return ss.str();
}

}} // namespace qubitcoin::monitoring 