// wallet/test/net_qs_tests.cpp
// Tests for quantum-safe P2P service flags and protocol

#include <boost/test/unit_test.hpp>
#include <protocol.h>               // serviceFlagsToStr, ServiceFlags
#include <kernel/chainparams.h>     // SeedsServiceFlags

BOOST_AUTO_TEST_SUITE(net_qs_tests)

BOOST_AUTO_TEST_CASE(seed_service_flags_include_pq)
{
    // SeedsServiceFlags should include NODE_NETWORK and NODE_PQ
    ServiceFlags flags = SeedsServiceFlags();
    // The numeric value is (1<<0) | (1<<12) = 4097
    BOOST_CHECK_EQUAL(uint64_t(flags), (1ULL << 0) | (1ULL << 12));
    // Human-readable strings
    auto v = serviceFlagsToStr(uint64_t(flags));
    BOOST_CHECK(std::find(v.begin(), v.end(), "NODE_NETWORK") != v.end());
    BOOST_CHECK(std::find(v.begin(), v.end(), "NODE_PQ") != v.end());
}

BOOST_AUTO_TEST_SUITE_END()