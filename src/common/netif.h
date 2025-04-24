//   2024 
//    
 

#ifndef BITCOIN_COMMON_NETIF_H
#define BITCOIN_COMMON_NETIF_H

#include <netaddress.h>

#include <optional>

//! Query the OS for the default gateway for `network`. This only makes sense for NET_IPV4 and NET_IPV6.
//! Returns std::nullopt if it cannot be found, or there is no support for this OS.
std::optional<CNetAddr> QueryDefaultGateway(Network network);

//! Return all local non-loopback IPv4 and IPv6 network addresses.
std::vector<CNetAddr> GetLocalAddresses();

#endif // BITCOIN_COMMON_NETIF_H
