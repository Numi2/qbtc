//   2024 
//    
//  

#ifndef BITCOIN_INTERFACES_TYPES_H
#define BITCOIN_INTERFACES_TYPES_H

#include <uint256.h>

namespace interfaces {

//! Hash/height pair to help track and identify blocks.
struct BlockRef {
    uint256 hash;
    int height = -1;
};

} // namespace interfaces

#endif // BITCOIN_INTERFACES_TYPES_H
