//   2022 
//    
//  

#ifndef BITCOIN_KERNEL_CHECKS_H
#define BITCOIN_KERNEL_CHECKS_H

#include <util/result.h>

namespace kernel {

struct Context;

/**
 *  Ensure a usable environment with all necessary library support.
 */
[[nodiscard]] util::Result<void> SanityChecks(const Context&);
} // namespace kernel

#endif // BITCOIN_KERNEL_CHECKS_H
