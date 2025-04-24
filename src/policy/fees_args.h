//   2022 
//    
//  

#ifndef BITCOIN_POLICY_FEES_ARGS_H
#define BITCOIN_POLICY_FEES_ARGS_H

#include <util/fs.h>

class ArgsManager;

/** @return The fee estimates data file path. */
fs::path FeeestPath(const ArgsManager& argsman);

#endif // BITCOIN_POLICY_FEES_ARGS_H
