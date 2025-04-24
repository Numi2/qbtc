//   2019-2022 
//    
//  

#include <node/context.h>

#include <addrman.h>
#include <banman.h>
#include <interfaces/chain.h>
#include <interfaces/mining.h>
#include <kernel/context.h>
#include <key.h>
#include <net.h>
#include <net_processing.h>
#include <netgroup.h>
#include <node/kernel_notifications.h>
#include <node/warnings.h>
#include <policy/fees.h>
#include <scheduler.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>

namespace node {
NodeContext::NodeContext() = default;
NodeContext::~NodeContext() = default;
} // namespace node
