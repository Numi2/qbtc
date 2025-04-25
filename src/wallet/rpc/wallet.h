// src/wallet/rpc/wallet.h

#ifndef QUBITCOIN_WALLET_RPC_WALLET_H
#define QUBITCOIN_WALLET_RPC_WALLET_H

#include <span.h>

class CRPCCommand;

namespace wallet {
std::span<const CRPCCommand> GetWalletRPCCommands();
} // namespace wallet

#endif // QUBITCOIN_WALLET_RPC_WALLET_H
