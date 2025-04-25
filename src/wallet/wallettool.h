// src/wallet/wallettool.h

#ifndef QUBITCOIN_WALLET_WALLETTOOL_H
#define QUBITCOIN_WALLET_WALLETTOOL_H

#include <string>

class ArgsManager;

namespace wallet {
namespace WalletTool {

bool ExecuteWalletToolFunc(const ArgsManager& args, const std::string& command);

} // namespace WalletTool
} // namespace wallet

#endif // QUBITCOIN_WALLET_WALLETTOOL_H
