// src/wallet/salvage.h

#ifndef QUBITCOIN_WALLET_SALVAGE_H
#define QUBITCOIN_WALLET_SALVAGE_H

#include <streams.h>
#include <util/fs.h>

class ArgsManager;
struct bilingual_str;

namespace wallet {
bool RecoverDatabaseFile(const ArgsManager& args, const fs::path& file_path, bilingual_str& error, std::vector<bilingual_str>& warnings);
} // namespace wallet

#endif // QUBITCOIN_WALLET_SALVAGE_H
