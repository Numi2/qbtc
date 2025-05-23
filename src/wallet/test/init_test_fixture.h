// src/wallet/test/init_test_fixture.h

#ifndef QUBITCOIN_WALLET_TEST_INIT_TEST_FIXTURE_H
#define QUBITCOIN_WALLET_TEST_INIT_TEST_FIXTURE_H

#include <interfaces/chain.h>
#include <interfaces/wallet.h>
#include <node/context.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>


namespace wallet {
struct InitWalletDirTestingSetup: public BasicTestingSetup {
    explicit InitWalletDirTestingSetup(const ChainType chain_type = ChainType::MAIN);
    ~InitWalletDirTestingSetup();
    void SetWalletDir(const fs::path& walletdir_path);

    fs::path m_datadir;
    fs::path m_cwd;
    std::map<std::string, fs::path> m_walletdir_path_cases;
    std::unique_ptr<interfaces::WalletLoader> m_wallet_loader;
};

#endif // QUBITCOIN_WALLET_TEST_INIT_TEST_FIXTURE_H
} // namespace wallet
