//     
//    
//  

#ifndef BITCOIN_WALLET_TEST_WALLET_TEST_FIXTURE_H
#define BITCOIN_WALLET_TEST_WALLET_TEST_FIXTURE_H

#include <test/util/setup_common.h>

#include <interfaces/chain.h>
#include <interfaces/wallet.h>
#include <node/context.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <wallet/wallet.h>

#include <memory>

namespace wallet {
/** Testing setup and teardown for wallet.
 */
struct WalletTestingSetup : public TestingSetup {
    explicit WalletTestingSetup(const ChainType chainType = ChainType::MAIN);
    ~WalletTestingSetup();

    std::unique_ptr<interfaces::WalletLoader> m_wallet_loader;
    CWallet m_wallet;
    std::unique_ptr<interfaces::Handler> m_chain_notifications_handler;
};
} // namespace wallet

#endif // BITCOIN_WALLET_TEST_WALLET_TEST_FIXTURE_H
