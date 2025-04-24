//   2019-2021 
//    
//  

#include <node/coin.h>

#include <node/context.h>
#include <txmempool.h>
#include <validation.h>

namespace node {
void FindCoins(const NodeContext& node, std::map<COutPoint, Coin>& coins)
{
    assert(node.mempool);
    assert(node.chainman);
    LOCK2(cs_main, node.mempool->cs);
    CCoinsViewCache& chain_view = node.chainman->ActiveChainstate().CoinsTip();
    CCoinsViewMemPool mempool_view(&chain_view, *node.mempool);
    for (auto& [outpoint, coin] : coins) {
        if (auto c{mempool_view.GetCoin(outpoint)}) {
            coin = std::move(*c);
        } else {
            coin.Clear(); // Either the coin is not in the CCoinsViewCache or is spent
        }
    }
}
} // namespace node
