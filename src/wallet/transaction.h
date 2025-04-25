 // src/wallet/transaction.h

#ifndef QUBITCOIN_WALLET_TRANSACTION_H
#define QUBITCOIN_WALLET_TRANSACTION_H
// src/wallet/transaction.hpp
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <variant>
#include <vector>

#include <serialize.h>
#include <uint256.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>

namespace qubitcoin {
namespace wallet {

//— Transaction confirmation in a block
struct TxStateConfirmed {
    uint256 block_hash;
    int     height;
    int     index;
    TxStateConfirmed(const uint256& h, int ht, int idx) noexcept
      : block_hash(h), height(ht), index(idx) {}
};

//— In mempool
struct TxStateInMempool {};

//— Conflicted with a block
struct TxStateConflicted {
    uint256 block_hash;
    int     height;
    TxStateConflicted(const uint256& h, int ht) noexcept
      : block_hash(h), height(ht) {}
};

//— Not in mempool or block (maybe abandoned)
struct TxStateInactive {
    bool abandoned;
    explicit TxStateInactive(bool a=false) noexcept : abandoned(a) {}
};

//— Unrecognized legacy state
struct TxStateUnknown {
    uint256 block_hash;
    int     index;
    TxStateUnknown(const uint256& h, int i) noexcept
      : block_hash(h), index(i) {}
};

//— All possible states
using TxState = std::variant<
    TxStateConfirmed,
    TxStateInMempool,
    TxStateConflicted,
    TxStateInactive,
    TxStateUnknown
>;

//— Subset used during sync
using SyncState = std::variant<
    TxStateConfirmed,
    TxStateInMempool,
    TxStateInactive
>;

//— Serialize helpers for legacy compatibility
static inline TxState interpretSerialized(const TxStateUnknown& u) {
    if (u.block_hash == uint256::ZERO && u.index == 0) {
        return TxStateInactive{};
    }
    if (u.block_hash == uint256::ZERO && u.index == -1) {
        return TxStateInactive{true};
    }
    if (u.index >= 0) {
        return TxStateConfirmed{u.block_hash, -1, u.index};
    }
    if (u.index == -1) {
        return TxStateConflicted{u.block_hash, -1};
    }
    return u;
}
static inline uint256 serializedBlockHash(const TxState& s) {
    return std::visit([](auto&& st) -> uint256 {
        using T = std::decay_t<decltype(st)>;
        if constexpr(std::is_same_v<T, TxStateConfirmed> || std::is_same_v<T, TxStateConflicted>)
            return st.block_hash;
        else if constexpr(std::is_same_v<T, TxStateInactive>)
            return st.abandoned ? uint256::ONE : uint256::ZERO;
        else
            return uint256::ZERO;
    }, s);
}
static inline int serializedIndex(const TxState& s) {
    return std::visit([](auto&& st) -> int {
        using T = std::decay_t<decltype(st)>;
        if constexpr(std::is_same_v<T, TxStateConfirmed>)
            return st.index;
        else if constexpr(std::is_same_v<T, TxStateInactive>)
            return st.abandoned ? -1 : 0;
        else if constexpr(std::is_same_v<T, TxStateConflicted>)
            return -1;
        else
            return 0;
    }, s);
}

//— A wallet transaction
class CWalletTx {
public:
    CTransactionRef       tx;
    TxState               state;
    std::map<std::string,std::string> mapValue;
    std::vector<std::pair<std::string,std::string>> orderForm;
    uint32_t              timeReceived{0};
    uint32_t              timeSmart{0};
    bool                  fromMe{false};
    int64_t               orderPos{-1};
    std::set<uint256>     conflicts;

    explicit CWalletTx(CTransactionRef t, TxState s) noexcept
      : tx(std::move(t)), state(std::move(s)) {}

    void markDirty() noexcept {
        // clear any cached balances (if implemented)
    }

    bool isConfirmed() const noexcept {
        return std::holds_alternative<TxStateConfirmed>(state);
    }
    bool isInMempool() const noexcept {
        return std::holds_alternative<TxStateInMempool>(state);
    }
    bool isConflicted() const noexcept {
        return std::holds_alternative<TxStateConflicted>(state)
            || !conflicts.empty();
    }
    bool isAbandoned() const noexcept {
        if (auto p = std::get_if<TxStateInactive>(&state)) return p->abandoned;
        return false;
    }

    uint256 getHash() const noexcept { return tx->GetHash(); }

    template<typename Stream>
    void Serialize(Stream& s) const {
        auto mapCopy = mapValue;
        mapCopy["n"] = orderPos>=0 ? std::to_string(orderPos) : "0";
        mapCopy["timesmart"] = std::to_string(timeSmart);
        std::vector<uint8_t> dummy1, dummy2;
        bool dummyBool = false;
        s << TX_WITH_WITNESS(tx)
          << serializedBlockHash(state)
          << dummy1
          << serializedIndex(state)
          << dummy2
          << mapCopy
          << orderForm
          << timeReceived
          << fromMe
          << dummyBool;
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        uint256 blkHash;
        int     idx;
        std::vector<uint256> dummyHashes;
        std::vector<CMerkleTx> dummyPrev;
        bool    dummyBool;
        s >> TX_WITH_WITNESS(tx)
          >> blkHash
          >> dummyHashes
          >> idx
          >> dummyPrev
          >> mapValue
          >> orderForm
          >> timeReceived
          >> fromMe
          >> dummyBool;
        state = interpretSerialized({blkHash, idx});
        orderPos   = std::stoll(mapValue["n"]);
        timeSmart  = std::stoul(mapValue["timesmart"]);
        mapValue.erase("n");
        mapValue.erase("timesmart");
    }
};

} // namespace wallet
} // namespace qubitcoin

#endif // QUBITCOIN_WALLET_TRANSACTION_H
