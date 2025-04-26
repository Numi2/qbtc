 # Qubitcoin Chain Parameters

This document summarizes the core `CChainParams` settings for Qubitcoin networks, as defined in `src/kernel/chainparams.cpp`.
Use `-chain=qubit` for mainnet and `-chain=qubit-test` for testnet (aliases for "main" and "test").

 ---
 ## Mainnet (ChainType::MAIN)

 ### Network
 - Message start (magic): 0x51 0x42 0x49 0x54 (ASCII "QBIT")
 - Default P2P port: 8334
 - Prune-after height: 100000

 ### Consensus
 - Subsidy halving interval: 210000 blocks
 - Proof-of-Work limit (powLimit): 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
 - Target timespan: 14 days (1209600 seconds)
 - Target spacing: 10 minutes (600 seconds)
 - Minimum chain work: 0x0000000000000000000000000000000000000000B1F3B93B65B16D035A82BE84
 - Default assume-valid: 00000000000000000001b658dd1120e82e66d2790811f89ede9742ada3ed6d77

 ### Genesis Block
 - Timestamp: 1713878400 (2025-04-23 00:00:00 UTC)
 - Nonce: 0
 - Bits: 0x1d00ffff (difficulty 1)
 - Version: 1
 - Reward: 50 QB
 - Coinbase scriptPubKey: `04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f OP_CHECKSIG`

 ### Address Prefixes
 - P2PKH (PUBKEY_ADDRESS): 58 → addresses start with 'Q'
 - P2SH (SCRIPT_ADDRESS): 5  → addresses start with '3'
 - WIF (SECRET_KEY): 128
 - ExtPubKey (qpub): 0x0488B21E
 - ExtPrivKey (qprv): 0x0488ADE4
 - Bech32 HRP: `qbc`

 ### DNS Seeds
- siqn.org

 ---
 ## Testnet (ChainType::TESTNET)

 ### Network
 - Message start (magic): 0x51 0x42 0x49 0x54 (ASCII "QBIT")
 - Default P2P port: 18334
 - Prune-after height: 1000

 ### Consensus
 - Subsidy halving interval: 210000 blocks
 - Proof-of-Work limit (powLimit): same as mainnet
 - Target timespan: 14 days
 - Target spacing: 10 minutes
 - Minimum chain work: 0x0000000000000000000000000000000000000000000015F5E0C9F13455B0EB17
 - Default assume-valid: 00000000000003FC7967410BA2D0A8A8D50DAEDC318D43E8BAF1A9782C236A57

 ### Genesis Block
 - Same parameters as mainnet (genesis hash and Merkle root are identical)

 ### Address Prefixes
 - P2PKH: 111 → addresses start with 'm' or 'n'
 - P2SH: 196 → addresses start with '2'
 - WIF: 239
 - ExtPubKey (qtpub): 0x053587CF
 - ExtPrivKey (qtprv): 0x05358394
 - Bech32 HRP: `tq`

 ### DNS Seeds
 - testnet-seed1.siqn.org
 - testnet-seed2.siqn.org