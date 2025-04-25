## Qubitcoin Deployment Guide

This document outlines the steps to launch and maintain a thriving Qubitcoin network from genesis to full production.

### 1. Network Parameters
- Magic bytes: `0x51 0x42 0x49 0x54` (ASCII “QBIT”)
- Default ports:
  - Mainnet: **8334**
  - Testnet: **18334**
  - Testnet4: **48334**
- Bech32m human-readable prefixes (HRP):
  - Mainnet: `qb`
  - Testnet: `tq`
  - Testnet4: `tq4`

### 2. Genesis & Chain Configuration
1. Verify genesis block parameters in `kernel/chainparams.cpp`:
   - Timestamp: `1713878400` (2025-04-23)
   - Bits: `0x1d00ffff`
   - Nonce: `0` (or as locked in code)
2. Confirm consensus rules:
   - HD derivation set to m/86'/<coin_type>'/0'/<chain>'/<index>'
   - Dilithium3 signature limits reflected in `MAX_BLOCK_WEIGHT=111000000` and `MAX_BLOCK_SIGOPS_COST=800000`
   - Bloom filters use BLAKE3 (implement via `blockfilter.cpp`).

### 2.X Quantum-Safe Enhancements
- Hashing: BLAKE3-256 replaces SHA256 for all hashing (blocks, transactions, UTXO DB keys).
- Block header extended (in `primitives/block.h`):
  - New fields `headerPubKey` (Dilithium3 public key) and `headerSig` (Dilithium3 signature) serialized immediately after `nNonce`.
  - Blocks are signed by the mining node using Dilithium3; verification enforced in `validation.cpp`.
- BlockIndex database schema change:
  - `CDiskBlockIndex::DUMMY_VERSION` bumped to `260000`, forcing a one-time full reindex (`-reindex` or implicit on start).
  - Legacy Bitcoin (`bitcoind`) block-index formats are incompatible.
- Transaction scripts use Dilithium3 only; legacy ECDSA has been removed.
- New address format: Bech32m `qbc1p...` for Dilithium3 public keys (see `OutputType::P2PQ`).
- RPC `pqc` namespace commands (`rpc/pqccmds.cpp`): generate key, sign message, verify signature.
- Testing:
  - Unit tests for quantum-safe features are in `wallet/test/*_qs_tests.cpp`.
  - Run `ctest -R qs` to execute all quantum-safe tests.

### 3. Seed Node Deployment
1. Provision at least three geographically distributed, high-uptime servers.
2. Install Qubitcoin (`qubitcoind`) on each.
3. In `qubitcoin.conf`, add:
   ```ini
   listen=1
   server=1
   bind=<public-ip>
   port=8334
   rpcport=8332
   txindex=1
   zmqpubrawblock=tcp://0.0.0.0:28332
   zmqpubrawtx=tcp://0.0.0.0:28333
   ```
4. Start `qubitcoind` and ensure it syncs to genesis.
5. Open TCP port **8334** and monitor uptime and peer count.

### 4. DNS Seed Configuration
1. Register DNS names:
   - `seed1.qubitcoin.org`, `seed2.qubitcoin.org`, etc.
2. Point each seed name to your seed node IPs (A/AAAA records).
3. In `kernel/chainparams.cpp`, confirm seed list matches your DNS names.
4. Monitor seed resolution and connectivity across the network.

### 5. Release & Versioning
1. Bump `CLIENT_VERSION_MAJOR`/`MINOR`/`BUILD` in `clientversion.h` to **1.0.0-qb**.
2. Tag the Git repository:
   ```bash
   git tag -a v1.0.0-qb -m "Qubitcoin v1.0.0-qb launch"
   git push origin v1.0.0-qb
   ```
3. Build release artifacts (Linux tarball, Windows MSI, Homebrew/Cargo formulas).
4. Publish checksums (SHA256) and BLAKE3 manifests for all binaries.

### 6. Community & Node Onboarding
1. Publish an **Upgrade Guide**:
   - Explain new ports (8334), magic, HRPs.
   - Dump then import old wallet seeds (via `dumpwallet` → `importwallet`).
2. Provide **Quickstart** docs:
   ```bash
   qubitcoind -daemon \
     -port=8334 \
     -txindex=1 \
     -datadir=/path/to/data
   qubitcoin-cli getblockchaininfo
   ```
3. Share monitoring dashboards (Prometheus, Grafana) and alert rules.

### 7. Monitoring & Maintenance
- Enable `-blocknotify` and `-walletnotify` hooks for external indexing services.
- Collect metrics via RPC (`getnetworkinfo`, `getpeerinfo`, `getmempoolinfo`).
- Regularly prune old block files if disk space is tight (`-prune=<n>`).

### 8. Security & Best Practices
- Always run over TLS for RPC communications (`rpcssl=1`).
- Use hardware wallets with PSBT workflows for large funds.
- Rotate RPC credentials and rotate seed node keys periodically.

---
_With these steps, your Qubitcoin network will be fully deployed, secure, and ready to grow. Welcome to the quantum-safe future!_