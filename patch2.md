PR 2b: Wallet DB & RPC for HD Dilithium keys

Summary:
- Persist a master PQC (post-quantum) seed in the wallet database under a new key `pqcseed`.
- Extend `CWallet` to store a 32-byte `m_pqc_seed` with thread-safe accessors:
  - `HasPqcSeed()`, `SetPqcSeed()`, `GetPqcSeed()`
- Implement `WalletBatch::WritePQCSeed` for atomic DB writes.
- Load the PQC seed during wallet startup in both legacy and descriptor loading paths:
  - Handlers added in `LoadLegacyWalletRecords()` and `LoadDescriptorWalletRecords()`.
- Add two RPC commands:
  - `setpqcseed`: Generates a fresh 32-byte seed (via `GetRandBytes`), stores it in the wallet.
    * Usage: `bitcoin-cli setpqcseed`
  - `getpqcseed`: Returns the hex-encoded seed (requires unlocked wallet and an existing seed).
    * Usage: `bitcoin-cli getpqcseed`
- Include necessary headers in `wallet.cpp`: `<random.h>`, `<util/strencodings.h>`.
- Register new RPCs in `GetWalletRPCCommands()`.

Files modified:
- `src/wallet/walletdb.h`, `walletdb.cpp`: Declare/write/read new DB key `pqcseed`.
- `src/wallet/wallet.h`, `wallet.cpp`: Add `m_pqc_seed`, accessors, seed persistence logic.
- `src/wallet/rpc/wallet.cpp`: Implement `setpqcseed`/`getpqcseed` RPC, RPC help text, examples.

Next steps (PR 2c):
- Implement `CPQCKeyStore` using BLAKE3-PRF to derive per-index Dilithium keypairs from the seed.
- Add `getnewpqcaddress` and `importpqcaddress` RPCs for on-demand address issuance/import.
- Wire up the new `qbc1p…` address type in `key_io` and the UI.