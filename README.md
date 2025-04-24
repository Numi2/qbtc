 Core Crypto & Build
     • Vendor and wire up BLAKE3 and OpenSSL-OQS (Dilithium) in CMake.
     • Remove any residual secp256k1/OpenSSL-SHA256 code paths.
     • Add unit & fuzz tests for:
       – CBlake3, CHash256/160, HashWriter, HMAC-BLAKE3 (BIP32)
       – pqc_keys: Generate/Import/Export, Sign/Verify

Consensus & PoW
     • Switch all PoW hashing to single-round BLAKE3.
     • Update difficulty adjustment (retarget) parameters around BLAKE3’s performance.
     • Flesh out CheckProofOfWorkImpl with BLAKE3.
     • Write unit tests for PoW / retarget logic.

Block Header Signing
     • Extend CBlockHeader to carry a Dilithium signature.
     • Miner: once BLAKE3 PoW passes, sign the header with your Dilithium key.
     • Validation: always enforce Dilithium signature + BLAKE3 PoW.
     • Write block-signing and verification tests.

 P2P & Network Protocol
     • Bump PROTOCOL_VERSION, choose unique magic bytes, add NODE_PQ service bit.
     • Serialize new header‐sig field in block, getheaders, headers messages.
     • Update inv/getdata to advertise BLAKE3 block IDs.
     • Test a two-node regtest network fully exchanging blocks/txs.

  Address Format & Scripts
     • Define “qbc1p…” Bech32m address: BLAKE3(pubkey) as witness program.
     • Reimplement scriptPubKey templates: P2WPKH-Dilithium, P2WSH.
     • Rewire script interpreter & CScriptCheck to use Dilithium Verify.
     • Adjust sigops cost for large PQ signatures; add tests for valid/invalid scripts.


  Wallet & HD Key Derivation
     • BIP-32-style tree using HMAC-BLAKE3: seed → Dilithium master key → child
    keypairs.
     • Define xprv/xpub (or simple hex) serialization for Dilithium keypaths.
     • Complete wallet/pqckeystore: encrypt, backup, import, export PQ private keys.
     • Wire all signing RPCs and PSBT flows to use pqc_keys.
     • Write functional wallet tests: derive address, fund, sign, broadcast.

    Genesis & Release
     • Craft a new genesis block: find a BLAKE3-valid nonce and include a valid
    Dilithium header-sig.
     • Bake in mainnet/testnet/regtest params (magic bytes, seeds, checkpoints).
     • CI & packaging: build with vendored libs, run full unit + functional + fuzz
    suites.
     • Docs & spec: BIP-style write-up for address/tx format, HD derivation, network
    magic, mining guide.
     • Publish a v1.0 “Qubitcoin Fresh-Start” release.

     I’ve stripped out the Bitcoin‐legacy protocol versioning and replaced it with a
    clean “v1” handshake, and added a new quantum‐safe P2P flag:

    • In src/node/protocol_version.h
      – PROTOCOL_VERSION, INIT_PROTO_VERSION, MIN_PEER_PROTO_VERSION, and all
    feature‐version constants are now set to 1.

    • In src/protocol.h
      – Added NODE_PQ service flag (1<<12) for quantum‐safe support
      – SeedsServiceFlags() now advertises NODE_NETWORK|NODE_PQ only

    This removes all old‐chain version gates and ensures a fresh P2P handshake on the
    Qubitcoin network.



    All right—since Qubitcoin is a fresh‐start chain (no legacy rules, no fork, no
    migration), let’s strip out any backward‐compatibility work and instead treat every
    rule as “from genesis.” Here’s a lean, 7-phase rollout:

    Phase 1: Core Crypto & Build
     • Vendor and wire up BLAKE3 and OpenSSL-OQS (Dilithium) in CMake.
     • Remove any residual secp256k1/OpenSSL-SHA256 code paths.
     • Add unit & fuzz tests for:
       – CBlake3, CHash256/160, HashWriter, HMAC-BLAKE3 (BIP32)
       – pqc_keys: Generate/Import/Export, Sign/Verify

    Phase 2: Consensus & PoW
     • Switch all PoW hashing to single-round BLAKE3.
     • Update difficulty adjustment (retarget) parameters around BLAKE3’s performance.
     • Flesh out CheckProofOfWorkImpl with BLAKE3.
     • Write unit tests for PoW / retarget logic.

    Phase 3: Block Header Signing
     • Extend CBlockHeader to carry a Dilithium signature.
     • Miner: once BLAKE3 PoW passes, sign the header with your Dilithium key.
     • Validation: always enforce Dilithium signature + BLAKE3 PoW.
     • Write block-signing and verification tests.

    Phase 4: P2P & Network Protocol
     • Bump PROTOCOL_VERSION, choose unique magic bytes, add NODE_PQ service bit.
     • Serialize new header‐sig field in block, getheaders, headers messages.
     • Update inv/getdata to advertise BLAKE3 block IDs.
     • Test a two-node regtest network fully exchanging blocks/txs.

    Phase 5: Address Format & Scripts
     • Define “qbc1p…” Bech32m address: BLAKE3(pubkey) as witness program.
     • Reimplement scriptPubKey templates: P2WPKH-Dilithium, P2WSH.
     • Rewire script interpreter & CScriptCheck to use Dilithium Verify.
     • Adjust sigops cost for large PQ signatures; add tests for valid/invalid scripts.


    Phase 6: Wallet & HD Key Derivation
     • BIP-32-style tree using HMAC-BLAKE3: seed → Dilithium master key → child
    keypairs.
     • Define xprv/xpub (or simple hex) serialization for Dilithium keypaths.
     • Complete wallet/pqckeystore: encrypt, backup, import, export PQ private keys.
     • Wire all signing RPCs and PSBT flows to use pqc_keys.
     • Write functional wallet tests: derive address, fund, sign, broadcast.

    Phase 7: Genesis & Release
     • Craft a new genesis block: find a BLAKE3-valid nonce and include a valid
    Dilithium header-sig.
     • Bake in mainnet/testnet/regtest params (magic bytes, seeds, checkpoints).
     • CI & packaging: build with vendored libs, run full unit + functional + fuzz
    suites.
     • Docs & spec: BIP-style write-up for address/tx format, HD derivation, network
    magic, mining guide.
     • Publish a v1.0 “Qubitcoin Fresh-Start” release.

  I’ve wired up full block‐header signing and verification:

    • primitives/block.h
      – CBlock now carries two new buffers: headerPubKey and headerSig.
      – Serialization of CBlock is updated to emit/consume them (wire format:
    headerPubKey, headerSig, then vtx).

    • rpc/mining.cpp
      – Added a new -pqcprivkey=<path> startup flag (via gArgs) to point at your
    Dilithium3 private‐key file.
      – On first use we load that file into an EVP_PKEY and extract the raw public key.
      – After we find a valid BLAKE3 PoW solution, we sign the 32‐byte header hash with
    SignDilithium3, and attach both pubkey and signature to the CBlock before
    broadcasting.

    • validation.cpp
      – After the usual PoW (and Signet) checks in CheckBlock(), we now reject any block
     missing a PQC signature or whose Dilithium signature doesn’t verify against the
    header hash.

    Next steps (tests):
    – Unit test for CDilithiumKey to exercise generate/sign/verify on a sample message.
    – Functional test: craft a minimal CBlock with dummy coinbase, signature it against
    a test key, run through CheckBlock() with fCheckPOW=false/fCheckMerkleRoot=false
    (but fCheckPOW=true so we hit signature‐verify path), assert acceptance.
