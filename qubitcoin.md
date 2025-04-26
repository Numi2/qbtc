# QuBitcoin: A Quantum-Resistant Blockchain

QuBitcoin Tech Stack & Decisions:
Signature Algorithm: CRYSTALS-Dilithium (replaces ECDSA)
Hash Algorithm: BLAKE3 (replaces SHA256/SHA256d)
Consensus: Proof-of-Work based on BLAKE3
Launch: New Genesis Block
Address Format: Bech32m format (qbc1p...) using BLAKE3 hashes of Dilithium public keys
HD Wallets: Dilithium/BLAKE3-compatible derivation scheme
Block/Transaction Structure: Designed to accommodate Dilithium signature sizes (~3.3kB) and use BLAKE3 hashes, with parameters like `MAX_BLOCK_WEIGHT` set accordingly (e.g., 111M weight units)
Network Protocol: Unique `PROTOCOL_VERSION`, service bit (`NODE_PQ`), distinct magic bytes

**Abstract:** The emergence of practical quantum computation invalidates the security model underpinning many existing cryptocurrencies, particularly those reliant on elliptic curve cryptography (like Bitcoin). Shor's algorithm renders ECC demonstrably obsolete for securing ownership. Grover's algorithm significantly weakens the security guarantees of hash-based Proof-of-Work algorithms like SHA256 against quantum adversaries. A purely peer-to-peer system of electronic cash intended for enduring value requires cryptographic foundations resistant to these known threats. QuBitcoin is presented as a *new* blockchain, inspired by Bitcoin's core principles but built from the ground up using cryptographic primitives resistant to known quantum attacks. By utilizing CRYSTALS-Dilithium for signatures and BLAKE3 for hashing from its genesis, QuBitcoin aims to provide a secure foundation for decentralized digital scarcity in the quantum era. This document specifies the rationale and technical design of this new blockchain.

## 1. Introduction

The original Bitcoin protocol was a landmark achievement, demonstrating peer-to-peer electronic cash secured by computational proof. Its security assumptions, however, were predicated on the limitations of *classical* computation. The reliance on ECDSA and SHA256 was sound only within that paradigm.

The advent of fault-tolerant quantum computers fundamentally alters the security landscape. Shor's algorithm [1] definitively breaks ECDSA, dissolving the cryptographic guarantee of ownership it provides. Grover's algorithm [2] significantly reduces the effective security of hash functions like SHA256 against quantum pre-image attacks, making its assumed security margin insufficient for a global value system facing such threats. Ignoring this cryptographic reality is incompatible with building a secure, long-term store of value.

QuBitcoin is therefore designed as a *new* blockchain, built from genesis with quantum-resistant cryptography as its foundation. It learns from the vulnerabilities of earlier systems and implements robust solutions from the outset. While inspired by Bitcoin's UTXO model, Proof-of-Work consensus, and sound money principles, it does not inherit its legacy cryptography or blockchain history. The objective is to launch a secure chain using primitives resilient against adversaries wielding the power of quantum mechanics. This requires:

1.  **Post-Quantum Signatures:** Utilizing a standardized, lattice-based scheme (CRYSTALS-Dilithium) whose hardness assumptions remain robust against all known algorithms, classical or quantum, from the very first block.
2.  **Strengthened Hashing:** Employing BLAKE3 for all hashing operations, providing a comfortable security margin (\(2^{128}\) post-Grover) along with superior performance and architectural elegance.
3.  **Genesis Launch:** Establishing the blockchain with a new genesis block, initiating a completely independent history secured by the chosen post-quantum primitives.

The work specified herein is the foundation for a decentralized value transfer system designed for the realities of quantum computation.

## 2. Cryptographic Primitives

The core of QuBitcoin lies in its use of cryptographic primitives grounded in hardness assumptions resilient to quantum computation from its inception.

### 2.1 Post-Quantum Signatures: CRYSTALS-Dilithium

**Rationale:** Cryptosystems relying on ECDSA over secp256k1 are fundamentally broken by Shor's algorithm. Building a new secure system requires avoiding this vulnerability entirely.

**Solution:** QuBitcoin utilizes CRYSTALS-Dilithium [3], specifically Dilithium3, for all digital signatures. This choice is based on its selection by NIST [4] after rigorous public scrutiny, reflecting confidence in the hardness of underlying lattice problems against quantum attack.

**Implementation:**
*   **Key Representation:** `CKey`, `CPubKey`, and `CKeyID` are designed to handle Dilithium primitives via a robust cryptographic library (e.g., OpenSSL >= 3.2 EVP).
*   **Signature Verification:** Script opcodes (`OP_CHECKSIG`, etc.) and the `SignatureChecker` infrastructure are designed to exclusively validate Dilithium signatures, enforcing the security standard from genesis.
*   **Signature Size:** The larger size of Dilithium signatures (~3.3 kB for Dilithium3) is the necessary physical cost of achieving verifiable post-quantum security. Consensus rules (`MAX_SIGLEN`, `MAX_SCRIPT_ELEMENT_SIZE`) are set accordingly from the start.

### 2.2 Hash Function: BLAKE3

**Rationale:** While SHA256 retains some resistance, Grover's algorithm halves its effective security against quantum pre-image searches to \(2^{128}\). Relying on this margin is imprudent when superior alternatives exist. Furthermore, the complexity of SHA256d (used in Bitcoin to mitigate length-extension weaknesses) is unnecessary with modern designs like BLAKE3.

**Solution:** QuBitcoin utilizes BLAKE3-256 [5] for all consensus-critical hashing operations.

**Benefits:**
*   **Security:** BLAKE3 provides a robust \(2^{128}\) security margin against Grover's attack. Its design is based on sound, modern cryptographic principles.
*   **Performance:** BLAKE3's inherent parallelism offers substantial performance gains on contemporary hardware.
*   **Simplicity:** Using a single, state-of-the-art hash function provides architectural coherence.

**Implementation:**
*   **Block Hashing:** `CBlockHeader::GetHash` computes a single BLAKE3 hash for the Proof-of-Work process.
*   **Transaction Hashing:** `txid` and `wtxid` computations use BLAKE3.
*   **Merkle Trees:** Tree construction employs BLAKE3.
*   **Signature Hashing:** `SignatureHash` utilizes BLAKE3.
*   **Other Uses:** All protocol-level hashing (filters, etc.) uses BLAKE3 for consistency and robust security.

## 3. Consensus Rules

QuBitcoin implements a set of consensus rules based on its chosen cryptographic primitives and design goals, established from the genesis block.

### 3.1 Block Structure and Validation Parameters

*   **Signature Size Limits:** Consensus rules such as `MAX_SCRIPT_ELEMENT_SIZE` and `MAX_SIGLEN` are defined to accommodate Dilithium signature sizes.
*   **Block Weight:** The `MAX_BLOCK_WEIGHT` parameter (e.g., 111M weight units) is set to handle the data requirements of post-quantum signatures and desired transaction throughput.

### 3.2 Proof-of-Work

*   **Algorithm:** PoW is defined as verifying `BLAKE3(BlockHeader) <= target`. This directly links energy expenditure to resistance against known computational attacks using the chosen hash function.
*   **Difficulty Target (`powLimit`):** The genesis block defines the initial `powLimit` value appropriate for the BLAKE3 algorithm.
*   **Retargeting:** A difficulty adjustment mechanism (e.g., recalculating every 2016 blocks similar to Bitcoin) is implemented to maintain a consistent block target time (e.g., 10 minutes) as network hash rate changes.

## 4. Network Protocol

QuBitcoin employs a distinct network protocol to ensure nodes connect only to peers enforcing the correct consensus rules.
*   **Protocol Version:** A unique `PROTOCOL_VERSION` identifies QuBitcoin peers.
*   **Service Bit:** A dedicated service bit (`NODE_PQ`) allows nodes to advertise support for the QuBitcoin protocol.
*   **Message Payloads:** Hash-based identifiers within network messages (e.g., in compact blocks, filter headers) utilize BLAKE3.
*   **Network Magic:** Distinct magic bytes prevent connections between QuBitcoin nodes and nodes of other blockchains (like Bitcoin), avoiding network partitioning and ensuring consensus integrity.

## 5. Address Format and Wallet Infrastructure

New user-facing elements are required for interacting with the QuBitcoin blockchain.

### 5.1 New Address Format

A unique address format provides unambiguous identification of QuBitcoin outputs.
*   **Encoding:** Bech32m [6] is used for efficiency and error detection.
*   **Witness Version:** Version 1 (`0x01`) signals a modern script format designed for post-quantum security.
*   **Payload:** `BLAKE3-256(DilithiumPublicKey)` constitutes the witness program – a commitment to ownership secured by lattice cryptography.
*   **Identifier:** Addresses starting with `qbc1p...` uniquely identify QuBitcoin destinations.

### 5.2 HD Wallets and Descriptors

*   **Derivation:** As standard BIP32 relies on ECDSA, a new Dilithium-compatible HD derivation scheme (e.g., PRF-based, using BLAKE3) is required for secure key management.
*   **Descriptors:** Output script descriptors must explicitly support the new key types (Dilithium) and derivation paths, enabling robust wallet interoperability.
*   **Wallet Management:** Wallet software must be built to handle Dilithium key generation, secure storage (encryption), and transaction signing using the new primitives and address formats specified by QuBitcoin.

## 6. Future Outlook: Establishing Quantum-Resistant Value

QuBitcoin launches into a world increasingly aware of the threat quantum computing poses to classical cryptography. Its existence provides a necessary alternative for users seeking long-term security for digital assets.

The trajectory for a quantum-resistant blockchain like QuBitcoin involves:

1.  **Demonstrating Viability:** Establishing a stable network, attracting miners to secure the BLAKE3 PoW chain, and fostering development of compatible wallets and infrastructure are the initial priorities.
2.  **Building Trust and Adoption:** As awareness of quantum threats grows, users, institutions, and developers seeking demonstrable, future-proof security may turn to systems built on post-quantum cryptography like QuBitcoin. Its value proposition rests on providing security that legacy systems, without significant upgrades, cannot guarantee.
3.  **Coexistence and Differentiation:** QuBitcoin will likely coexist with other blockchains. Its differentiator is its inherent resistance to known quantum attacks from genesis. Market adoption will depend on the perceived urgency of the quantum threat and the demonstrated reliability and utility of the QuBitcoin network.
4.  **Ecosystem Growth:** Long-term success requires building a robust ecosystem around QuBitcoin, including exchanges, payment processors, and applications that leverage its unique security properties.

QuBitcoin aims to be a foundational layer for secure digital value in an era where quantum computation is a reality. Its success will be driven by its technical soundness, the growing need for quantum-resistant solutions, and the community that builds upon it. Security against the *known* future, not just the past, is the only sound foundation for enduring digital scarcity.

## 7. Conclusion

The quantum computational era demands new cryptographic foundations for decentralized systems. QuBitcoin is designed from the ground up as a response to the proven inadequacy of ECDSA and the weakened security of SHA256 against future quantum adversaries. By utilizing CRYSTALS-Dilithium and BLAKE3 from its genesis block within a framework inspired by Bitcoin's core principles, QuBitcoin aims to provide a robust and enduring platform for peer-to-peer electronic cash.

This specification outlines the blueprint for this new blockchain. Its successful realization demands rigorous implementation, exhaustive testing, independent audits, and coordinated network launch and growth. The development of a healthy BLAKE3 mining ecosystem will be crucial for securing the network's value. QuBitcoin is engineered to offer secure, decentralized digital value, resilient against the cryptographic challenges defined by the laws of physics themselves.

## 8. References

[1] Shor, P.W. (1997). Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer. *SIAM Journal on Computing*, 26(5), 1484-1509.
[2] Grover, L.K. (1996). A fast quantum mechanical algorithm for database search. *Proceedings of the 28th Annual ACM Symposium on Theory of Computing*, 212-219.
[3] Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., & Stehlé, D. (2018). CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme. *IACR Transactions on Cryptographic Hardware and Embedded Systems*, 2018(1), 238-268.
[4] National Institute of Standards and Technology (NIST). (2022). *Post-Quantum Cryptography Standardization*. [https://csrc.nist.gov/Projects/post-quantum-cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
[5] O'Connor, J., Aumasson, J.P., Neves, S., & Wilcox-O'Hearn, Z. (2019). BLAKE3: One Function, Fast Everywhere. [https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
[6] Wuille, P., & Segwit Address Format contributors. (2019). *Bech32m format for v1-v16 witness addresses*. BIP-0350. [https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) 