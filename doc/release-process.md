# QuBitcoin Release Process

This document outlines the process for creating and verifying official QuBitcoin releases.

## Table of Contents

1. [Release Preparation](#release-preparation)
2. [Release Signing](#release-signing)
3. [Building Release Binaries](#building-release-binaries)
4. [Verification Process](#verification-process)
5. [Publishing the Release](#publishing-the-release)
6. [Security Considerations](#security-considerations)

## Release Preparation

### 1. Finalize the code

- Freeze code by creating a release branch: `git checkout -b release/v1.x.x`
- Lock all dependencies and ensure reproducible builds
- Ensure all tests pass: `make check`
- Run extended test suite: `test/functional/test_runner.py --extended`
- Update version numbers in:
  - `configure.ac`
  - `src/clientversion.h`
  - `doc/release-notes/`

### 2. Create Release Notes

- Add a release notes document to `doc/release-notes/`
- Include all significant changes since the last release
- Note any breaking changes or important upgrade information
- Document any changes to RPC API
- List contributors

### 3. Final Code Review

- Conduct a security review with multiple developers
- Scan for potential vulnerabilities using static analyzers:
  ```
  ./contrib/devtools/security-check.py
  ```
- Review and sign off from at least two core developers

## Release Signing

QuBitcoin uses a multi-signature approach for release signing. The release manager and multiple core developers must sign the final release binaries and git tag.

### 1. Signing Keys

Our release signing keys are:

```
- Release Manager: <PGP KEY FINGERPRINT>
- Core Developer 1: <PGP KEY FINGERPRINT>
- Core Developer 2: <PGP KEY FINGERPRINT>
```

These keys are published on multiple key servers and verified through various channels.

### 2. Tag Signing

The release is tagged in git with a signed tag:

```bash
git tag -s v1.0.0 -m "QuBitcoin v1.0.0"
```

Multiple developers must verify and add their signatures:

```bash
git verify-tag v1.0.0
git tag -s v1.0.0-developer1 -m "Developer 1 signature for v1.0.0"
```

### 3. Post-Quantum Signature

In addition to traditional PGP signatures, we also sign the release with our Dilithium-III keys:

```bash
qubitcoin-cli signpqmessage "qp1developer" "SHA256(qubitcoin-1.0.0.tar.gz)=<hash>"
```

The post-quantum signatures are included in `docs.sig`.

## Building Release Binaries

QuBitcoin releases are built using [Gitian](https://github.com/bitcoin-core/gitian.sigs), allowing multiple developers to create deterministic builds independently.

### 1. Set up Gitian Builder

```bash
# Clone the gitian repository
git clone https://github.com/qubitcoin/gitian-builder.git
cd gitian-builder

# Set up the required VM
./bin/make-base-vm --suite focal --arch amd64
```

### 2. Build Binaries for All Platforms

```bash
# Linux 64-bit
./bin/gbuild --commit qubitcoin=v1.0.0 ../qubitcoin/contrib/gitian-descriptors/gitian-linux.yml
./bin/gsign --signer YOUR_KEY_ID --release v1.0.0-linux --destination ../gitian.sigs/ ../qubitcoin/contrib/gitian-descriptors/gitian-linux.yml

# Windows 64-bit
./bin/gbuild --commit qubitcoin=v1.0.0 ../qubitcoin/contrib/gitian-descriptors/gitian-win.yml
./bin/gsign --signer YOUR_KEY_ID --release v1.0.0-win --destination ../gitian.sigs/ ../qubitcoin/contrib/gitian-descriptors/gitian-win.yml

# macOS
./bin/gbuild --commit qubitcoin=v1.0.0 ../qubitcoin/contrib/gitian-descriptors/gitian-osx.yml
./bin/gsign --signer YOUR_KEY_ID --release v1.0.0-osx --destination ../gitian.sigs/ ../qubitcoin/contrib/gitian-descriptors/gitian-osx.yml
```

### 3. Verify Deterministic Builds

Multiple developers should independently build and compare their results. The SHA256 hashes of the resulting binaries must match exactly.

```bash
sha256sum build/out/qubitcoin-*
```

Developers' signatures should be submitted to the [gitian.sigs](https://github.com/qubitcoin/gitian.sigs) repository.

## Verification Process

### 1. Verify Binary Signatures

Users can verify the downloads using:

```bash
gpg --verify SHA256SUMS.asc
sha256sum -c SHA256SUMS
```

### 2. Verify Post-Quantum Signatures

```bash
qubitcoin-cli verifypqmessage "qp1developer" "signature" "SHA256(qubitcoin-1.0.0.tar.gz)=<hash>"
```

### 3. Seed Node Verification

The seed node operators verify and confirm the release by updating their nodes. The seed list is published in `chainparamsseeds.h` and can be cross-checked.

## Publishing the Release

### 1. Upload Binaries

Release binaries are uploaded to:

- GitHub Releases: https://github.com/qubitcoin/qubitcoin/releases
- QuBitcoin Download Server: https://download.qubitcoin.org/
- BitTorrent Network (with magnet links published)

### 2. Update Documentation

- Update website download pages
- Update documentation sites
- Publish updated Prometheus monitoring configs and alerts

### 3. Announcement

- Send announcement email to the mailing list
- Post on official communication channels
- Notify major exchanges and service providers

## Security Considerations

### 1. Air-gapped Signing

Release signing should be performed on an air-gapped machine that has never been connected to the internet.

### 2. Key Security

- Release signing keys should be protected with strong passphrases and kept offline
- Hardware security modules (HSMs) should be used when possible
- Private keys should never be transmitted over the internet

### 3. Backup Procedure

- Secure backups of signing keys must be maintained
- Multi-signature quorum ensures no single point of failure

## Document Signature

This document is cryptographically signed by the QuBitcoin development team. To verify the signature, use:

```bash
qubitcoin-cli verifymessage "qp1developer" "signature" "release-process.md hash: <sha256sum of this file>"
```

The latest signature can be found in docs.sig. 