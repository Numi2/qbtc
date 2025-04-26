Qubitcoin Block Header Format (Proof-of-Work Input)
================================================

External miners (and pool software) must hash exactly the same 80 bytes that the built-in miner hashes using BLAKE3-256.  The byte layout (all fields little-endian) is:

1. Version (4 bytes)
2. Previous Block Hash (32 bytes)
3. Merkle Root (32 bytes)
4. Time (4 bytes)
5. Difficulty Bits (nBits) (4 bytes)
6. Nonce (4 bytes)

Note:
- Do *not* include the post-quantum signature fields (`headerPubKey`, `headerSig`) in the hash input.  They are serialized after the 80-byte header in the full block and excluded from proof-of-work.
- Multi-byte integer fields must be encoded in little-endian, exactly as on the wire.
- After constructing the 80-byte header buffer, compute the BLAKE3-256 digest.  Treat the 32-byte output as a little-endian 256-bit value and compare it against the target derived from `nBits`.

Example invocation (pseudocode):
```
header = concat(
    encodeLE(version, 4),
    prev_hash,            // 32-byte little-endian
    merkle_root,          // 32-byte little-endian
    encodeLE(time, 4),
    encodeLE(nBits, 4),
    encodeLE(nonce, 4)
)
digest = blake3(header)
if le_uint256(digest) <= target_from_nBits(nBits):
    // valid proof-of-work
```

By following this exact header format, Stratum and other pool protocols will interoperate seamlessly with Qubitcoin’s built-in miner.