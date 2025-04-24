// src/util/hash.h
#include "blake3/blake3.h"

inline uint256 Blake3(const Span<const unsigned char>& m)
{
    uint8_t out[32];
    blake3_hasher h; blake3_hasher_init(&h);
    blake3_hasher_update(&h, m.data(), m.size());
    blake3_hasher_finalize(&h, out, 32);
    return uint256(std::span<const uint8_t,32>(out));
}
using Hash256 = Blake3;                  // replace all SHA256d occurences