ifndef BLAKE3_IMPL_H
#define BLAKE3_IMPL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "blake3.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Flags for chunk and parent node processing */
#define CHUNK_START 1u
#define CHUNK_END   2u
#define PARENT      4u
#define ROOT        8u
#define KEYED_HASH  16u
#define DERIVE_KEY_CONTEXT  32u
#define DERIVE_KEY_MATERIAL 64u

/** Compress a single block in place. */
void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len,
                                       uint64_t counter,
                                       uint8_t flags);
void blake3_compress_in_place_sse2(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags);
void blake3_compress_in_place_sse41(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags);
void blake3_compress_in_place_avx512(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags);

/** XOF output for a single block. */
void blake3_compress_xof_portable(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64]);
void blake3_compress_xof_sse2(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64]);
void blake3_compress_xof_sse41(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64]);
void blake3_compress_xof_avx512(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64]);

/** XOF many blocks. */
void blake3_xof_many(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64], size_t outblocks);

/** Hash many inputs in parallel. */
void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs, size_t blocks, const uint32_t key[8], uint64_t counter, bool increment_counter, uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t *out);

/** Detect SIMD degree. */
size_t blake3_simd_degree(void);

#ifdef __cplusplus
}
#endif

#endif // BLAKE3_IMPL_H