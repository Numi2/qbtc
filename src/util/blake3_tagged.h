#ifndef BITCOIN_UTIL_BLAKE3_TAGGED_H
#define BITCOIN_UTIL_BLAKE3_TAGGED_H

#include <crypto/blake3.h>
#include <util/span.h>
#include <vector>
#include <string>

/**
 * Tagged Blake3 hash (similar to BIP-340 tagged hash but using Blake3).
 */
class Blake3Writer {
private:
    blake3_hasher hasher;
public:
    /** Initialize with a tag string. Internally, tag is hashed twice. */
    explicit Blake3Writer(const std::string& tag) {
        uint8_t tag_hash[32];
        blake3_hasher_init(&hasher);
        // tag hashing
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, (const uint8_t*)tag.data(), tag.size());
        blake3_hasher_finalize(&hasher, tag_hash, sizeof(tag_hash));
        // pre-feed tag_hash
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, tag_hash, sizeof(tag_hash));
        blake3_hasher_update(&hasher, tag_hash, sizeof(tag_hash));
    }
    /** Append data to hash */
    void Write(const uint8_t* data, size_t len) {
        blake3_hasher_update(&hasher, data, len);
    }
    /** Finish and return final digest */
    std::vector<uint8_t> GetHash() {
        std::vector<uint8_t> out(32);
        blake3_hasher_finalize(&hasher, out.data(), out.size());
        return out;
    }
};

/** Compute tagged Blake3 hash in one call. */
inline std::vector<uint8_t> TaggedBlake3Hash(const std::string& tag, const std::vector<uint8_t>& data) {
    Blake3Writer writer(tag);
    writer.Write(data.data(), data.size());
    return writer.GetHash();
}

#endif // BITCOIN_UTIL_BLAKE3_TAGGED_H