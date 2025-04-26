// C++ wrapper and EVP integration for BLAKE3
#include <crypto/blake3.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <mutex>

// EVP method callbacks for BLAKE3
static int blake3_evp_init(EVP_MD_CTX* ctx) {
    blake3_hasher* h = (blake3_hasher*)EVP_MD_CTX_md_data(ctx);
    blake3_hasher_init(h);
    return 1;
}

static int blake3_evp_update(EVP_MD_CTX* ctx, const void* data, size_t count) {
    blake3_hasher* h = (blake3_hasher*)EVP_MD_CTX_md_data(ctx);
    blake3_hasher_update(h, data, count);
    return 1;
}

static int blake3_evp_final(EVP_MD_CTX* ctx, unsigned char* md) {
    blake3_hasher* h = (blake3_hasher*)EVP_MD_CTX_md_data(ctx);
    blake3_hasher_finalize(h, md, BLAKE3_OUT_LEN);
    return 1;
}

static int blake3_evp_copy(EVP_MD_CTX* to, const EVP_MD_CTX* from) {
    const blake3_hasher* src = (const blake3_hasher*)EVP_MD_CTX_md_data(from);
    blake3_hasher* dst = (blake3_hasher*)EVP_MD_CTX_md_data(to);
    *dst = *src;
    return 1;
}

const EVP_MD* EVP_blake3(void) {
    static EVP_MD* md = nullptr;
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        EVP_MD* m = EVP_MD_meth_new(NID_undef, NID_undef);
        if (!m ||
            EVP_MD_meth_set_result_size(m, BLAKE3_OUT_LEN) != 1 ||
            EVP_MD_meth_set_input_blocksize(m, BLAKE3_BLOCK_LEN) != 1 ||
            EVP_MD_meth_set_app_datasize(m, sizeof(blake3_hasher)) != 1 ||
            EVP_MD_meth_set_init(m, blake3_evp_init) != 1 ||
            EVP_MD_meth_set_update(m, blake3_evp_update) != 1 ||
            EVP_MD_meth_set_final(m, blake3_evp_final) != 1 ||
            EVP_MD_meth_set_copy(m, blake3_evp_copy) != 1) {
            throw std::runtime_error("EVP_blake3: failed to create EVP_MD");
        }
        EVP_add_digest(m);
        md = m;
    });
    return md;
}

// CBlake3 method definitions
CBlake3::CBlake3() {
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_blake3(), nullptr) != 1) {
        throw std::runtime_error("CBlake3: EVP initialization failed");
    }
}

CBlake3::~CBlake3() {
    if (ctx) EVP_MD_CTX_free(ctx);
}

CBlake3& CBlake3::Write(const unsigned char* data, size_t len) {
    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        throw std::runtime_error("CBlake3: EVP update failed");
    }
    return *this;
}

CBlake3& CBlake3::Reset() {
    if (EVP_DigestInit_ex(ctx, EVP_blake3(), nullptr) != 1) {
        throw std::runtime_error("CBlake3: EVP reset failed");
    }
    return *this;
}

void CBlake3::Finalize(unsigned char hash[CBlake3::OUTPUT_SIZE]) {
    unsigned int outlen = CBlake3::OUTPUT_SIZE;
    if (EVP_DigestFinal_ex(ctx, hash, &outlen) != 1 || outlen != CBlake3::OUTPUT_SIZE) {
        throw std::runtime_error("CBlake3: EVP finalization failed");
    }
}