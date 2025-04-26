// src/crypto/pqc.h
#ifndef QUBITCOIN_CRYPTO_PQC_H
#define QUBITCOIN_CRYPTO_PQC_H

#include <openssl/evp.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <stdexcept>
#include <gsl/span>
class CDilithiumKey {
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> p{nullptr,EVP_PKEY_free};
public:
    static CDilithiumKey Generate()
    {
        EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(nullptr,"dilithium3",nullptr);
        if(!c) throw std::runtime_error("ctx");
        if(EVP_PKEY_keygen_init(c)<=0) throw std::runtime_error("kg-init");
        EVP_PKEY* k=nullptr;
        if(EVP_PKEY_generate(c,&k)<=0) throw std::runtime_error("kg-run");
        EVP_PKEY_CTX_free(c);
        return CDilithiumKey{k};
    }
    std::vector<uint8_t> Pub() const
    {
        size_t l=0;
        EVP_PKEY_get_octet_string_param(p.get(),"pub",nullptr,0,&l,nullptr);
        std::vector<uint8_t> v(l);
        EVP_PKEY_get_octet_string_param(p.get(),"pub",v.data(),l,&l,nullptr);
        return v;
    }
    std::vector<uint8_t> Priv() const
    {
        size_t l=0;
        EVP_PKEY_get_octet_string_param(p.get(),"priv",nullptr,0,&l,nullptr);
        std::vector<uint8_t> v(l);
        EVP_PKEY_get_octet_string_param(p.get(),"priv",v.data(),l,&l,nullptr);
        return v;
    }
    std::vector<uint8_t> Sign(gsl::span<const uint8_t> msg) const
    {
        EVP_MD_CTX* m=EVP_MD_CTX_new();
        size_t sl=0;
        EVP_DigestSignInit(m,nullptr,nullptr,nullptr,p.get());
        EVP_DigestSign(m,nullptr,&sl,msg.data(),msg.size());
        std::vector<uint8_t> sig(sl);
        EVP_DigestSign(m,sig.data(),&sl,msg.data(),msg.size());
        EVP_MD_CTX_free(m);
        sig.resize(sl); return sig;
    }
    static bool Verify(const std::vector<uint8_t>& pub,
                       gsl::span<const uint8_t> msg,
                       gsl::span<const uint8_t> sig)
    {
        EVP_PKEY* pk = EVP_PKEY_new_raw_public_key_ex(nullptr,"dilithium3",
                                                      nullptr,pub.data(),pub.size());
        EVP_MD_CTX* m=EVP_MD_CTX_new();
        EVP_DigestVerifyInit(m,nullptr,nullptr,nullptr,pk);
        int r = EVP_DigestVerify(m,sig.data(),sig.size(),msg.data(),msg.size());
        EVP_PKEY_free(pk); EVP_MD_CTX_free(m);
        return r==1;
    }
private:
    explicit CDilithiumKey(EVP_PKEY* k):p(k,EVP_PKEY_free){}
};

#endif // QUBITCOIN_CRYPTO_PQC_H