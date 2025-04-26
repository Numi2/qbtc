#ifndef QUBITCOIN_NET_NOISE_H
#define QUBITCOIN_NET_NOISE_H

#pragma once

#include <crypto/kyber.h>
#include <span>
#include <vector>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

// Forward declarations to avoid OpenSSL dependency in header
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace qubitcoin {
namespace net {

/**
 * Noise Protocol Framework implementation with support for hybrid X25519+Kyber768
 * using the Noise_IK_25519_Kyber768 pattern.
 * 
 * This implementation follows the Noise Protocol Specification:
 * https://noiseprotocol.org/noise.html
 * 
 * Extended with a hybrid post-quantum approach using the "hybrid forward" pattern
 * where Kyber768 is used alongside X25519 for key exchange.
 */
class NoiseEncryption {
public:
    // Size constants
    static constexpr size_t X25519_PUBLIC_KEY_SIZE = 32;
    static constexpr size_t X25519_PRIVATE_KEY_SIZE = 32;
    static constexpr size_t HASH_SIZE = 32;  // SHA256 output size
    static constexpr size_t SYMMETRIC_KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 8;
    static constexpr size_t MAC_SIZE = 16;
    static constexpr size_t MAX_PACKET_SIZE = 65535;
    static constexpr size_t PROTOCOL_NAME_SIZE = 64;
    
    // Protocol identifier
    static constexpr const char* PROTOCOL_NAME = "Noise_IK_25519_Kyber768_SHA256_ChaChaPoly";
    
    /**
     * NoiseHandshakeState tracks the state during the handshake phase
     */
    class HandshakeState {
    public:
        // Handshake patterns
        enum class Pattern {
            IK      // Identity Key pattern (initiator knows recipient static key)
        };
        
        // Handshake roles
        enum class Role {
            Initiator,  // Client initiating the connection
            Responder   // Server accepting connections
        };

        /**
         * Initialize a handshake state for the given pattern and role
         * 
         * @param pattern The handshake pattern to use
         * @param role Whether this peer is the initiator or responder
         * @param static_key Our static keypair (both X25519 and Kyber)
         * @param remote_static_key Remote static public key (if known)
         * @param psk Pre-shared key (optional)
         */
        static std::unique_ptr<HandshakeState> Initialize(
            Pattern pattern,
            Role role, 
            EVP_PKEY* static_key,
            EVP_PKEY* remote_static_key = nullptr,
            std::span<const uint8_t> psk = {});
            
        /**
         * Write the next handshake message
         * 
         * @param payload Optional application payload to include
         * @return The handshake message to send
         */
        std::vector<uint8_t> WriteMessage(std::span<const uint8_t> payload = {});
        
        /**
         * Read and process the next handshake message
         * 
         * @param message The received handshake message
         * @return The decrypted payload, if any
         */
        std::optional<std::vector<uint8_t>> ReadMessage(std::span<const uint8_t> message);
        
        /**
         * Check if the handshake is complete
         * 
         * @return true if handshake is complete and transport messages can be exchanged
         */
        bool IsHandshakeComplete() const;
        
        /**
         * Get the transport encryption state after handshake is complete
         * 
         * @return The transport state for subsequent communication
         */
        std::unique_ptr<TransportState> GetTransportState();
        
    private:
        // Private implementation details
    };
    
    /**
     * NoiseTransportState handles message encryption/decryption after handshake
     */
    class TransportState {
    public:
        /**
         * Encrypt a message
         * 
         * @param plaintext The message to encrypt
         * @return The encrypted message
         */
        std::vector<uint8_t> EncryptMessage(std::span<const uint8_t> plaintext);
        
        /**
         * Decrypt a message
         * 
         * @param ciphertext The encrypted message
         * @return The decrypted message, or empty if authentication fails
         */
        std::optional<std::vector<uint8_t>> DecryptMessage(std::span<const uint8_t> ciphertext);
        
    private:
        // Private implementation details
    };
    
    /**
     * Generate a new X25519 keypair
     */
    static EVP_PKEY* GenerateX25519Keypair();
    
    /**
     * Create a hybrid keypair containing both X25519 and Kyber768 keys
     */
    static std::pair<EVP_PKEY*, EVP_PKEY*> GenerateHybridKeypair();
};

} // namespace net
} // namespace qubitcoin

#endif // QUBITCOIN_NET_NOISE_H 