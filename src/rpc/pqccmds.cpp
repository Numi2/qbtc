// RPC commands for post-quantum cryptography (Dilithium3) using OpenSSL EVP + Provider API
#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>
#include <crypto/pqc_keys.h>
#include <util/hash.h>
#include <bech32.h>
#include <util/strencodings.h>

static RPCHelpMan genpqckey()
{
    return RPCHelpMan{"genpqckey",
        "Generate a new Dilithium3 key pair.\n",
        {},
        {
            RPCResult{RPCResult::Type::STR, "private_key", "The private key in base64 (PKCS8 DER)"},
            RPCResult{RPCResult::Type::STR, "public_key", "The public key in base64 (SubjectPublicKeyInfo DER)"},
        },
        RPCExamples{
            HelpExampleCli("genpqckey", "") +
            HelpExampleRpc("genpqckey", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            EVP_PKEY* pkey = GenerateDilithium3Key();
            std::vector<unsigned char> priv_der = ExportDilithium3PrivateKey(pkey);
            std::vector<unsigned char> pub_der = ExportDilithium3PublicKey(pkey);
            EVP_PKEY_free(pkey);
            std::string priv_b64 = EncodeBase64(priv_der);
            std::string pub_b64 = EncodeBase64(pub_der);
            UniValue result(UniValue::VOBJ);
            result.pushKV("private_key", priv_b64);
            result.pushKV("public_key", pub_b64);
            return result;
        }
    };
}

static RPCHelpMan signmessagepqc()
{
    return RPCHelpMan{"signmessagepqc",
        "Sign a message with a Dilithium3 private key.\n",
        {
            {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key in base64 (PKCS8 DER)"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to sign"},
        },
        RPCResult{RPCResult::Type::STR, "", "The signature in base64"},
        RPCExamples{
            HelpExampleCli("signmessagepqc", R"(<privkey> \"message\"")") +
            HelpExampleRpc("signmessagepqc", R"(<privkey>, \"message\")")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string priv_b64 = request.params[0].get_str();
            std::string message = request.params[1].get_str();
            auto priv_der = DecodeBase64(priv_b64);
            if (!priv_der) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Malformed private key (not base64)");
            }
            EVP_PKEY* pkey = LoadDilithium3PrivateKey(priv_der->data(), priv_der->size());
            std::vector<unsigned char> sig = SignDilithium3(pkey,
                reinterpret_cast<const unsigned char*>(message.data()), message.size());
            EVP_PKEY_free(pkey);
            std::string sig_b64 = EncodeBase64(sig);
            return sig_b64;
        }
    };
}

static RPCHelpMan verifymessagepqc()
{
    return RPCHelpMan{"verifymessagepqc",
        "Verify a Dilithium3 signature of a message.\n",
        {
            {"pubkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The public key in base64 (SubjectPublicKeyInfo DER)"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed"},
            {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature in base64"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "True if signature is valid"},
        RPCExamples{
            HelpExampleCli("verifymessagepqc", R"(<pubkey> \"message\" <signature>)") +
            HelpExampleRpc("verifymessagepqc", R"(<pubkey>, \"message\", <signature>)")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string pub_b64 = request.params[0].get_str();
            std::string message = request.params[1].get_str();
            std::string sig_b64 = request.params[2].get_str();
            auto pub_der = DecodeBase64(pub_b64);
            if (!pub_der) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Malformed public key (not base64)");
            }
            auto sig = DecodeBase64(sig_b64);
            if (!sig) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Malformed signature (not base64)");
            }
            EVP_PKEY* pkey = LoadDilithium3PublicKey(pub_der->data(), pub_der->size());
            bool ok = VerifyDilithium3(pkey,
                sig->data(), sig->size(),
                reinterpret_cast<const unsigned char*>(message.data()), message.size());
            EVP_PKEY_free(pkey);
            return ok;
        }
    };
}

static RPCHelpMan getnewpqcaddress()
{
    return RPCHelpMan{"getnewpqcaddress",
        "Generate a new QuBitcoin quantum-safe (Dilithium3) address and key pair (witness v2).\n",
        {},
        {
            RPCResult{RPCResult::Type::STR, "address", "The new Bech32m v2 address (qbc1p...)"},
            RPCResult{RPCResult::Type::STR, "public_key", "The public key in base64 (SPKI DER)"},
            RPCResult{RPCResult::Type::STR, "private_key", "The private key in base64 (PKCS8 DER)"},
        },
        RPCExamples{
            HelpExampleCli("getnewpqcaddress", "") +
            HelpExampleRpc("getnewpqcaddress", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            LoadOQSProvider();
            EVP_PKEY* pkey = GenerateDilithium3Key();
            std::vector<unsigned char> pub_der = ExportDilithium3PublicKey(pkey);
            std::vector<unsigned char> priv_der = ExportDilithium3PrivateKey(pkey);
            std::string pub_b64 = EncodeBase64(pub_der);
            std::string priv_b64 = EncodeBase64(priv_der);
            // Compute BLAKE3-256 of pubkey DER
            uint256 h = Blake3(std::span{pub_der.data(), pub_der.size()});
            std::vector<unsigned char> prog(h.begin(), h.end());
            // Build Bech32m v2 address
            std::vector<unsigned char> data;
            data.push_back(2);
            ConvertBits<8,5,true>([&](unsigned char c){ data.push_back(c); }, prog.begin(), prog.end());
            std::string address = bech32::Encode(bech32::Encoding::BECH32M, Params().Bech32HRP(), data);
            EVP_PKEY_free(pkey);
            UniValue result(UniValue::VOBJ);
            result.pushKV("address", address);
            result.pushKV("public_key", pub_b64);
            result.pushKV("private_key", priv_b64);
            return result;
        }
    };

void RegisterPQCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[] = {
        {"pqc", &genpqckey},
        {"pqc", &signmessagepqc},
        {"pqc", &verifymessagepqc},
        {"pqc", &getnewpqcaddress},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}