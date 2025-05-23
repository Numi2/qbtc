//   2011-2022 
//    
//  

#include <common/signmessage.h>
#include <key_io.h>
#include <rpc/util.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>

#include <univalue.h>

namespace wallet {
RPCHelpMan signmessage()
{
    return RPCHelpMan{"signmessage",
        "\nSign a message with the private key of an address" +
          HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to use for the private key."},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
        },
        RPCResult{
            RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
        },
        RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"my message\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);

            EnsureWalletIsUnlocked(*pwallet);

            std::string strAddress = request.params[0].get_str();
            std::string strMessage = request.params[1].get_str();

            // Decode destination (supports PQC v2 and legacy PKH)
            std::string error_msg;
            std::vector<int> error_locations;
            CTxDestination dest = DecodeDestination(strAddress, error_msg, &error_locations);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error_msg.empty() ? "Invalid address" : error_msg);
            }

            // Handle PQC v2 addresses
            if (auto pw = std::get_if<WitnessUnknown>(&dest); pw && pw->GetWitnessVersion() == 2) {
                // Sign with PQC keystore
                const auto& keystore = pwallet->GetPQCKeyStore();
                std::string signature;
                if (!keystore.SignMessage(strAddress, strMessage, signature)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "PQC signing failed");
                }
                return signature;
            }
            // Legacy PKHash addresses
            const PKHash* pkhash = std::get_if<PKHash>(&dest);
            if (!pkhash) {
                throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to supported key type");
            }

            std::string signature;
            SigningResult err = pwallet->SignMessage(strMessage, *pkhash, signature);
            if (err == SigningResult::SIGNING_FAILED) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, SigningResultString(err));
            } else if (err != SigningResult::OK) {
                throw JSONRPCError(RPC_WALLET_ERROR, SigningResultString(err));
            }

            return signature;
        },
    };
}
} // namespace wallet
