
// src/rpc/register.h

#ifndef QUBITCOIN_RPC_REGISTER_H
#define QUBITCOIN_RPC_REGISTER_H

#include <bitcoin-build-config.h> // IWYU pragma: keep

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
void RegisterFeeRPCCommands(CRPCTable&);
void RegisterMempoolRPCCommands(CRPCTable&);
void RegisterMiningRPCCommands(CRPCTable &tableRPC);
void RegisterNodeRPCCommands(CRPCTable&);
void RegisterNetRPCCommands(CRPCTable&);
void RegisterOutputScriptRPCCommands(CRPCTable&);
void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);
void RegisterSignMessageRPCCommands(CRPCTable&);
void RegisterSignerRPCCommands(CRPCTable &tableRPC);
void RegisterTxoutProofRPCCommands(CRPCTable&);
// Register Post-Quantum Cryptography (PQC) RPC commands (Dilithium3)
void RegisterPQCCommands(CRPCTable&);

static inline void RegisterAllCoreRPCCommands(CRPCTable &t)
{
    RegisterBlockchainRPCCommands(t);
    RegisterFeeRPCCommands(t);
    RegisterMempoolRPCCommands(t);
    RegisterMiningRPCCommands(t);
    RegisterNodeRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterOutputScriptRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);
    RegisterSignMessageRPCCommands(t);
#ifdef ENABLE_EXTERNAL_SIGNER
    RegisterSignerRPCCommands(t);
#endif // ENABLE_EXTERNAL_SIGNER
    RegisterTxoutProofRPCCommands(t);
    // Register Post-Quantum Cryptography RPC commands (Dilithium3)
    RegisterPQCCommands(t);
}

#endif // QUBITCOIN_RPC_REGISTER_H
