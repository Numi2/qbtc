# QuBitcoin RPC API Documentation

This document provides a comprehensive reference for the QuBitcoin RPC (Remote Procedure Call) interface. 

**Version**: 1.0.0

**Last Updated**: 2023-06-15

## Table of Contents

1. [Authentication](#authentication)
2. [Getting Started](#getting-started)
3. [Blockchain Methods](#blockchain-methods)
4. [Network Methods](#network-methods)
5. [Wallet Methods](#wallet-methods)
6. [Mining Methods](#mining-methods)
7. [Post-Quantum Methods](#post-quantum-methods)
8. [Utility Methods](#utility-methods)

## Authentication

QuBitcoin RPC server uses HTTP Basic Authentication. The credentials are configured in the qubitcoin.conf file:

```
rpcuser=yourusername
rpcpassword=yourpassword
```

For security, use a strong, unique password. The RPC interface is not designed to be exposed to the internet.

## Getting Started

### Default RPC Port

- Mainnet: 8332
- Testnet: 18332
- Regtest: 18443

### Making Requests

RPC calls can be made using curl, like this:

```bash
curl --user yourusername:yourpassword --data-binary '{"jsonrpc":"1.0","id":"curltest","method":"getblockchaininfo","params":[]}' -H 'content-type: text/plain;' http://127.0.0.1:8332/
```

Or using the qubitcoin-cli utility:

```bash
qubitcoin-cli getblockchaininfo
```

## Blockchain Methods

### `getbestblockhash`

Returns the hash of the best (tip) block in the most-work fully-validated chain.

**Parameters**: None

**Result**: 
- `string` (hex) - The block hash, hex-encoded

**Example**:
```bash
qubitcoin-cli getbestblockhash
```

### `getblock "blockhash" ( verbosity )`

Returns data about the specified block.

**Parameters**:
1. `blockhash` (string, required) - The block hash
2. `verbosity` (numeric, optional, default=1) - 0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data

**Result (for verbosity = 1)**:
```json
{
  "hash": "...",
  "confirmations": n,
  "size": n,
  "height": n,
  "version": n,
  "versionHex": "...",
  "merkleroot": "...",
  "time": n,
  "mediantime": n,
  "nonce": n,
  "bits": "...",
  "difficulty": n,
  "previousblockhash": "...",
  "nextblockhash": "...",
  "tx": ["txid1", "txid2", ...]
}
```

**Example**:
```bash
qubitcoin-cli getblock "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"
```

### `getblockchaininfo`

Returns information about the current state of the blockchain.

**Parameters**: None

**Result**:
```json
{
  "chain": "...",
  "blocks": n,
  "headers": n,
  "bestblockhash": "...",
  "difficulty": n,
  "mediantime": n,
  "verificationprogress": n,
  "initialblockdownload": true|false,
  "chainwork": "...",
  "size_on_disk": n,
  "pruned": true|false,
  "softforks": {...},
  "warnings": "..."
}
```

**Example**:
```bash
qubitcoin-cli getblockchaininfo
```

### `getblockcount`

Returns the height of the most-work fully-validated chain.

**Parameters**: None

**Result**: 
- `numeric` - The current block count

**Example**:
```bash
qubitcoin-cli getblockcount
```

## Network Methods

### `getconnectioncount`

Returns the number of connections to other nodes.

**Parameters**: None

**Result**: 
- `numeric` - The connection count

**Example**:
```bash
qubitcoin-cli getconnectioncount
```

### `getnetworkinfo`

Returns information about the node's network connection.

**Parameters**: None

**Result**:
```json
{
  "version": n,
  "subversion": "...",
  "protocolversion": n,
  "localservices": "...",
  "localrelay": true|false,
  "timeoffset": n,
  "connections": n,
  "networks": [...],
  "relayfee": n,
  "incrementalfee": n,
  "localaddresses": [...],
  "warnings": "..."
}
```

**Example**:
```bash
qubitcoin-cli getnetworkinfo
```

### `getpeerinfo`

Returns data about each connected network node.

**Parameters**: None

**Result**:
```json
[
  {
    "id": n,
    "addr": "...",
    "addrbind": "...",
    "addrlocal": "...",
    "services": "...",
    "relaytxes": true|false,
    "lastsend": n,
    "lastrecv": n,
    "bytessent": n,
    "bytesrecv": n,
    "conntime": n,
    "timeoffset": n,
    "pingtime": n,
    "minping": n,
    "pingwait": n,
    "version": n,
    "subver": "...",
    "inbound": true|false,
    "startingheight": n,
    "banscore": n,
    "synced_headers": n,
    "synced_blocks": n,
    "inflight": [...],
    "whitelisted": true|false,
    "permissions": [...],
    "minfeefilter": n,
    "bytessent_per_msg": {...},
    "bytesrecv_per_msg": {...},
    "connection_type": "...",
    "pq_capable": true|false
  }
  ,...
]
```

**Example**:
```bash
qubitcoin-cli getpeerinfo
```

## Wallet Methods

### `createwallet "wallet_name" ( disable_private_keys )`

Creates and loads a new wallet.

**Parameters**:
1. `wallet_name` (string, required) - The name for the new wallet
2. `disable_private_keys` (boolean, optional, default=false) - Disable the possibility of private keys

**Result**:
```json
{
  "name": "...",
  "warning": "..."
}
```

**Example**:
```bash
qubitcoin-cli createwallet "testwallet"
```

### `getbalance ( "dummy" minconf include_watchonly avoid_reuse )`

Returns the total available balance.

**Parameters**:
1. `dummy` (string, optional) - Remains for backward compatibility, must be excluded or set to "*"
2. `minconf` (numeric, optional, default=0) - Only include transactions confirmed at least this many times
3. `include_watchonly` (boolean, optional, default=true for watch-only wallets, otherwise false) - Also include balance in watch-only addresses
4. `avoid_reuse` (boolean, optional, default=true) - Avoid spending from reused addresses

**Result**:
- `numeric` - The total amount

**Example**:
```bash
qubitcoin-cli getbalance
```

### `getnewaddress ( "label" "address_type" )`

Returns a new address for receiving payments.

**Parameters**:
1. `label` (string, optional, default="") - The label name for the address
2. `address_type` (string, optional) - The address type to use. Options: "legacy", "p2sh-segwit", "bech32", "p2wpq"

**Result**:
- `string` - The new address

**Example**:
```bash
qubitcoin-cli getnewaddress "mylabel" "p2wpq"
```

## Post-Quantum Methods

### `createpqaddress`

Creates a new post-quantum address using Dilithium signatures.

**Parameters**: None

**Result**:
```json
{
  "address": "qp1...",
  "pubkey": "hex string",
  "algorithm": "dilithium3",
  "path": "m/6077'/0'/0'/..."
}
```

**Example**:
```bash
qubitcoin-cli createpqaddress
```

### `signpqmessage "address" "message"`

Signs a message with the private key of a post-quantum address.

**Parameters**:
1. `address` (string, required) - The post-quantum address
2. `message` (string, required) - The message to sign

**Result**:
- `string` - The signature

**Example**:
```bash
qubitcoin-cli signpqmessage "qp1..." "test message"
```

### `verifypqmessage "address" "signature" "message"`

Verifies a signed message from a post-quantum address.

**Parameters**:
1. `address` (string, required) - The post-quantum address
2. `signature` (string, required) - The signature
3. `message` (string, required) - The message that was signed

**Result**:
- `boolean` - True if the signature is valid

**Example**:
```bash
qubitcoin-cli verifypqmessage "qp1..." "signature" "test message"
```

## Monitoring Methods

### `getmetrics`

Returns all Prometheus metrics values.

**Parameters**: None

**Result**:
```json
{
  "qubitcoin_blockchain_height": n,
  "qubitcoin_blockchain_difficulty": n,
  "qubitcoin_mempool_size": n,
  ...
}
```

**Example**:
```bash
qubitcoin-cli getmetrics
```

## Signature Verification

This document is cryptographically signed by the QuBitcoin development team. To verify the signature, use:

```bash
qubitcoin-cli verifymessage "qp1developer" "signature" "rpc-api.md hash: <sha256sum of this file>"
```

The latest signature can be found in docs.sig. 