//   2012-present 
//    
//  

#ifndef BITCOIN_NODE_PROTOCOL_VERSION_H
#define BITCOIN_NODE_PROTOCOL_VERSION_H

/**
 * network protocol versioning
 */

static const int PROTOCOL_VERSION = 1;

//! initial proto version
static const int INIT_PROTO_VERSION = 1;

//! disconnect from peers with lower proto version
static const int MIN_PEER_PROTO_VERSION = 1;

//! BIP 0031, pong message, is enabled for all versions AFTER this one
static const int BIP0031_VERSION = 1;

//! "sendheaders" command and announcing blocks with headers starts with this version
static const int SENDHEADERS_VERSION = 1;

//! "feefilter" tells peers to filter invs to you by fee starts with this version
static const int FEEFILTER_VERSION = 1;

//! short-id-based block download starts with this version
static const int SHORT_IDS_BLOCKS_VERSION = 1;

//! not banning for invalid compact blocks starts with this version
static const int INVALID_CB_NO_BAN_VERSION = 1;

//! "wtxidrelay" command for wtxid-based relay starts with this version
static const int WTXID_RELAY_VERSION = 1;

#endif // BITCOIN_NODE_PROTOCOL_VERSION_H
