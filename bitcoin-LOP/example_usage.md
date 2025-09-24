# New Order Creation Usage Example

## Overview
The new order creation system provides enhanced functionality for creating Bitcoin HTLC orders with support for different HTLC types (P2TR, P2WSH, ICP Escrow) and advanced features like auctions and cross-chain support.

## Key Features
- **Multiple HTLC Types**: Support for P2TR (Taproot), P2WSH, and ICP Escrow
- **Cross-Chain Support**: Source and destination chain IDs
- **Enhanced Order Parameters**: Salt, maker addresses, auction details
- **Address Validation**: EVM address validation for destination addresses
- **Partial Fill Support**: Configurable partial fill behavior
- **Separate Storage**: Independent from existing order system

## Usage Example

```rust
use bitcoin_lop::{
    create_order_new, get_order_new, get_all_orders_new, get_orders_count_new, get_next_bitcoin_path_new, get_order_address_new,
    OrderDetailNew, HtlcType, MakerKey, AuctionDetails
};

// Example: Create a P2TR order
let order_hash = create_order_new(
    12345, // salt - random number for uniqueness
    MakerKey {
        source_address: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(), // x-only public key for P2TR
        destination_address: "0x742d35Cc6634C0532925a3b8D0C0C4C7C7C7C7C7".to_string(), // EVM address
    },
    HtlcType::P2TR,
    137, // dst_chain_id - Polygon (source is always Bitcoin)
    100000, // making_amount - 0.001 BTC in satoshis
    500000, // taking_amount - 0.005 BTC in satoshis
    "BTC".to_string(), // taking_asset
    "a1b2c3d4e5f6...".to_string(), // hashlock
    1000, // timelock
    AuctionDetails {
        initial_rate_bump: 0,
        points: vec![],
        duration: 120,
        start_time: 1234567890,
    },
    true, // allow_partial_fills
)?;

// Get the order address
let order_address = get_order_address_new(order_hash.clone()).await?;

// Retrieve order details
let order_details = get_order_new(order_hash);
```

## HTLC Types and Address Requirements

### P2TR (Taproot)
- **HTLC Type**: `HtlcType::P2TR`
- **Source Address**: Must be a valid x-only public key (64 hex characters)
- **Destination Address**: Must be a valid EVM address (starts with "0x", 42 characters)

### P2WSH (P2WSH)
- **HTLC Type**: `HtlcType::P2WSH`
- **Source Address**: Must be a valid compressed public key (66 hex characters starting with "02" or "03")
- **Destination Address**: Must be a valid EVM address (starts with "0x", 42 characters)

### ICP Escrow
- **HTLC Type**: `HtlcType::ICPEscrow`
- **Source Address**: Must be a valid Bitcoin address (starts with "bc1")
- **Destination Address**: Must be a valid EVM address (starts with "0x", 42 characters)

## Order Parameters

- **salt**: Random number ensuring each order is unique
- **maker_key**: Contains source (Bitcoin) and destination (EVM) addresses
- **htlc_type**: Type of HTLC (P2TR, P2WSH, ICP Escrow)
- **dst_chain_id**: Destination chain ID (e.g., 137 for Polygon) - source is always Bitcoin
- **making_amount**: Amount being offered (in satoshis)
- **taking_amount**: Amount being requested (in respective token)
- **taking_asset**: Asset identifier being requested (in respective token)
- **hashlock**: Hashlock for the HTLC
- **timelock**: Timelock duration for the HTLC
- **auction**: Auction configuration details
- **allow_partial_fills**: Whether partial fills are allowed

## Address Validation

The system automatically validates:
- **EVM Addresses**: Must start with "0x" and be exactly 42 characters with valid hex
- **Bitcoin Keys/Addresses**: Format validation based on HTLC type
  - P2TR: Must be x-only public key (64 hex characters)
  - P2WSH: Must be compressed public key (66 hex characters starting with "02" or "03")
  - ICPEscrow: Must be valid Bitcoin address

## Available Functions

- `create_order_new(...)` - Create a new order (returns Result<String, String> - order hash)
- `get_order_new(order_hash)` - Get specific order details by hash
- `get_all_orders_new()` - Get all orders (returns Vec<(String, OrderDetailNew)>)
- `get_orders_count_new()` - Get total number of orders
- `get_next_bitcoin_path_new()` - Get next Bitcoin derivation path
- `get_order_address_new(order_hash)` - Get order's Bitcoin address by hash

## Order Hash System

The system now uses SHA-256 hashes of the entire order structure as unique identifiers:
- **Deterministic**: Same order parameters always produce the same hash
- **Unique**: Different orders produce different hashes
- **Collision Resistant**: SHA-256 ensures no hash collisions
- **Duplicate Prevention**: System prevents creating duplicate orders

## Bitcoin Path System

Each order gets a unique Bitcoin derivation path:
- **Auto-incremented**: `order_contract_bitcoin_path` starts at 1 and increments for each order
- **Deterministic**: Same path number always generates the same Bitcoin address
- **Unique**: Each order gets a different derivation path
- **Persistent**: Path is stored in the order and used for address generation

## Chain ID Validation

The system validates addresses based on fixed chain types:
- **Source (Always Bitcoin)**: Must be valid Bitcoin address/key based on HTLC type
- **Destination (Always EVM)**: Must be valid EVM address (0x...)
- **HTLC Type Validation**: Additional validation based on P2TR, P2WSH, or ICP Escrow
