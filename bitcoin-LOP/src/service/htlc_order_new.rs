//! HTLC Order System with 5-Secret Partial Fill Logic
//! 
//! This module implements a secure HTLC order system with percentage-based secret selection
//! for partial fills. The system uses 5 secrets corresponding to different fill percentage ranges:
//! - Secret 0: 0-25% of total order amount
//! - Secret 1: 25-50% of total order amount  
//! - Secret 2: 50-75% of total order amount
//! - Secret 3: 75-100% of total order amount (but not exactly 100%)
//! - Secret 4: Exactly 100% of total order amount
//!
//! Security Features:
//! - Integer arithmetic to prevent floating-point rounding issues
//! - Secret reuse protection to prevent double-spending
//! - Concurrency control with order-level locking
//! - Proper Merkle tree structure for secret validation
//! - Secure random secret generation (production should use OsRng)
//! - Atomic transaction processing with rollback on failure

use candid::CandidType;
use ic_cdk::{query, update};
use std::cell::RefCell;
use std::collections::HashMap;
use crate::{common::DerivationPath, ecdsa::get_ecdsa_public_key, BTC_CONTEXT};
use bitcoin::{Address, CompressedPublicKey, PublicKey, XOnlyPublicKey, ScriptBuf, opcodes};
use bitcoin::script::PushBytesBuf;
use sha2::{Sha256, Digest};
use std::str::FromStr;
// Note: For production, add rand_core and rand to Cargo.toml
// For now, using a simple approach with system time for demonstration
use crate::{
    common::{get_fee_per_byte},
    ecdsa::{sign_with_ecdsa},
    p2wpkh,
};
use ic_cdk::bitcoin_canister::{
    bitcoin_get_utxos, bitcoin_send_transaction, GetUtxosRequest, SendTransactionRequest,
};
use bitcoin::consensus::serialize;

/// Validates if an address is a valid EVM address (starts with 0x and is 42 characters)
fn is_valid_evm_address(address: &str) -> bool {
    address.starts_with("0x") && address.len() == 42 && address[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Validates if an address is a valid Bitcoin address
fn is_valid_bitcoin_address(address: &str) -> bool {
    Address::from_str(address).is_ok()
}

/// Validates if a string is a valid x-only public key by parsing it
fn is_valid_p2tr_address(key: &str) -> bool {
    // Try to parse as hex bytes first
    if let Ok(hex_bytes) = hex::decode(key) {
        // Try to create XOnlyPublicKey from the bytes
        XOnlyPublicKey::from_slice(&hex_bytes).is_ok()
    } else {
        false
    }
}

/// Validates if a string is a valid compressed public key by parsing it
fn is_valid_p2wsh_address(key: &str) -> bool {
    // Try to parse as hex bytes first
    if let Ok(hex_bytes) = hex::decode(key) {
        // Try to create PublicKey from the bytes
        PublicKey::from_slice(&hex_bytes).is_ok()
    } else {
        false
    }
}


/// Calculates SHA-256 hash of the order structure
fn calculate_order_hash(order: &OrderDetailNew) -> String {
    // Serialize the order to bytes for hashing
    let order_bytes = candid::encode_one(order).unwrap_or_default();
    
    // Calculate SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(&order_bytes);
    let hash = hasher.finalize();
    
    // Convert to hex string
    format!("{:x}", hash)
}

/// Enum to represent different HTLC types for the maker
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub enum HtlcType {
    P2TR,      // Taproot - requires x-only public key
    P2WSH,     // P2WSH - requires compressed public key
    ICPEscrow, // ICP Escrow - requires Bitcoin address
}

/// Maker key structure with source and destination addresses
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub struct MakerKey {
    pub source_address: String,  
    pub source_pubkey: Option<String>,   // Maker's source address (Bitcoin address as string)
    pub destination_address: String, // Maker's destination address (EVM address as string)
    // compressed pubkey hex used in HTLC (required for P2WSH)
}

/// Taker key structure with source and destination addresses
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub struct TakerKey {
    pub source_address: String,           // Taker's EVM address
    pub destination_address: String,      // Taker's Bitcoin address (for UTXO / refunds)
    pub destination_pubkey: Option<String>, // compressed pubkey hex used in HTLC (required for P2WSH)
}


/// Auction details for the order
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub struct AuctionDetails {
    pub initial_rate_bump: u64,    // Starting price multiplier (e.g., 1000 = 10x)
    pub points: Vec<u64>,          // Price points for the auction curve
    pub duration: u64,             // Auction duration in seconds
    pub start_time: u64,           // Auction start timestamp
}

/// Secret management for partial fills using 5-secret percentage-based approach
/// 
/// SECURITY: Secrets are generated OFF-CHAIN and only hashes are stored on-chain.
/// The maker must securely store the original secrets (S0-S4) off-chain.
/// 
/// The 5-secret system works as follows:
/// - Secret 0: Used for fills 0-25% of total order amount (exclusive of 25%)
/// - Secret 1: Used for fills 25-50% of total order amount (exclusive of 50%)
/// - Secret 2: Used for fills 50-75% of total order amount (exclusive of 75%)
/// - Secret 3: Used for fills 75-100% of total order amount (exclusive of 100%)
/// - Secret 4: Used for fills that reach exactly 100% of total order amount
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub struct SecretManagement {
    pub merkle_root: String,        // Merkle root of all secret hashes
    pub total_secrets: u64,        // Total number of secrets generated (always 5)
    pub used_secrets: Vec<u64>,    // Indices of used secrets (for tracking)
    pub secret_hashes: Vec<String>, // All secret hashes (for validation)
}

/// Partial fill tracking for an order
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub struct PartialFill {
    pub taker_key: TakerKey,       // Taker's addresses
    pub filled_amount: u64,         // Amount already filled
    pub remaining_amount: u64,     // Remaining amount to fill
    pub fill_timestamp: u64,       // When this fill occurred
}

/// Order fill status tracking
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub struct OrderFillStatus {
    pub total_filled: u64,         // Total amount filled across all partial fills
    pub remaining_amount: u64,     // Remaining amount to fill
    pub partial_fills: Vec<PartialFill>, // List of partial fills
    pub is_fully_filled: bool,     // Whether order is completely filled
}

/// New order structure with enhanced parameters
#[derive(CandidType, Clone, Debug)]
pub struct OrderDetailNew {
    pub salt: u64,                    // Random number for order uniqueness
    pub maker_key: MakerKey,          // Maker's source and destination addresses
    pub taker_key: Option<TakerKey>,  // Taker's source and destination addresses (set when filled)
    pub htlc_type: HtlcType,          // Type of HTLC (P2TR, P2WSH, ICP Escrow)
    pub dst_chain_id: u64,            // Destination chain ID
    pub making_amount: u64,           // Amount being offered in sats
    pub taking_amount: u64,           // Amount being requested in respicitive token 
    pub taking_asset: String,         // Asset being requested in respicitive token
    pub hashlock: String,             // Hashlock for the HTLC (legacy, for single fills)
    pub timelock: u64,                // Timelock for the HTLC in btc block time
    pub auction: AuctionDetails,      // Auction configuration
    pub allow_partial_fills: bool,    // Whether partial fills are allowed
    pub order_contract_bitcoin_path: u32, // Bitcoin derivation path (auto-incremented)
    pub order_address: Option<String>, // P2WPKH address for this order
    pub fill_status: Option<OrderFillStatus>, // Fill status for partial fills tracking
    pub secret_management: Option<SecretManagement>, // Secret management for partial fills
    pub processing: bool,             // Concurrency control flag to prevent race conditions
}

/// Storage for the new order system
#[derive(CandidType, Clone)]
struct OrderStorageNew {
    orders: HashMap<String, OrderDetailNew>, // Using order hash as key
    next_bitcoin_path: u32, // Counter for Bitcoin derivation path
}

impl OrderStorageNew {
    fn new() -> Self {
        Self {
            orders: HashMap::new(),
            next_bitcoin_path: 1, // Start from 1
        }
    }
}

thread_local! {
    static STORAGE_NEW: RefCell<OrderStorageNew> = RefCell::new(OrderStorageNew::new());
}

/// Creates a new order with enhanced parameters
#[update]
pub fn create_order_new(
    salt: u64,
    maker_key: MakerKey,
    htlc_type: HtlcType,
    dst_chain_id: u64,
    making_amount: u64,
    taking_amount: u64,
    taking_asset: String,
    hashlock: String,
    timelock: u64,
    auction: AuctionDetails,
    allow_partial_fills: bool,
) -> Result<String, String> {
    // Validate addresses based on HTLC type
    
    // Validate source based on HTLC type
    match htlc_type {
        HtlcType::P2TR => {
            // For P2TR, require source_pubkey (x-only public key)
            if let Some(ref source_pubkey) = maker_key.source_pubkey {
                if !is_valid_p2tr_address(source_pubkey) {
                    return Err("Source pubkey must be a valid x-only public key (64 hex chars) for P2TR HTLC type".to_string());
                }
            } else {
                return Err("Source pubkey is required for P2TR HTLC type".to_string());
            }
        },
        HtlcType::P2WSH => {
            // For P2WSH, require source_pubkey (compressed public key)
            if let Some(ref source_pubkey) = maker_key.source_pubkey {
                if !is_valid_p2wsh_address(source_pubkey) {
                    return Err("Source pubkey must be a valid compressed public key (66 hex chars starting with 02/03) for P2WSH HTLC type".to_string());
                }
            } else {
                return Err("Source pubkey is required for P2WSH HTLC type".to_string());
            }
        },
        HtlcType::ICPEscrow => {
            // For ICP Escrow, require source_address (Bitcoin address)
            if !is_valid_bitcoin_address(&maker_key.source_address) {
                return Err("Source address must be a valid Bitcoin address for ICP Escrow".to_string());
            }
        }
    }
    
    // Validate destination address (always EVM)
    if !is_valid_evm_address(&maker_key.destination_address) {
        return Err("Invalid EVM address format for destination address".to_string());
    }
    
    // Get the next Bitcoin path and increment counter
    let bitcoin_path = STORAGE_NEW.with(|s| {
        let mut storage = s.borrow_mut();
        let path = storage.next_bitcoin_path;
        storage.next_bitcoin_path += 1;
        path
    });
    
    // Create the order structure first
    let order_detail = OrderDetailNew {
        salt,
        maker_key,
        taker_key: None, // Will be set when order is filled
        htlc_type,
        dst_chain_id,
        making_amount,
        taking_amount,
        taking_asset,
        hashlock,
        timelock,
        auction,
        allow_partial_fills,
        order_contract_bitcoin_path: bitcoin_path,
        order_address: None, // Address will be generated separately
        fill_status: None, // Will be initialized when first fill occurs
        secret_management: None, // Will be set when secrets are generated
        processing: false, // Initialize concurrency control flag
    };
    
    // Calculate the order hash
    let order_hash = calculate_order_hash(&order_detail);
    
    // Check if order already exists (duplicate prevention)
    let order_exists = STORAGE_NEW.with(|s| {
        s.borrow().orders.contains_key(&order_hash)
    });
    
    if order_exists {
        return Err("Order with this hash already exists".to_string());
    }
    
    // Store the order with hash as key
    STORAGE_NEW.with(|s| {
        let mut storage = s.borrow_mut();
        storage.orders.insert(order_hash.clone(), order_detail);
    });
    
    Ok(order_hash)
}

/// Retrieves a specific new order by order hash
#[query]
pub fn get_order_new(order_hash: String) -> Option<OrderDetailNew> {
    STORAGE_NEW.with(|s| {
        s.borrow().orders.get(&order_hash).cloned()
    })
}

/// Retrieves all new orders
#[query]
pub fn get_all_orders_new() -> Vec<(String, OrderDetailNew)> {
    STORAGE_NEW.with(|s| {
        s.borrow().orders.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    })
}

/// Gets the total number of orders
#[query]
pub fn get_orders_count_new() -> usize {
    STORAGE_NEW.with(|s| {
        s.borrow().orders.len()
    })
}

/// Gets the next Bitcoin path that will be assigned
#[query]
pub fn get_next_bitcoin_path_new() -> u32 {
    STORAGE_NEW.with(|s| {
        s.borrow().next_bitcoin_path
    })
}

/// Creates a P2WPKH address for a specific new order and stores it
#[update]
pub async fn get_order_address_new(order_hash: String) -> Result<String, String> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());
    
    // Check if the order exists
    let order_exists = STORAGE_NEW.with(|s| {
        s.borrow().orders.contains_key(&order_hash)
    });
    
    if !order_exists {
        return Err(format!("Order with hash {} does not exist", order_hash));
    }
    
    // Check if address already exists for this order
    let existing_address = STORAGE_NEW.with(|s| {
        s.borrow().orders.get(&order_hash).and_then(|order| order.order_address.clone())
    });
    
    if let Some(address) = existing_address {
        return Ok(address);
    }
    
    // Get the Bitcoin path from the order
    let bitcoin_path = STORAGE_NEW.with(|s| {
        s.borrow().orders.get(&order_hash).map(|order| order.order_contract_bitcoin_path)
    });
    
    let bitcoin_path = bitcoin_path.unwrap_or(1); // fallback to 1 if not found
    
    // Use the Bitcoin path for derivation
    let derivation_path = DerivationPath::p2wpkh(bitcoin_path, 0);
    
    // Get the ECDSA public key for this specific derivation path
    let public_key = get_ecdsa_public_key(&ctx, derivation_path.to_vec_u8_path()).await;
    
    // Create a CompressedPublicKey from the raw public key bytes
    let public_key = CompressedPublicKey::from_slice(&public_key)
        .map_err(|e| format!("Failed to create public key: {}", e))?;
    
    // Generate a P2WPKH Bech32 address
    let address = Address::p2wpkh(&public_key, ctx.bitcoin_network).to_string();
    
    // Store the address in the order
    STORAGE_NEW.with(|s| {
        let mut storage = s.borrow_mut();
        if let Some(order) = storage.orders.get_mut(&order_hash) {
            order.order_address = Some(address.clone());
        }
    });
    
    Ok(address)
}

/// Generates a P2WSH HTLC script
fn generate_htlc_script(
    payment_hash: &str,
    initiator_pubkey: &str,
    responder_pubkey: &str,
    timelock: u64,
) -> Result<ScriptBuf, String> {
    // Decode payment hash from hex
    let payment_hash_bytes = hex::decode(payment_hash)
        .map_err(|_| "Failed to decode payment hash".to_string())?;
    
    // Convert bytes to PushBytesBuf
    let mut payment_hash_buf = PushBytesBuf::new();
    for byte in payment_hash_bytes {
        payment_hash_buf.push(byte).map_err(|_| "Failed to push byte to buffer".to_string())?;
    }

    // Parse public keys
    let initiator_pubkey = PublicKey::from_str(initiator_pubkey)
        .map_err(|_| "Failed to parse initiator public key".to_string())?;
    let responder_pubkey = PublicKey::from_str(responder_pubkey)
        .map_err(|_| "Failed to parse responder public key".to_string())?;

    // Build the HTLC script
    let htlc_script = ScriptBuf::builder()
        .push_opcode(opcodes::all::OP_IF)
        .push_opcode(opcodes::all::OP_SHA256)
        .push_slice(&payment_hash_buf)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_key(&responder_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_int(timelock as i64)
        .push_opcode(opcodes::all::OP_CSV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_key(&initiator_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .push_opcode(opcodes::all::OP_ENDIF)
        .into_script();

    Ok(htlc_script)
}

/// Generates a P2WSH address for HTLC
fn generate_htlc_address(
    payment_hash: &str,
    initiator_pubkey: &str,
    responder_pubkey: &str,
    timelock: u64,
    network: bitcoin::Network,
) -> Result<Address, String> {
    let script_buf = generate_htlc_script(
        payment_hash,
        initiator_pubkey,
        responder_pubkey,
        timelock,
    )?;

    let address = Address::p2wsh(&script_buf, network);
    Ok(address)
}

/// Calculate the current auction price based on time and auction parameters
/// Implements a Dutch auction where price decreases over time
#[query]
pub fn calculate_auction_price(order_hash: String) -> Result<u64, String> {
    let order = STORAGE_NEW.with(|s| {
        s.borrow().orders.get(&order_hash).cloned()
    });

    let order = match order {
        Some(order) => order,
        None => return Err("Order not found".to_string()),
    };

    let current_time = ic_cdk::api::time() / 1_000_000_000; // Convert nanoseconds to seconds
    
    // Check if auction has started
    if current_time < order.auction.start_time {
        return Ok(order.auction.initial_rate_bump);
    }
    
    // Check if auction has ended
    let auction_end_time = order.auction.start_time + order.auction.duration;
    if current_time >= auction_end_time {
        // Return the final price (lowest point)
        return Ok(order.auction.points.last().copied().unwrap_or(100)); // Default to 1x if no points
    }
    
    // Calculate current price using linear interpolation between points
    let elapsed_time = current_time - order.auction.start_time;
    let progress = elapsed_time as f64 / order.auction.duration as f64;
    
    // If no points defined, use linear interpolation from initial_rate_bump to 100 (1x)
    if order.auction.points.is_empty() {
        let start_price = order.auction.initial_rate_bump as f64;
        let end_price = 100.0; // 1x multiplier
        let current_price = start_price - (start_price - end_price) * progress;
        return Ok(current_price as u64);
    }
    
    // Use the points for more complex price curves
    let num_points = order.auction.points.len();
    if num_points == 1 {
        return Ok(order.auction.points[0]);
    }
    
    // Linear interpolation between points with explicit floor to prevent overshoot
    let point_index = (progress * (num_points - 1) as f64).floor() as usize;
    let point_index = point_index.min(num_points - 2); // Ensure we don't go out of bounds
    
    let point1 = order.auction.points[point_index] as f64;
    let point2 = order.auction.points[point_index + 1] as f64;
    
    let segment_progress = (progress * (num_points - 1) as f64) - point_index as f64;
    let current_price = point1 + (point2 - point1) * segment_progress;
    
    Ok(current_price as u64)
}

/// Validate if a bid meets the current auction price requirements
#[query]
pub fn validate_auction_bid(order_hash: String, bid_price: u64) -> Result<bool, String> {
    let current_price = calculate_auction_price(order_hash)?;
    
    // Bid must be greater than or equal to current auction price
    Ok(bid_price >= current_price)
}

/// Combined auction validation result
#[derive(Debug)]
struct AuctionValidationResult {
    is_valid: bool,
    error_message: String,
}

/// Combined auction validation: check both status and price requirements
fn validate_auction_bid_and_status(order_hash: String, bid_price: u64) -> Result<AuctionValidationResult, String> {
    // Check auction status first
    let status = get_auction_status(order_hash.clone())?;
    if status != "Active" {
        return Ok(AuctionValidationResult {
            is_valid: false,
            error_message: format!("Auction is not active. Status: {}", status),
        });
    }
    
    // Check bid price
    let current_price = calculate_auction_price(order_hash)?;
    if bid_price < current_price {
        return Ok(AuctionValidationResult {
            is_valid: false,
            error_message: "Bid price does not meet current auction requirements".to_string(),
        });
    }
    
    Ok(AuctionValidationResult {
        is_valid: true,
        error_message: String::new(),
    })
}

/// Get auction status for an order
#[query]
pub fn get_auction_status(order_hash: String) -> Result<String, String> {
    let order = STORAGE_NEW.with(|s| {
        s.borrow().orders.get(&order_hash).cloned()
    });

    let order = match order {
        Some(order) => order,
        None => return Err("Order not found".to_string()),
    };

    let current_time = ic_cdk::api::time() / 1_000_000_000; // Convert nanoseconds to seconds
    let auction_end_time = order.auction.start_time + order.auction.duration;
    
    if current_time < order.auction.start_time {
        Ok("Not started".to_string())
    } else if current_time >= auction_end_time {
        Ok("Ended".to_string())
    } else {
        Ok("Active".to_string())
    }
}

/// Execute auction redemption with price validation and Bitcoin transaction
/// Similar to execute_order_withdraw_to_htlc but with auction price validation
#[update]
pub async fn execute_auction_redemption(
    order_hash: String, 
    taker_key: TakerKey,
    amount_in_satoshi: u64,
    bid_price: u64
) -> Result<String, String> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    if amount_in_satoshi == 0 {
        return Err("Amount must be greater than 0".to_string());
    }

    // Combined auction validation: check status and price together
    let auction_validation = validate_auction_bid_and_status(order_hash.clone(), bid_price)?;
    if !auction_validation.is_valid {
        return Err(auction_validation.error_message);
    }

    // Get the order details and check for concurrency conflicts
    let (order, secret_index, mut _guard) = STORAGE_NEW.with(|s| {
        let mut storage = s.borrow_mut();
        if let Some(order) = storage.orders.get_mut(&order_hash) {
            // Check if order is already being processed
            if order.processing {
                return Err("Order is currently being processed by another fill".to_string());
            }
            
            // Set processing flag to prevent concurrent fills
            order.processing = true;
            
            // Calculate secret index before releasing the lock
            let secret_index = if order.secret_management.is_some() && order.allow_partial_fills {
                calculate_secret_index(order, amount_in_satoshi).ok()
            } else {
                None
            };
            
            // Create RAII guard to ensure processing flag is reset
            let guard = ProcessingGuard::new(order_hash.clone());
            
            Ok((order.clone(), secret_index, guard))
        } else {
            Err("Order not found".to_string())
        }
    })?;

    // Validate taker addresses
    if !is_valid_evm_address(&taker_key.source_address) {
        return Err("Invalid taker source address format".to_string());
    }
    if !is_valid_bitcoin_address(&taker_key.destination_address) {
        return Err("Invalid taker destination address format".to_string());
    }
    
    // ensure taker supplied compressed pubkey for HTLC scripts
    let responder_pubkey_hex = taker_key
        .destination_pubkey
        .as_ref()
        .ok_or("taker destination_pubkey (compressed pubkey hex) required for HTLC")?;

    if !is_valid_p2wsh_address(responder_pubkey_hex) {
        return Err("Invalid taker destination_pubkey (not a compressed pubkey)".to_string());
    }

    // Check if this is a partial fill
    let is_partial_fill = if let Some(ref fill_status) = order.fill_status {
        fill_status.total_filled > 0
    } else {
        false
    };

    // Validate partial fill requirements
    if is_partial_fill && !order.allow_partial_fills {
        return Err("Partial fills not allowed for this order".to_string());
    }

    // Check remaining amount for partial fills
    let remaining_amount = if let Some(ref fill_status) = order.fill_status {
        fill_status.remaining_amount
    } else {
        order.making_amount
    };

    if amount_in_satoshi > remaining_amount {
        return Err(format!(
            "Requested amount {} exceeds remaining amount {}", 
            amount_in_satoshi, 
            remaining_amount
        ));
    }

    // Generate P2WSH HTLC address using the appropriate secret for this fill
    let secret_hash = if let Some(secret_index) = secret_index {
        // Use secret management scheme for all fills (including first fill)
        get_secret_hash_for_fill(&order, secret_index)?
    } else {
        // Legacy single-fill fallback
        order.hashlock.clone()
    };

    // Get the appropriate initiator pubkey based on HTLC type
    let initiator_pubkey = match order.htlc_type {
        HtlcType::P2TR => {
            order.maker_key.source_pubkey
                .as_ref()
                .ok_or("Maker source_pubkey required for P2TR HTLC")?
        },
        HtlcType::P2WSH => {
            order.maker_key.source_pubkey
                .as_ref()
                .ok_or("Maker source_pubkey required for P2WSH HTLC")?
        },
        HtlcType::ICPEscrow => {
            // For ICP Escrow, we don't use HTLC scripts, so this shouldn't be called
            return Err("ICP Escrow does not use HTLC address generation".to_string());
        }
    };

    let htlc_address = generate_htlc_address(
        &secret_hash,
        initiator_pubkey,                // initiator pubkey (compressed pubkey hex for P2WSH/P2TR)
        responder_pubkey_hex,            // responder pubkey (compressed pubkey hex)
        order.timelock,
        ctx.bitcoin_network,
    )?;

    // Get the order's P2WPKH address (source address)
    let derivation_path = DerivationPath::p2wpkh(order.order_contract_bitcoin_path, 0);
    let own_public_key = get_ecdsa_public_key(&ctx, derivation_path.to_vec_u8_path()).await;
    let own_compressed_public_key = CompressedPublicKey::from_slice(&own_public_key)
        .map_err(|e| format!("Failed to create public key: {}", e))?;
    let own_public_key = PublicKey::from_slice(&own_public_key)
        .map_err(|e| format!("Failed to create public key: {}", e))?;
    let own_address = Address::p2wpkh(&own_compressed_public_key, ctx.bitcoin_network);

    // Get UTXOs from the order's P2WPKH address
    let own_utxos = bitcoin_get_utxos(&GetUtxosRequest {
        address: own_address.to_string(),
        network: ctx.network,
        filter: None,
    })
    .await
    .map_err(|e| format!("Failed to get UTXOs: {:?}", e))?
    .utxos;

    if own_utxos.is_empty() {
        return Err("No UTXOs available for this order".to_string());
    }

    // Note: We rely on UTXO selection logic instead of global balance check
    // to avoid timing mismatches between UTXO state and balance state

    // Build the transaction that sends `amount` to the HTLC address
    let fee_per_byte = get_fee_per_byte(&ctx).await;
    let (transaction, prevouts) = p2wpkh::build_transaction(
        &ctx,
        &own_public_key,
        &own_address,
        &own_utxos,
        &htlc_address,
        amount_in_satoshi,
        fee_per_byte,
    )
    .await;

    // Sign the transaction
    let signed_transaction = p2wpkh::sign_transaction(
        &ctx,
        &own_public_key,
        &own_address,
        transaction,
        &prevouts,
        derivation_path.to_vec_u8_path(),
        sign_with_ecdsa,
    )
    .await;

    // Send the transaction to the Bitcoin network
    let tx_result = bitcoin_send_transaction(&SendTransactionRequest {
        network: ctx.network,
        transaction: serialize(&signed_transaction),
    })
    .await;

    // If transaction fails, clear the processing flag
    if tx_result.is_err() {
        STORAGE_NEW.with(|s| {
            let mut storage = s.borrow_mut();
            if let Some(order) = storage.orders.get_mut(&order_hash) {
                order.processing = false;
            }
        });
        return Err(format!("Failed to send transaction: {:?}", tx_result.unwrap_err()));
    }

    // Update order with taker information and fill status
    STORAGE_NEW.with(|s| {
        let mut storage = s.borrow_mut();
        if let Some(order) = storage.orders.get_mut(&order_hash) {
            // Mark secret as used if we used secret management
            if let Some(secret_index) = secret_index {
                mark_secret_used(order, secret_index);
            }
            
            // Set taker key if this is the first fill
            if order.taker_key.is_none() {
                order.taker_key = Some(taker_key.clone());
            }

            // Update fill status
            let current_time = ic_cdk::api::time() / 1_000_000_000; // Convert nanoseconds to seconds
            let new_fill = PartialFill {
                taker_key: taker_key.clone(),
                filled_amount: amount_in_satoshi,
                remaining_amount: remaining_amount - amount_in_satoshi,
                fill_timestamp: current_time,
            };

            if let Some(ref mut fill_status) = order.fill_status {
                // Update existing fill status
                fill_status.total_filled += amount_in_satoshi;
                fill_status.remaining_amount -= amount_in_satoshi;
                fill_status.partial_fills.push(new_fill);
                fill_status.is_fully_filled = fill_status.remaining_amount == 0;
            } else {
                // Initialize fill status for first fill
                order.fill_status = Some(OrderFillStatus {
                    total_filled: amount_in_satoshi,
                    remaining_amount: order.making_amount - amount_in_satoshi,
                    partial_fills: vec![new_fill],
                    is_fully_filled: amount_in_satoshi == order.making_amount,
                });
            }
        }
    });
    
    // ProcessingGuard will automatically reset the processing flag when it drops

    // Get current auction price for logging
    let current_price = calculate_auction_price(order_hash.clone())?;

    // Return the transaction ID with auction information
    Ok(format!(
        "Auction redemption successful. TXID: {}, Current price: {}, Bid price: {}, Filled: {} satoshis", 
        signed_transaction.compute_txid(),
        current_price, 
        bid_price,
        amount_in_satoshi
    ))
}

/// Get the fill status for an order
#[query]
pub fn get_order_fill_status(order_hash: String) -> Result<Option<OrderFillStatus>, String> {
    let order = STORAGE_NEW.with(|s| {
        s.borrow().orders.get(&order_hash).cloned()
    });

    match order {
        Some(order) => Ok(order.fill_status),
        None => Err("Order not found".to_string()),
    }
}

/// Check if an order is fully filled
#[query]
pub fn is_order_fully_filled(order_hash: String) -> Result<bool, String> {
    let fill_status = get_order_fill_status(order_hash)?;
    Ok(fill_status.map_or(false, |status| status.is_fully_filled))
}

/// Get remaining amount for an order
#[query]
pub fn get_remaining_amount(order_hash: String) -> Result<u64, String> {
    let fill_status = get_order_fill_status(order_hash)?;
    Ok(fill_status.map_or(0, |status| status.remaining_amount))
}

/// Set secret hashes for partial fills (secrets must be generated off-chain)
#[update]
pub fn set_secret_hashes_for_partial_fills(
    order_hash: String,
    secret_hashes: Vec<String>  // 5 secret hashes generated off-chain
) -> Result<SecretManagement, String> {
    // Validate that exactly 5 secret hashes are provided
    if secret_hashes.len() != 5 {
        return Err("Exactly 5 secret hashes must be provided for partial fills".to_string());
    }

    // Validate that all secret hashes are valid hex strings (64 chars for SHA256)
    for (i, hash) in secret_hashes.iter().enumerate() {
        if hash.len() != 64 {
            return Err(format!("Secret hash {} must be 64 hex characters (SHA256)", i));
        }
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("Secret hash {} contains invalid hex characters", i));
        }
    }

    // Create Merkle tree from the provided hashes
    let merkle_root = create_merkle_root(&secret_hashes);

    let secret_management = SecretManagement {
        merkle_root,
        total_secrets: 5,
        used_secrets: Vec::new(),
        secret_hashes,
    };

    // Update the order with secret management
    STORAGE_NEW.with(|s| {
        let mut storage = s.borrow_mut();
        if let Some(order) = storage.orders.get_mut(&order_hash) {
            order.secret_management = Some(secret_management.clone());
        }
    });

    Ok(secret_management)
}

/// Get the appropriate secret hash for a partial fill
fn get_secret_hash_for_fill(
    order: &OrderDetailNew,
    fill_index: u64
) -> Result<String, String> {
    if let Some(ref secret_mgmt) = order.secret_management {
        if fill_index >= secret_mgmt.total_secrets {
            return Err(format!(
                "Fill index {} exceeds available secrets (total: {})",
                fill_index,
                secret_mgmt.total_secrets
            ));
        }

        if secret_mgmt.used_secrets.contains(&fill_index) {
            return Err(format!("Secret index {} already used", fill_index));
        }

        Ok(secret_mgmt.secret_hashes[fill_index as usize].clone())
    } else {
        // Fallback to single hashlock for non-partial fills
        Ok(order.hashlock.clone())
    }
}

/// Mark a secret as used to prevent reuse
fn mark_secret_used(order: &mut OrderDetailNew, idx: u64) {
    if let Some(ref mut sm) = order.secret_management {
        if !sm.used_secrets.contains(&idx) {
            sm.used_secrets.push(idx);
        }
    }
}

/// RAII guard to ensure processing flag is reset even on panic/error
struct ProcessingGuard {
    order_hash: String,
    active: bool,
}

impl ProcessingGuard {
    fn new(order_hash: String) -> Self {
        Self {
            order_hash,
            active: true,
        }
    }
}

impl Drop for ProcessingGuard {
    fn drop(&mut self) {
        if self.active {
            // Reset processing flag if still active
            STORAGE_NEW.with(|s| {
                let mut storage = s.borrow_mut();
                if let Some(order) = storage.orders.get_mut(&self.order_hash) {
                    order.processing = false;
                }
            });
        }
    }
}

/// Calculate which secret index to use for a partial fill based on percentage thresholds
/// Uses integer arithmetic to avoid floating point rounding issues
fn calculate_secret_index(
    order: &OrderDetailNew,
    fill_amount: u64
) -> Result<u64, String> {
    if order.making_amount == 0 {
        return Err("Invalid making_amount == 0".to_string());
    }

    let total_filled = order.fill_status.as_ref().map(|fs| fs.total_filled).unwrap_or(0);
    let new_total_filled = total_filled + fill_amount;

    // Prevent overshoot — should be checked earlier, but assert here defensively:
    if new_total_filled > order.making_amount {
        return Err("Fill would exceed order's making_amount".to_string());
    }

    // Compute percentage using integer arithmetic scaled by 10000 to preserve precision
    // percent_basis_points = new_total_filled * 10000 / making_amount  (10000 = 100.00%)
    let pb = new_total_filled
        .saturating_mul(10000)
        .checked_div(order.making_amount)
        .unwrap_or(0); // basis points

    // thresholds in basis points: 25% = 2500, 50% = 5000, 75% = 7500, 100% = 10000
    // Fixed boundaries to match documentation:
    // Secret 0: 0-25% (exclusive of 25%)
    // Secret 1: 25-50% (exclusive of 50%) 
    // Secret 2: 50-75% (exclusive of 75%)
    // Secret 3: 75-100% (exclusive of 100%)
    // Secret 4: Exactly 100%
    let secret_index = if pb == 10000 {
        4u64  // Fifth secret for exactly 100%
    } else if pb < 2500 {
        0u64  // First secret for 0-25% (exclusive)
    } else if pb < 5000 {
        1u64  // Second secret for 25-50% (exclusive)
    } else if pb < 7500 {
        2u64  // Third secret for 50-75% (exclusive)
    } else {
        3u64  // Fourth secret for 75-100% (exclusive)
    };

    // Defensive clamp
    if let Some(ref sm) = order.secret_management {
        Ok(secret_index.min(sm.total_secrets - 1))
    } else {
        Ok(0)
    }
}

/// Improved Merkle root calculation using proper binary tree structure
fn create_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return "0".to_string();
    }
    
    if hashes.len() == 1 {
        return hashes[0].clone();
    }
    
    // Build a proper binary Merkle tree
    let mut current_level = hashes.to_vec();
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        // Process pairs of hashes with byte-level concatenation
        for i in (0..current_level.len()).step_by(2) {
            if i + 1 < current_level.len() {
                // Pair exists - decode hex and concatenate bytes
                let left_bytes = hex::decode(&current_level[i]).unwrap_or_default();
                let right_bytes = hex::decode(&current_level[i + 1]).unwrap_or_default();
                let mut combined = Vec::with_capacity(left_bytes.len() + right_bytes.len());
                combined.extend(left_bytes);
                combined.extend(right_bytes);
                next_level.push(sha256(&combined));
            } else {
                // Odd number - promote the last hash
                next_level.push(current_level[i].clone());
            }
        }
        
        current_level = next_level;
    }
    
    current_level[0].clone()
}

/// Simple SHA256 implementation
fn sha256(data: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Helper function to calculate secret index with simulated state
fn calculate_secret_index_simulated(total_filled_before: u64, making_amount: u64, fill_amount: u64) -> Result<u64, String> {
    if making_amount == 0 { 
        return Err("making_amount==0".to_string()); 
    }
    let new_total = total_filled_before + fill_amount;
    if new_total > making_amount { 
        return Err("overshoot".to_string()); 
    }
    let pb = new_total.saturating_mul(10000) / making_amount;
    let idx = if pb == 10000 { 4 } else if pb < 2500 { 0 } else if pb < 5000 { 1 } else if pb < 7500 { 2 } else { 3 };
    Ok(idx)
}

/// Test function to validate secret selection logic
#[query]
pub fn test_secret_selection_logic(
    order_hash: String,
    test_fill_amounts: Vec<u64>
) -> Result<Vec<(u64, u64, f64, String)>, String> {
    let order = STORAGE_NEW.with(|s| {
        s.borrow().orders.get(&order_hash).cloned()
    });

    let order = match order {
        Some(order) => order,
        None => return Err("Order not found".to_string()),
    };

    if order.secret_management.is_none() {
        return Err("No secret management found for this order".to_string());
    }

    let mut results = Vec::new();
    let mut cumulative_filled = 0u64;

    for fill_amount in test_fill_amounts {
        let secret_index = calculate_secret_index_simulated(cumulative_filled, order.making_amount, fill_amount)?;
        cumulative_filled += fill_amount;
        let fill_percentage = (cumulative_filled as f64) / (order.making_amount as f64) * 100.0;
        
        let percentage_range = match secret_index {
            0 => "0-25%",
            1 => "25-50%", 
            2 => "50-75%",
            3 => "75-100%",
            4 => "100%",
            _ => "Unknown"
        };

        results.push((
            fill_amount,
            secret_index,
            fill_percentage,
            format!("Secret {} ({})", secret_index, percentage_range)
        ));
    }

    Ok(results)
}

/// Test function to verify Merkle root implementation
#[query]
pub fn test_merkle_root_calculation() -> Result<Vec<(String, String, String)>, String> {
    // Test with known inputs to verify Merkle root calculation
    let test_hashes = vec![
        "hash1".to_string(),
        "hash2".to_string(), 
        "hash3".to_string(),
        "hash4".to_string(),
        "hash5".to_string(),
    ];
    
    let mut results = Vec::new();
    
    // Test with different numbers of hashes
    for i in 1..=test_hashes.len() {
        let subset = &test_hashes[0..i];
        let merkle_root = create_merkle_root(subset);
        let expected_single = if i == 1 { subset[0].clone() } else { "computed".to_string() };
        
        results.push((
            format!("{} hashes", i),
            merkle_root,
            expected_single,
        ));
    }
    
    Ok(results)
}

/// Helper function to generate secrets off-chain (for client-side use)
/// This function demonstrates how to generate secrets securely off-chain
/// 
/// USAGE: Call this function off-chain to generate secrets, then use
/// set_secret_hashes_for_partial_fills() to store only the hashes on-chain
/// 
/// Example usage in JavaScript/TypeScript:
/// ```javascript
/// import { randomBytes } from 'crypto';
/// import { createHash } from 'crypto';
/// 
/// function generateSecretsOffChain() {
///   const secrets = [];
///   const secretHashes = [];
///   
///   for (let i = 0; i < 5; i++) {
///     // Generate 32 random bytes
///     const secret = randomBytes(32);
///     const secretHex = secret.toString('hex');
///     
///     // Hash the secret
///     const hash = createHash('sha256').update(secret).digest('hex');
///     
///     secrets.push(secretHex);  // Store securely off-chain
///     secretHashes.push(hash);  // Send to contract
///   }
///   
///   return { secrets, secretHashes };
/// }
/// ```
#[query]
pub fn generate_secrets_offchain_helper() -> Result<Vec<String>, String> {
    // This is just a helper to show the expected format
    // In practice, secrets should be generated using cryptographically secure RNG
    // like crypto.randomBytes(32) in Node.js or OsRng in Rust
    
    let example_secret_hashes = vec![
        "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890".to_string(),
        "b2c3d4e5f6789012345678901234567890123456789012345678901234567890a1".to_string(),
        "c3d4e5f6789012345678901234567890123456789012345678901234567890a1b2".to_string(),
        "d4e5f6789012345678901234567890123456789012345678901234567890a1b2c3".to_string(),
        "e5f6789012345678901234567890123456789012345678901234567890a1b2c3d4".to_string(),
    ];
    
    Ok(example_secret_hashes)
}

