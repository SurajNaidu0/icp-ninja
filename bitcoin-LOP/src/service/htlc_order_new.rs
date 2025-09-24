use candid::CandidType;
use ic_cdk::{query, update};
use std::cell::RefCell;
use std::collections::HashMap;
use crate::{common::DerivationPath, ecdsa::get_ecdsa_public_key, BTC_CONTEXT};
use bitcoin::{Address, CompressedPublicKey, PublicKey, XOnlyPublicKey};
use sha2::{Sha256, Digest};
use std::str::FromStr;

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
    pub source_address: String,      // Maker's source address (Bitcoin address as string)
    pub destination_address: String, // Maker's destination address (EVM address as string)
}


/// Auction details for the order
#[derive(CandidType, Clone, Debug, serde::Deserialize)]
pub struct AuctionDetails {
    pub initial_rate_bump: u64,
    pub points: Vec<u64>,
    pub duration: u64,
    pub start_time: u64,
}

/// New order structure with enhanced parameters
#[derive(CandidType, Clone, Debug)]
pub struct OrderDetailNew {
    pub salt: u64,                    // Random number for order uniqueness
    pub maker_key: MakerKey,          // Maker's source and destination addresses
    pub htlc_type: HtlcType,          // Type of HTLC (P2TR, P2WSH, ICP Escrow)
    pub dst_chain_id: u64,            // Destination chain ID
    pub making_amount: u64,           // Amount being offered in sats
    pub taking_amount: u64,           // Amount being requested in respicitive token 
    pub taking_asset: String,         // Asset being requested in respicitive token
    pub hashlock: String,             // Hashlock for the HTLC
    pub timelock: u64,                // Timelock for the HTLC
    pub auction: AuctionDetails,      // Auction configuration
    pub allow_partial_fills: bool,    // Whether partial fills are allowed
    pub order_contract_bitcoin_path: u32, // Bitcoin derivation path (auto-incremented)
    pub order_address: Option<String>, // P2WPKH address for this order
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
    // Validate addresses - source is always Bitcoin, destination is always EVM
    
    // Validate source address (always Bitcoin)
    match htlc_type {
        HtlcType::P2TR => {
            if !is_valid_p2tr_address(&maker_key.source_address) {
                return Err("Source address must be a valid x-only public key (64 hex chars) for P2TR HTLC type".to_string());
            }
        },
        HtlcType::P2WSH => {
            if !is_valid_p2wsh_address(&maker_key.source_address) {
                return Err("Source address must be a valid compressed public key (66 hex chars starting with 02/03) for P2WSH HTLC type".to_string());
            }
        },
        HtlcType::ICPEscrow => {
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

