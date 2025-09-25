mod brc20;
mod common;
mod ecdsa;
mod ordinals;
mod p2pkh;
mod p2tr;
mod p2wpkh;
mod runes;
mod schnorr;
mod service;

use ic_cdk::{bitcoin_canister::Network, init, post_upgrade};
use std::cell::Cell;

/// Runtime configuration shared across all Bitcoin-related operations.
///
/// This struct carries network-specific context:
/// - `network`: The ICP Bitcoin API network enum.
/// - `bitcoin_network`: The corresponding network enum from the `bitcoin` crate, used
///   for address formatting and transaction construction.
/// - `key_name`: The global ECDSA key name used when requesting derived keys or making
///   signatures. Different key names are used locally and when deployed on the IC.
///
/// Note: Both `network` and `bitcoin_network` are needed because ICP and the
/// Bitcoin library use distinct network enum types.
#[derive(Clone, Copy)]
pub struct BitcoinContext {
    pub network: Network,
    pub bitcoin_network: bitcoin::Network,
    pub key_name: &'static str,
}

// Global, thread-local instance of the Bitcoin context.
// This is initialized at smart contract init/upgrade time and reused across all API calls.
thread_local! {
    static BTC_CONTEXT: Cell<BitcoinContext> = const {
        Cell::new(BitcoinContext {
            network: Network::Testnet,
            bitcoin_network: bitcoin::Network::Testnet,
            key_name: "test_key_1",
        })
    };
}

/// Internal shared init logic used both by init and post-upgrade hooks.
fn init_upgrade(network: Network) {
    let key_name = match network {
        Network::Regtest => "dfx_test_key",
        Network::Mainnet | Network::Testnet => "test_key_1",
    };

    let bitcoin_network = match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet,
        Network::Regtest => bitcoin::Network::Regtest,
    };

    BTC_CONTEXT.with(|ctx| {
        ctx.set(BitcoinContext {
            network,
            bitcoin_network,
            key_name,
        })
    });
}

/// Smart contract init hook.
/// Sets up the BitcoinContext based on the given IC Bitcoin network.
#[init]
pub fn init(network: Network) {
    init_upgrade(network);
}

/// Post-upgrade hook.
/// Reinitializes the BitcoinContext with the same logic as `init`.
#[post_upgrade]
fn upgrade(network: Network) {
    init_upgrade(network);
}

/// Input structure for sending Bitcoin.
/// Used across P2PKH, P2WPKH, and P2TR transfer endpoints.
#[derive(candid::CandidType, candid::Deserialize)]
pub struct SendRequest {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

// Re-export Order Protocol functionality
pub use service::htlc_orders::{
    create_order, get_order, get_all_orders, get_next_order_no, get_order_address, 
    execute_order_withdraw_to_htlc, preview_order_withdrawal, recover_order, OrderDetail, OrderWithdrawInfo
};

// Re-export New Order Protocol functionality
pub use service::htlc_order_new::{
    create_order_new, get_order_new, get_all_orders_new, get_orders_count_new, get_next_bitcoin_path_new, get_order_address_new,
    calculate_auction_price, validate_auction_bid, get_auction_status, execute_auction_redemption,
    get_order_fill_status, is_order_fully_filled, get_remaining_amount, generate_secrets_for_partial_fills, generate_p2tr_htlc_address_test,
    create_icp_escrow, redeem_icp_escrow, refund_icp_escrow, get_icp_escrow, get_icp_escrows_for_principal,
    OrderDetailNew, HtlcType, MakerKey, TakerKey, AuctionDetails, PartialFill, OrderFillStatus, SecretManagement, ICPEscrow as ICPEscrowRecord, ICPEscrowStatus
};
