# Bitcoin LOP Auction Mechanism Example

This document demonstrates how to use the auction mechanism in the Bitcoin LOP ICP contract.

## Overview

The auction mechanism allows makers to create orders with Dutch auction pricing, where the price decreases over time. Takers can only redeem orders if their bid meets the current auction price.

## Key Components

### 1. AuctionDetails Structure
```rust
pub struct AuctionDetails {
    pub initial_rate_bump: u64,    // Starting price multiplier (e.g., 1000 = 10x)
    pub points: Vec<u64>,          // Price points for the auction curve
    pub duration: u64,             // Auction duration in seconds
    pub start_time: u64,           // Auction start timestamp
}
```

### 2. Creating an Auction Order

```rust
// Example: Create an auction order
let auction_details = AuctionDetails {
    initial_rate_bump: 1500,  // Start at 15x price
    points: vec![1500, 1200, 900, 600, 300, 100], // Price curve points
    duration: 3600,           // 1 hour auction
    start_time: current_time + 300, // Start in 5 minutes
};

let order_hash = create_order_new(
    salt,
    maker_key,
    htlc_type,
    dst_chain_id,
    making_amount,
    taking_amount,
    taking_asset,
    hashlock,
    timelock,
    auction_details,
    allow_partial_fills
)?;
```

### 3. Checking Auction Status

```rust
// Check if auction is active
let status = get_auction_status(order_hash.clone())?;
// Returns: "Not started", "Active", or "Ended"
```

### 4. Getting Current Auction Price

```rust
// Get the current price for bidding
let current_price = calculate_auction_price(order_hash.clone())?;
// Returns the current price multiplier (e.g., 1200 = 12x)
```

### 5. Validating a Bid

```rust
// Check if a bid meets current requirements
let bid_price = 1100; // 11x multiplier
let is_valid = validate_auction_bid(order_hash.clone(), bid_price)?;
// Returns true if bid_price >= current_price
```

### 6. Executing Auction Redemption

```rust
// Execute redemption with price validation and Bitcoin transaction
let taker_key = TakerKey {
    source_address: "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6".to_string(), // Taker's EVM address
    destination_address: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(), // Taker's Bitcoin address
};

let result = execute_auction_redemption(
    order_hash,
    taker_key,         // Taker's source and destination addresses
    amount_in_satoshi, // Amount to send to HTLC
    bid_price         // Bid price for auction validation
).await?;
```

## Price Calculation Logic

The auction price decreases over time using linear interpolation:

1. **Before auction starts**: Returns `initial_rate_bump`
2. **During auction**: Linear interpolation between price points
3. **After auction ends**: Returns the final price point

### Example Price Curve

For an auction with:
- `initial_rate_bump: 1500` (15x)
- `points: [1500, 1200, 900, 600, 300, 100]`
- `duration: 3600` (1 hour)

The price will decrease from 15x to 1x over 1 hour, following the defined curve.

## Usage Flow

1. **Maker creates auction order** with desired price curve
2. **Takers monitor auction** using `get_auction_status()` and `calculate_auction_price()`
3. **Takers place bids** that meet current price requirements
4. **System validates bids** using `validate_auction_bid()`
5. **Successful takers execute redemption** using `execute_auction_redemption()` with:
   - Taker's source and destination addresses
   - Amount to send to HTLC
   - Bid price for validation
6. **System executes Bitcoin transaction** from order address to HTLC address
7. **System tracks partial fills** and updates order status

## Partial Fills Support

The system supports partial fills similar to ETH LOP:

### Key Features:
- **Multiple Takers**: Different takers can fill parts of the same order
- **Fill Tracking**: Each partial fill is tracked with taker information
- **Remaining Amount**: System tracks how much is left to fill
- **Validation**: Ensures partial fills don't exceed remaining amount

### Partial Fill Functions:
```rust
// Check if order is fully filled
let is_fully_filled = is_order_fully_filled(order_hash)?;

// Get remaining amount
let remaining = get_remaining_amount(order_hash)?;

// Get detailed fill status
let fill_status = get_order_fill_status(order_hash)?;
```

### Fill Status Structure:
```rust
pub struct OrderFillStatus {
    pub total_filled: u64,         // Total amount filled
    pub remaining_amount: u64,     // Remaining to fill
    pub partial_fills: Vec<PartialFill>, // All partial fills
    pub is_fully_filled: bool,     // Whether completely filled
}
```

## Benefits

- **Price Discovery**: Automatic price discovery through time-based decay
- **Fair Access**: All participants see the same current price
- **Flexible Pricing**: Custom price curves through points array
- **Transparent**: All auction data is publicly queryable
- **Secure**: Price validation prevents invalid bids

## Error Handling

The system handles various error conditions:
- Order not found
- Auction not active
- Bid price too low
- Invalid auction parameters

All functions return `Result<String, String>` for proper error handling.
