# Secret Management for Partial Fills in ICP Bitcoin LOP

## **The Problem with Simple Secret Management**

### **❌ What Doesn't Work:**
```rust
// BAD: All partial fills use the same secret
let htlc_address = generate_htlc_address(
    &order.hashlock,  // Same secret for all fills!
    &maker_key,
    &taker_key,
    timelock,
    network,
);
```

**Problems:**
- All takers need the same secret to redeem
- Security risk: one taker can redeem all HTLCs
- Not practical for independent redemption

## **✅ The Solution: Merkle Tree of Secrets**

### **How It Works:**

#### **1. Secret Generation Phase**
```rust
// Maker generates multiple secrets for partial fills
let secret_management = generate_secrets_for_partial_fills(
    order_hash,
    10  // Generate 10 secrets for up to 10 partial fills
)?;
```

**What happens:**
- Generates 10 random secrets: `secret_0`, `secret_1`, ..., `secret_9`
- Creates hashes: `hash_0`, `hash_1`, ..., `hash_9`
- Builds Merkle tree with all hashes
- Stores Merkle root in order

#### **2. Partial Fill Execution**
```rust
// Each partial fill uses a different secret
let taker1_key = TakerKey { /* ... */ };
let result1 = execute_auction_redemption(
    order_hash,
    taker1_key,
    300000,  // 30% of order
    bid_price
).await?;
// Uses secret_0 (first 30%)

let taker2_key = TakerKey { /* ... */ };
let result2 = execute_auction_redemption(
    order_hash,
    taker2_key,
    400000,  // 40% of order
    bid_price
).await?;
// Uses secret_3 (next 40%)

let taker3_key = TakerKey { /* ... */ };
let result3 = execute_auction_redemption(
    order_hash,
    taker3_key,
    300000,  // Final 30%
    bid_price
).await?;
// Uses secret_9 (final 30%)
```

### **3. Secret Index Calculation**

The system calculates which secret to use based on fill progress:

```rust
fn calculate_secret_index(order: &OrderDetailNew, fill_amount: u64) -> u64 {
    let total_filled = order.fill_status.total_filled;
    let progress = total_filled as f64 / order.making_amount as f64;
    let secret_index = (progress * secret_mgmt.total_secrets as f64) as u64;
    secret_index.min(secret_mgmt.total_secrets - 1)
}
```

**Example:**
- Order: 1,000,000 satoshis, 10 secrets
- Fill 1: 300,000 sats → progress = 0.3 → secret_index = 3
- Fill 2: 400,000 sats → progress = 0.7 → secret_index = 7  
- Fill 3: 300,000 sats → progress = 1.0 → secret_index = 9

### **4. HTLC Generation with Unique Secrets**

```rust
// Each fill gets a unique HTLC with its own secret
let secret_hash = get_secret_hash_for_fill(&order, secret_index)?;
let htlc_address = generate_htlc_address(
    &secret_hash,  // Different secret for each fill!
    &maker_key,
    &taker_key,
    timelock,
    network,
)?;
```

## **Complete Flow Example**

### **Step 1: Maker Creates Order**
```rust
let order_hash = create_order_new(
    salt,
    maker_key,
    htlc_type,
    dst_chain_id,
    making_amount: 1000000,  // 1M satoshis
    taking_amount,
    taking_asset,
    hashlock: "single_secret_hash",  // Legacy single secret
    timelock,
    auction,
    allow_partial_fills: true,
)?;

// Generate secrets for partial fills
let secrets = generate_secrets_for_partial_fills(order_hash, 10)?;
```

### **Step 2: Taker 1 Fills 30%**
```rust
// Taker 1 fills 300k satoshis
let result1 = execute_auction_redemption(
    order_hash,
    taker1_key,
    300000,
    bid_price
).await?;

// Internally:
// - secret_index = 3 (30% of 10 secrets)
// - Uses secret_3 hash for HTLC
// - Creates unique HTLC for taker1
// - Updates order with fill status
```

### **Step 3: Taker 2 Fills 40%**
```rust
// Taker 2 fills 400k satoshis  
let result2 = execute_auction_redemption(
    order_hash,
    taker2_key,
    400000,
    bid_price
).await?;

// Internally:
// - secret_index = 7 (70% of 10 secrets)
// - Uses secret_7 hash for HTLC
// - Creates unique HTLC for taker2
// - Updates order with fill status
```

### **Step 4: Taker 3 Fills Final 30%**
```rust
// Taker 3 fills remaining 300k satoshis
let result3 = execute_auction_redemption(
    order_hash,
    taker3_key,
    300000,
    bid_price
).await?;

// Internally:
// - secret_index = 9 (100% of 10 secrets)
// - Uses secret_9 hash for HTLC
// - Creates unique HTLC for taker3
// - Order is now fully filled
```

## **Key Benefits**

### **1. Independent Redemption**
- Each taker can redeem their HTLC independently
- No dependency on other takers
- Each has their own secret

### **2. Security**
- Secrets are used in order (prevents reuse)
- Each secret is unique
- Merkle tree provides cryptographic proof

### **3. Flexibility**
- Any number of partial fills
- Takers can fill any amount
- System tracks which secrets are used

### **4. Transparency**
- All secret usage is tracked
- Fill status is queryable
- Complete audit trail

## **Data Structures**

### **SecretManagement**
```rust
pub struct SecretManagement {
    pub merkle_root: String,        // Merkle root of all secrets
    pub total_secrets: u64,        // Number of secrets generated
    pub used_secrets: Vec<u64>,    // Indices of used secrets
    pub secret_hashes: Vec<String>, // All secret hashes
}
```

### **OrderFillStatus**
```rust
pub struct OrderFillStatus {
    pub total_filled: u64,         // Total amount filled
    pub remaining_amount: u64,     // Amount remaining
    pub partial_fills: Vec<PartialFill>, // All fills with secrets used
    pub is_fully_filled: bool,     // Whether complete
}
```

## **Query Functions**

```rust
// Check fill status
let status = get_order_fill_status(order_hash)?;

// Check if fully filled
let is_complete = is_order_fully_filled(order_hash)?;

// Get remaining amount
let remaining = get_remaining_amount(order_hash)?;

// Get secret management info
let secrets = order.secret_management;
```

This approach ensures that each partial fill gets its own unique secret while maintaining the security and flexibility needed for a robust partial fill system!
