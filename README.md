# Intmax2-ZKP

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)

A Rust implementation of Zero-Knowledge Proof circuits for Intmax2, a high-performance stateless rollup protocol for blockchain scalability.

## Table of Contents

- [Overview](#overview)
- [Technical Architecture](#technical-architecture)
- [Core Components](#core-components)
- [Circuit Implementations](#circuit-implementations)
- [Data Structures](#data-structures)
- [Development](#development)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
  - [Testing](#testing)
  - [Benchmarking](#benchmarking)
- [API Reference](#api-reference)
- [Dependencies](#dependencies)
- [Performance Considerations](#performance-considerations)
- [License](#license)

## Overview

Intmax2-ZKP provides the cryptographic backbone for the Intmax2 rollup protocol, enabling high-throughput blockchain transactions with minimal on-chain footprint. The implementation focuses on:

- Client-side state management and proof generation
- Stateless block validation
- Secure asset transfers with cryptographic guarantees
- Efficient Layer-1 integration

## Technical Architecture

The codebase is organized into modular components that handle different aspects of the ZKP system:

```
src/
├── circuits/           # ZKP circuit implementations
│   ├── balance/        # Balance verification circuits
│   ├── validity/       # Block validation circuits
│   ├── withdrawal/     # Withdrawal verification circuits
│   ├── claim/          # Deposit claim circuits
│   └── proof_of_innocence/ # Fraud prevention circuits
├── common/             # Common data structures and utilities
│   ├── trees/          # Merkle tree implementations
│   ├── witness/        # Witness generation utilities
│   └── signature/      # Cryptographic signature utilities
├── ethereum_types/     # Ethereum-compatible data types
├── mock/               # Mock implementations for testing
├── utils/              # Utility functions and helpers
│   ├── trees/          # Tree data structure utilities
│   └── hash_chain/     # Hash chain implementations
└── wrapper_config/     # Configuration for proof system wrappers
```

## Core Components

### Proof System

Intmax2-ZKP uses Plonky2, a PLONK-based SNARK system with FRI commitments, optimized for:

- Fast proof generation (critical for client-side operations)
- Efficient verification (important for on-chain validation)
- Recursive proof composition (enables proof aggregation)

```rust
// Example: Creating a circuit with Plonky2
use plonky2::plonk::{Circuit, CircuitBuilder};

fn build_simple_circuit<F: Field, C: Config>(builder: &mut CircuitBuilder<F, C>) {
    // Register inputs
    let a = builder.add_virtual_target();
    let b = builder.add_virtual_target();
    
    // Perform operations
    let sum = builder.add(a, b);
    let product = builder.mul(a, b);
    
    // Register outputs
    builder.register_public_input(sum);
    builder.register_public_input(product);
}
```

### Merkle Tree Implementations

The codebase includes several specialized Merkle tree implementations:

1. **Indexed Merkle Tree**: Optimized for efficient lookups and updates
   ```rust
   // Usage pattern for Indexed Merkle Tree
   let mut tree = IndexedMerkleTree::new(height);
   tree.insert(index, leaf_value);
   let proof = tree.generate_membership_proof(index);
   let is_valid = proof.verify(tree.root(), index, leaf_value);
   ```

2. **Sparse Merkle Tree**: Efficient for representing sparse state
   ```rust
   // Usage pattern for Sparse Merkle Tree
   let mut tree = SparseMerkleTree::new();
   tree.update(key, value);
   let proof = tree.generate_proof(key);
   ```

3. **Incremental Merkle Tree**: Optimized for append-only operations
   ```rust
   // Usage pattern for Incremental Merkle Tree
   let mut tree = IncrementalMerkleTree::new(height);
   tree.append(leaf_value);
   let root = tree.root();
   ```

## Circuit Implementations

### Balance Circuits

The balance circuits implement the core functionality for verifying and updating user balances:

```
src/circuits/balance/
├── balance_circuit.rs      # Main balance verification circuit
├── balance_pis.rs          # Public inputs for balance circuits
├── balance_processor.rs    # Processor for balance operations
├── receive/                # Circuits for receiving tokens
│   ├── receive_deposit_circuit.rs
│   ├── receive_transfer_circuit.rs
│   └── update_circuit.rs
├── send/                   # Circuits for sending tokens
│   ├── sender_circuit.rs
│   ├── spent_circuit.rs
│   └── tx_inclusion_circuit.rs
└── transition/             # Circuits for state transitions
    └── transition_circuit.rs
```

Key implementation pattern:

```rust
// Simplified example of balance verification
pub fn verify_balance<F: Field, C: Config>(
    builder: &mut CircuitBuilder<F, C>,
    balance_state: BalanceState,
    merkle_proof: MerkleProof,
) -> VerificationResult {
    // 1. Verify the Merkle proof of inclusion
    let is_valid_proof = verify_merkle_proof(builder, merkle_proof, balance_state.hash());
    
    // 2. Verify balance constraints
    let valid_balance = verify_balance_constraints(builder, balance_state);
    
    // 3. Combine verification results
    builder.and(is_valid_proof, valid_balance)
}
```

### Validity Circuits

The validity circuits ensure the correctness of blocks submitted to Layer-1:

```
src/circuits/validity/
├── validity_circuit.rs     # Main validity circuit
├── validity_pis.rs         # Public inputs for validity circuits
├── validity_processor.rs   # Processor for validity operations
├── block_validation/       # Block validation circuits
│   ├── format_validation.rs
│   ├── account_inclusion.rs
│   ├── main_validation.rs
│   └── processor.rs
└── transition/             # Account transition circuits
    ├── account_registration.rs
    ├── account_update.rs
    └── transition.rs
```

Block validation process:

1. **Format Validation**: Ensures transactions follow the correct format
2. **Account Inclusion**: Verifies account inclusion in the state tree
3. **Transaction Validation**: Validates individual transactions
4. **State Transition**: Verifies correct state updates
5. **Proof Aggregation**: Combines proofs into a single validity proof

### Withdrawal Circuits

Enables secure withdrawals from Layer-2 to Layer-1:

```rust
// Simplified withdrawal verification pattern
pub fn verify_withdrawal<F: Field, C: Config>(
    builder: &mut CircuitBuilder<F, C>,
    withdrawal: Withdrawal,
    nullifier_proof: MerkleProof,
    balance_proof: BalanceProof,
) -> VerificationResult {
    // 1. Verify the user has sufficient balance
    let has_balance = verify_sufficient_balance(builder, balance_proof, withdrawal.amount);
    
    // 2. Verify the nullifier hasn't been used
    let nullifier_unused = verify_nullifier_unused(builder, nullifier_proof, withdrawal.nullifier);
    
    // 3. Verify withdrawal signature
    let valid_signature = verify_signature(builder, withdrawal.signature, withdrawal.hash());
    
    // 4. Combine all verification results
    builder.and(builder.and(has_balance, nullifier_unused), valid_signature)
}
```

## Data Structures

### Block Structure

```rust
pub struct Block {
    // Block header
    pub header: BlockHeader,
    // Transactions included in the block
    pub transactions: Vec<Transaction>,
    // State updates
    pub state_updates: Vec<StateUpdate>,
    // Validity proof
    pub validity_proof: ValidityProof,
}

pub struct BlockHeader {
    pub previous_block_hash: Hash,
    pub block_number: u64,
    pub timestamp: u64,
    pub transactions_root: Hash,
    pub state_root: Hash,
}
```

### Transaction Structure

```rust
pub struct Transaction {
    // Transaction type (Transfer, Deposit, Withdrawal)
    pub tx_type: TxType,
    // Transaction data
    pub data: TxData,
    // Cryptographic signature
    pub signature: Signature,
    // Nullifier to prevent double-spending
    pub nullifier: Nullifier,
}

pub enum TxType {
    Transfer,
    Deposit,
    Withdrawal,
}
```

### State Representation

```rust
pub struct PrivateState {
    // User account identifier
    pub account_id: AccountId,
    // Asset identifier
    pub asset_id: AssetId,
    // Balance amount
    pub balance: U256,
    // State version
    pub version: u64,
    // Merkle proof of inclusion
    pub inclusion_proof: MerkleProof,
}
```

## Development

### Prerequisites

- Rust (latest stable version)
- Cargo package manager
- Git

### Setup

1. Clone the repository:

```bash
git clone https://github.com/InternetMaximalism/intmax2-zkp.git
cd intmax2-zkp
```

2. Install dependencies:

```bash
cargo build
```

### Testing

Run the comprehensive test suite:

```bash
# Run end-to-end tests
cargo test -r e2e_test

# Run specific circuit tests
cargo test -p intmax2-zkp --lib

# Run tests with verbose output
cargo test -- --nocapture
```

### Benchmarking

Benchmark proof generation and verification:

```bash
cargo bench
```

## API Reference

### Key Traits

```rust
// Trait for types that can be hashed into a leaf
pub trait Leafable {
    fn hash(&self) -> Hash;
}

// Trait for recursive verification
pub trait RecursivelyVerifiable {
    fn verify_recursively(&self, proof: &Proof) -> bool;
}

// Trait for circuit processors
pub trait CircuitProcessor {
    type Input;
    type Output;
    
    fn process(&self, input: Self::Input) -> Result<Self::Output, Error>;
}
```

### Common Functions

```rust
// Generate a Merkle proof
pub fn generate_merkle_proof(tree: &MerkleTree, index: usize) -> MerkleProof;

// Verify a transaction
pub fn verify_transaction(tx: &Transaction, state: &State) -> Result<(), Error>;

// Generate a ZK proof
pub fn generate_proof(circuit: &Circuit, witness: &Witness) -> Result<Proof, Error>;

// Verify a ZK proof
pub fn verify_proof(proof: &Proof, public_inputs: &[Field]) -> Result<bool, Error>;
```

## Dependencies

This implementation relies on the following specialized cryptographic libraries:

- [plonky2_keccak](https://github.com/InternetMaximalism/plonky2_keccak): Keccak hash function for Plonky2
  ```rust
  // Usage example
  use plonky2_keccak::keccak256;
  
  let hash = keccak256(data);
  ```

- [plonky2_bn254](https://github.com/InternetMaximalism/plonky2_bn254): BN254 elliptic curve for Plonky2
  ```rust
  // Usage example
  use plonky2_bn254::{Bn254Field, G1Point};
  
  let point = G1Point::generator();
  let scalar = Bn254Field::from(42);
  let result = point.scalar_mul(scalar);
  ```

## Performance Considerations

### Proof Generation Optimization

- **Circuit Design**: Minimize the number of constraints to improve proof generation time
- **Parallel Processing**: Utilize multi-threading for independent circuit components
- **Memory Management**: Optimize witness generation to reduce memory usage

### Verification Efficiency

- **Recursive Verification**: Use recursive proof composition to aggregate multiple proofs
- **Batched Verification**: Implement batch verification for multiple proofs
- **Gas Optimization**: Minimize on-chain verification costs for Layer-1 integration

## License

This project is licensed under the MIT License - see the LICENSE file for details.
