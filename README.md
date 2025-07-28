# Intmax2-ZKP

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)

Intmax2 is an innovative blockchain scaling protocol utilizing Zero-Knowledge Rollups. It significantly reduces the computational and data load on the underlying Layer 1 blockchain by shifting nearly all computational and storage responsibilities to client-side operations.

## Features

- **Stateless Block Production**: Block producers only periodically commit transaction sets, distribute inclusion proofs, and aggregate sender signatures.

- **Permissionless Operation**: Anyone can participate in block production without prior permission or specialized resources.

- **Client-side Computation**: Minimizes on-chain data and computation by moving these processes off-chain.

- **High Scalability**: The architecture scales efficiently with an increasing number of users.

## Circuit Descriptions

### Validity Circuit

Directory: `src/circuits/validity/`

<p align="center">
  <img src="https://github.com/user-attachments/assets/8b5db742-1afa-4fa2-9fa9-8603675d8cba" width="600" alt="Intmax2 Validity Circuit">
</p>

The Validity Proof is a ZK circuit designed to demonstrate the legitimacy of public state transitions and transaction structures within blocks submitted to Intmax2's rollup. This proof is recursive, meaning it references the Validity Proof of the preceding block to generate new proofs.

Key Roles:

- Proof of correctness for public state transitions within blocks
- Validation of transactions within blocks
- Maintenance of system-wide integrity

### Balance Circuit

Directory: `src/circuits/balance/`

<p align="center">
  <img src="https://github.com/user-attachments/assets/f3ba2654-f128-4b18-ab6a-521567fa74f9" width="600" alt="Intmax2 Balance Proof">
</p>

The Balance Proof is a recursive ZK circuit that verifies the correct updating of individual user account balances. It can demonstrate the sending and receiving of funds and deposit processes.

Key Roles:

- Proof of balance correctness for each account
- Assurance of transaction order and accuracy
- Protection of individual user privacy

**Receive Transfer Circuit**

When a user A receives assets from another user B, user A's balance proof A is updated using user B's balance proof B, increasing user A's balance. In this case, the public state of user B's balance proof B needs to be older than user A's public state.

<p align="center">
  <img src="https://github.com/user-attachments/assets/443d91b3-f6cf-496b-8718-4d95669a1d43" width="600" alt="Intmax2_receive_transfer">
</p>

**Receive Deposit Circuit**

To receive tokens deposited to the contract, the user needs to have already updated their balance proof to the block that includes the deposit. After that, they can update their balance proof using the deposit Merkle proof.

<p align="center">
  <img src="https://github.com/user-attachments/assets/1deeef44-0dc0-4374-b088-07fbc0cfddd5" width="600" alt="Intmax_receive_deposit">
</p>

**Update Circuit**

If no tx has been sent to a new block, the balance proof can be updated using a validity proof with a new public state.

<p align="center">
  <img src="https://github.com/user-attachments/assets/f0397797-ab64-47db-b2ff-23f6dd107925" width="600" alt="Intmax2_update">
</p>

**Send Circuit**

To synchronize the balance proof to the block where a tx was sent, the validity proof of the block where the tx was sent

<p align="center">
  <img src="https://github.com/user-attachments/assets/7804697b-bdbf-4608-8c20-97dd4950529d" width="600" alt="Intmax2_send">
</p>

### Withdrawal Circuit

Directory: `src/circuits/withdrawal/`

<p align="center">
  <img src="https://github.com/user-attachments/assets/439261f1-6e57-4f84-91e3-144fbe34d55a" width="600" alt="Intmax2_withdrawal_proof">
</p>

The Withdrawal Proof is a ZK circuit that validates the legitimacy of withdrawal requests when users transfer assets from Intmax2 to Ethereum. It allows for the aggregation of multiple withdrawal requests into a single proof, which can be submitted to Ethereum by an aggregator to make funds accessible.

Key Roles:

- Proof of validity for asset withdrawal processes to Ethereum
- Efficiency through batch processing of multiple withdrawal requests

### Claim Circuit

Directory: `src/circuits/claim/`

<p align="center">
  <img src="https://github.com/user-attachments/assets/6b40af5d-ebd6-481b-9df8-b3326210bf8a" width="600" alt="Intmax_claim_proof">
</p>

The Claim Proof is a ZK circuit used to verify that a given address meets the conditions for privacy mining. It allows for the aggregation of multiple withdrawal requests into a single proof, which can be submitted to Ethereum by an aggregator to make funds accessible.

Key Role:

- Verification of prerequisites for privacy mining, such as the validity of the duration of stay

### Proof of Innocence

Directory: `src/circuits/proof_of_innocence/`

The Proof of Innocence is a ZK circuit designed to prove the relationship between deposits and withdrawals without revealing the details of transfers within the network. It is used to disclose the minimum necessary information while maintaining privacy.

## Running Tests

To run the test:

```
cargo test -r test_e2e
```

## Dependencies

This project relies on the following custom repositories:

- [plonky2_keccak](https://github.com/InternetMaximalism/plonky2_keccak)
- [plonky2_bn254](https://github.com/InternetMaximalism/plonky2_bn254)


## WASM Test

```
wasm-pack test --firefox --release
```