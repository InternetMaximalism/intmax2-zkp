# Intmax2-ZKP

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)

intmax2-zkp is the main repository for Zero-Knowledge Proof circuits of Intmax2, an stateless rollup.

## About Intmax2

Intmax2 is a cutting-edge Zero-Knowledge rollup protocol designed to achieve scalable blockchain performance with minimal data and computational requirements on the underlying blockchain. Key features include:

## Circuit Descriptions

### Validity Circuit

Directory: `src/circuits/validity/`

![Intmax2 Validity Circuit](https://github.com/user-attachments/assets/8b5db742-1afa-4fa2-9fa9-8603675d8cba)

The Validity Proof is a ZK circuit designed to demonstrate the legitimacy of public state transitions and transaction structures within blocks submitted to Intmax2's rollup. This proof is recursive, meaning it references the Validity Proof of the preceding block to generate new proofs.

Key Roles:

- Proof of correctness for public state transitions within blocks
- Validation of transactions within blocks
- Maintenance of system-wide integrity

### Balance Circuit

Directory: `src/circuits/balance/`

![Intmax2 Balance Proof](https://github.com/user-attachments/assets/f3ba2654-f128-4b18-ab6a-521567fa74f9)

The Balance Proof is a recursive ZK circuit that verifies the correct updating of individual user account balances. It can demonstrate the sending and receiving of funds and deposit processes.

Key Roles:

- Proof of balance correctness for each account
- Assurance of transaction order and accuracy
- Protection of individual user privacy

**Receive Transfer Circuit**

When a user A receives assets from another user B, user A's balance proof A is updated using user B's balance proof B, increasing user A's balance. In this case, the public state of user B's balance proof B needs to be older than user A's public state.

![Intmax2_receive_transfer](https://github.com/user-attachments/assets/443d91b3-f6cf-496b-8718-4d95669a1d43)

**Receive Deposit Circuit**

To receive tokens deposited to the contract, the user needs to have already updated their balance proof to the block that includes the deposit. After that, they can update their balance proof using the deposit Merkle proof.

![Intmax_receive_deposit](https://github.com/user-attachments/assets/1deeef44-0dc0-4374-b088-07fbc0cfddd5)

**Update Circuit**

If no tx has been sent to a new block, the balance proof can be updated using a validity proof with a new public state.

![Intmax2_update](https://github.com/user-attachments/assets/f0397797-ab64-47db-b2ff-23f6dd107925)

**Send Circuit**

To synchronize the balance proof to the block where a tx was sent, the validity proof of the block where the tx was sent

![Intmax2_send](https://github.com/user-attachments/assets/7804697b-bdbf-4608-8c20-97dd4950529d)

### Withdrawal Circuit

Directory: `src/circuits/withdrawal/`

![Intmax2_withdrawal_proof](https://github.com/user-attachments/assets/439261f1-6e57-4f84-91e3-144fbe34d55a)

The Withdrawal Proof is a ZK circuit that validates the legitimacy of withdrawal requests when users transfer assets from Intmax2 to Ethereum. It allows for the aggregation of multiple withdrawal requests into a single proof, which can be submitted to Ethereum by an aggregator to make funds accessible.

Key Roles:

- Proof of validity for asset withdrawal processes to Ethereum
- Efficiency through batch processing of multiple withdrawal requests

### Claim Circuit

Directory: `src/circuits/claim/`

![Intmax_claim_proof](https://github.com/user-attachments/assets/6b40af5d-ebd6-481b-9df8-b3326210bf8a)

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
