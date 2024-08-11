# intmax2-zkp

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

intmax2-zkp is the main repository for Zero-Knowledge Proof circuits of Intmax2, an stateless rollup.

## About Intmax2

Intmax2 is a cutting-edge Zero-Knowledge rollup protocol designed to achieve scalable blockchain performance with minimal data and computational requirements on the underlying blockchain. Key features include:

- Stateless and permissionless block production
- Client-side Zero-Knowledge Proofs for user balances
- Client-side data availability

## Circuit Descriptions

- **Balance Circuits** (`src/circuits/balance/`):

  - Client-side ZKP circuits for proving user token balances
  - Update receiver's balance proof by incorporating sender's balance proof
  - Handle the integration of tokens deposited from Layer1 to Intmax2

- **Validity Circuits** (`src/circuits/validity/`):

  - Verify the correctness of blocks posted to Layer1 contracts
  - Used for updating balance proofs

- **Withdrawal Circuits** (`src/circuits/withdrawal/`):

  - Enable token withdrawals from Intmax2 to Layer1

- **Fraud Circuits** (`src/circuits/fraud/`):
  - Punish submitters of fraudulent rollup blocks

## Running Tests

To run the test:

```
cargo test -r e2e_test
```

## Dependencies

This project relies on the following custom repositories:

- [plonky2_keccak](https://github.com/InternetMaximalism/plonky2_keccak)
- [plonky2_bn254](https://github.com/InternetMaximalism/plonky2_bn254)
