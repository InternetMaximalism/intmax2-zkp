# intmax2-zkp

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

intmax2-zkp is the main repository for Zero-Knowledge Proof circuits of Intmax2, an innovative Layer2 blockchain scaling solution.

## 🌟 About Intmax2

Intmax2 is a cutting-edge Zero-Knowledge rollup protocol designed to achieve scalable blockchain performance with minimal data and computational requirements on the underlying blockchain. Key features include:

- Stateless and permissionless block production
- Client-side focused data and computational costs
- Periodic commitment generation by block producers
- Distribution of inclusion proofs to senders
- Collection and aggregation of sender signatures
- Highly scalable architecture accommodating a large number of users

This innovative design allows for a more efficient and scalable blockchain ecosystem, significantly reducing the burden on block producers and the Layer 1 blockchain.

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

## 🧪 Running Tests

To run the test:

```
cargo test -r e2e_test
```

## 🔗 Dependencies

This project relies on the following custom repositories:

- [plonky2_keccak](https://github.com/InternetMaximalism/plonky2_keccak)
- [plonky2_bn254](https://github.com/InternetMaximalism/plonky2_bn254)
