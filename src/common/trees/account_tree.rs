use crate::{
    constants::ACCOUNT_TREE_HEIGHT,
    ethereum_types::{
        u256::U256,
        u32limb_trait::{U32LimbTargetTrait, U32LimbTrait},
    },
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::indexed_merkle_tree::{
            insertion::{IndexedInsertionProof, IndexedInsertionProofTarget},
            leaf::{IndexedMerkleLeaf, IndexedMerkleLeafTarget},
            membership::{MembershipProof, MembershipProofTarget},
            update::{UpdateProof, UpdateProofTarget},
            IndexedMerkleProof, IndexedMerkleProofTarget, IndexedMerkleTree,
        },
    },
};
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

pub type AccountTree = IndexedMerkleTree;

/// Proof that demonstrates whether the given pubkey exists or not in the account tree.
pub type AccountMembershipProof = MembershipProof;
pub type AccountMembershipProofTarget = MembershipProofTarget;

pub type AccountRegistorationProof = IndexedInsertionProof;
pub type AccountRegistorationProofTarget = IndexedInsertionProofTarget;
pub type AccountUpdateProof = UpdateProof;
pub type AccountUpdateProofTarget = UpdateProofTarget;

impl AccountTree {
    pub fn initialize() -> Self {
        let mut tree = IndexedMerkleTree::new(ACCOUNT_TREE_HEIGHT);
        tree.insert(U256::<u32>::one(), 0).unwrap(); // add default account
        tree
    }

    pub fn prove_inclusion(&self, account_id: usize) -> AccountMerkleProof {
        let leaf = self.get_leaf(account_id);
        let merkle_proof = self.prove(account_id);
        AccountMerkleProof { merkle_proof, leaf }
    }
}

///  Proof that demonstrates whether the given account id exists or not in the account tree.
#[derive(Clone, Debug)]
pub struct AccountMerkleProof {
    pub merkle_proof: IndexedMerkleProof,
    pub leaf: IndexedMerkleLeaf,
}

impl AccountMerkleProof {
    /// id is already registered. Account id range check is assumed already
    /// done.
    pub fn verify(&self, root: PoseidonHashOut, account_id: usize, pubkey: U256<u32>) -> bool {
        let mut result = true;
        let is_not_pubkey_zero = pubkey != U256::default();
        result = result && is_not_pubkey_zero;
        self.merkle_proof
            .verify(&self.leaf, account_id, root)
            .unwrap();
        let is_eq = pubkey == self.leaf.key;
        result = result && is_eq;
        result
    }
}

#[derive(Clone, Debug)]
pub struct AccountMerkleProofTarget {
    pub merkle_proof: IndexedMerkleProofTarget,
    pub leaf: IndexedMerkleLeafTarget,
}

impl AccountMerkleProofTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        Self {
            merkle_proof: IndexedMerkleProofTarget::new(builder, ACCOUNT_TREE_HEIGHT),
            leaf: IndexedMerkleLeafTarget::new(builder, is_checked),
        }
    }

    pub fn verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        root: PoseidonHashOutTarget,
        account_id: Target,
        pubkey: U256<Target>,
    ) -> BoolTarget
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut result = builder._true();

        let is_pubkey_zero = pubkey.is_zero::<F, D, U256<u32>>(builder);
        let is_not_pubkey_zero = builder.not(is_pubkey_zero);
        result = builder.and(result, is_not_pubkey_zero);

        self.merkle_proof
            .verify::<F, C, D>(builder, &self.leaf, account_id, root);
        let is_eq = pubkey.is_equal(builder, &self.leaf.key);
        result = builder.and(result, is_eq);

        result
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &AccountMerkleProof,
    ) {
        self.merkle_proof.set_witness(witness, &value.merkle_proof);
        self.leaf.set_witness(witness, &value.leaf);
    }
}
