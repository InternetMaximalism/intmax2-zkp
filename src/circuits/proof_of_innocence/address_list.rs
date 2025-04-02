use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use crate::{
    common::generic_address::{GenericAddress, GenericAddressTarget},
    constants::ADDRESS_LIST_TREE_HEIGHT,
    ethereum_types::address::{Address, AddressTarget},
    utils::{
        poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
        trees::indexed_merkle_tree::{
            membership::{MembershipProof, MembershipProofTarget},
            IndexedMerkleTree,
        },
    },
};

#[derive(Debug, Clone)]
pub struct AddressListTree(IndexedMerkleTree);

#[derive(Debug, Clone)]
pub struct AddressMembershipProof(MembershipProof);

#[derive(Debug, Clone)]
pub struct AddressMembershipProofTarget(MembershipProofTarget);

impl AddressListTree {
    pub fn new(address_list: &[Address]) -> anyhow::Result<Self> {
        let mut tree = IndexedMerkleTree::new(ADDRESS_LIST_TREE_HEIGHT);
        for address in address_list {
            let generic_address = GenericAddress::from_address(*address);
            tree.insert(generic_address.data, 0)
                .map_err(|e| anyhow::anyhow!("Failed to insert address: {}", e))?;
        }
        Ok(Self(tree))
    }

    pub fn get_root(&self) -> PoseidonHashOut {
        self.0.get_root()
    }

    pub fn prove_membership(&self, address: Address) -> AddressMembershipProof {
        let generic_address = GenericAddress::from_address(address);
        let proof = self.0.prove_membership(generic_address.data);
        AddressMembershipProof(proof)
    }
}

impl AddressMembershipProof {
    pub fn verify(&self, address: Address, root: PoseidonHashOut) -> anyhow::Result<()> {
        let generic_address = GenericAddress::from_address(address);
        self.0
            .verify(generic_address.data, root)
            .map_err(|e| anyhow::anyhow!("Failed to verify address membership: {}", e))
    }

    pub fn is_included(&self) -> bool {
        self.0.is_included
    }
}

impl AddressMembershipProofTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self {
        AddressMembershipProofTarget(MembershipProofTarget::new(
            builder,
            ADDRESS_LIST_TREE_HEIGHT,
            is_checked,
        ))
    }

    pub fn set_witness<F: Field, W: WitnessWrite<F>>(
        &self,
        witness: &mut W,
        value: &AddressMembershipProof,
    ) {
        self.0.set_witness(witness, &value.0)
    }

    pub fn verify<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        address: AddressTarget,
        root: PoseidonHashOutTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let generic_address = GenericAddressTarget::from_address(builder, address);
        self.0
            .verify::<F, C, D>(builder, generic_address.data, root);
    }

    pub fn is_included(&self) -> BoolTarget {
        self.0.is_included
    }
}
