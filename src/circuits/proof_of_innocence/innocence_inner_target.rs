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
    circuits::proof_of_innocence::address_list::AddressMembershipProofTarget,
    common::{
        deposit::{Deposit, DepositTarget},
        trees::nullifier_tree::{NullifierInsertionProof, NullifierInsertionProofTarget},
    },
    ethereum_types::bytes32::{Bytes32, Bytes32Target},
    utils::poseidon_hash_out::{PoseidonHashOut, PoseidonHashOutTarget},
};

use super::address_list::AddressMembershipProof;

#[derive(Debug, Clone)]
pub struct InnocenceInnerValue {
    pub use_allow_list: bool,
    pub allow_list_tree_root: PoseidonHashOut,
    pub deny_list_tree_root: PoseidonHashOut,
    pub prev_nullifier_tree_root: PoseidonHashOut,
    pub new_nullifier_tree_root: PoseidonHashOut,
    pub deposit: Deposit,
    pub nullifier_proof: NullifierInsertionProof,
    pub allow_list_membership_proof: AddressMembershipProof,
    pub deny_list_membership_proof: AddressMembershipProof,
}

impl InnocenceInnerValue {
    pub fn new(
        use_allow_list: bool,
        allow_list_tree_root: PoseidonHashOut,
        deny_list_tree_root: PoseidonHashOut,
        prev_nullifier_tree_root: PoseidonHashOut,
        deposit: Deposit,
        nullifier_proof: NullifierInsertionProof,
        allow_list_membership_proof: AddressMembershipProof,
        deny_list_membership_proof: AddressMembershipProof,
    ) -> anyhow::Result<Self> {
        // prove allow/deny list inclusion/exclusion
        allow_list_membership_proof
            .verify(deposit.depositor, allow_list_tree_root)
            .map_err(|e| {
                anyhow::anyhow!("allow list membership proof verification failed: {}", e)
            })?;
        if use_allow_list && !allow_list_membership_proof.is_included() {
            return Err(anyhow::anyhow!("depositor is not in the allow list"));
        }
        deny_list_membership_proof
            .verify(deposit.depositor, deny_list_tree_root)
            .map_err(|e| {
                anyhow::anyhow!("deny list membership proof verification failed: {}", e)
            })?;
        if deny_list_membership_proof.is_included() {
            return Err(anyhow::anyhow!("depositor is in the deny list"));
        }
        // prove transition of nullifier root
        let nullifier: Bytes32 = deposit.poseidon_hash().into();
        let new_nullifier_tree_root = nullifier_proof
            .get_new_root(prev_nullifier_tree_root, nullifier)
            .map_err(|e| anyhow::anyhow!("Invalid nullifier merkle proof: {}", e))?;
        Ok(Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            prev_nullifier_tree_root,
            new_nullifier_tree_root,
            deposit,
            nullifier_proof,
            allow_list_membership_proof,
            deny_list_membership_proof,
        })
    }
}

#[derive(Debug, Clone)]
pub struct InnocenceInnerTarget {
    pub use_allow_list: BoolTarget,
    pub allow_list_tree_root: PoseidonHashOutTarget,
    pub deny_list_tree_root: PoseidonHashOutTarget,
    pub prev_nullifier_tree_root: PoseidonHashOutTarget,
    pub new_nullifier_tree_root: PoseidonHashOutTarget,
    pub deposit: DepositTarget,
    pub nullifier_proof: NullifierInsertionProofTarget,
    pub allow_list_membership_proof: AddressMembershipProofTarget,
    pub deny_list_membership_proof: AddressMembershipProofTarget,
}

impl InnocenceInnerTarget {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let use_allow_list = builder.add_virtual_bool_target_safe();
        let allow_list_tree_root = PoseidonHashOutTarget::new(builder);
        let deny_list_tree_root = PoseidonHashOutTarget::new(builder);
        let prev_nullifier_tree_root = PoseidonHashOutTarget::new(builder);
        let deposit = DepositTarget::new(builder, is_checked);
        let nullifier_proof = NullifierInsertionProofTarget::new(builder, is_checked);
        let allow_list_membership_proof = AddressMembershipProofTarget::new(builder, is_checked);
        let deny_list_membership_proof = AddressMembershipProofTarget::new(builder, is_checked);

        // prove allow/deny list inclusion/exclusion
        allow_list_membership_proof.verify::<F, C, D>(
            builder,
            deposit.depositor,
            allow_list_tree_root,
        );
        let not_included_allow_list = builder.not(allow_list_membership_proof.is_included());
        let use_allow_list_and_not_included_allow_list =
            builder.and(use_allow_list, not_included_allow_list);
        builder.assert_zero(use_allow_list_and_not_included_allow_list.target);

        deny_list_membership_proof.verify::<F, C, D>(
            builder,
            deposit.depositor,
            deny_list_tree_root,
        );
        builder.assert_zero(deny_list_membership_proof.is_included().target);

        // prove transition of nullifier root
        let nullifier_poseidon = deposit.poseidon_hash(builder);
        let nullifier = Bytes32Target::from_hash_out(builder, nullifier_poseidon);
        let new_nullifier_tree_root =
            nullifier_proof.get_new_root::<F, C, D>(builder, prev_nullifier_tree_root, nullifier);

        Self {
            use_allow_list,
            allow_list_tree_root,
            deny_list_tree_root,
            prev_nullifier_tree_root,
            new_nullifier_tree_root,
            deposit,
            nullifier_proof,
            allow_list_membership_proof,
            deny_list_membership_proof,
        }
    }

    pub fn set_witness<W: WitnessWrite<F>, F: Field>(
        &self,
        witness: &mut W,
        value: &InnocenceInnerValue,
    ) {
        witness.set_bool_target(self.use_allow_list, value.use_allow_list);
        self.allow_list_tree_root
            .set_witness(witness, value.allow_list_tree_root);
        self.deny_list_tree_root
            .set_witness(witness, value.deny_list_tree_root);
        self.prev_nullifier_tree_root
            .set_witness(witness, value.prev_nullifier_tree_root);
        self.new_nullifier_tree_root
            .set_witness(witness, value.new_nullifier_tree_root);
        self.deposit.set_witness(witness, &value.deposit);
        self.nullifier_proof
            .set_witness(witness, &value.nullifier_proof);
        self.allow_list_membership_proof
            .set_witness(witness, &value.allow_list_membership_proof);
        self.deny_list_membership_proof
            .set_witness(witness, &value.deny_list_membership_proof);
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::{
        circuits::proof_of_innocence::address_list::AddressListTree,
        common::{deposit::Deposit, trees::nullifier_tree::NullifierTree},
        ethereum_types::{address::Address, bytes32::Bytes32, u32limb_trait::U32LimbTrait},
    };

    use super::{InnocenceInnerTarget, InnocenceInnerValue};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_innocence_inner_target() {
        let mut rng = rand::thread_rng();
        let depositor = Address::rand(&mut rng);

        let allow_list_tree = AddressListTree::new(&[depositor]).unwrap();
        let deny_list_tree = AddressListTree::new(&[]).unwrap();
        let mut nullifier_tree = NullifierTree::new();
        let prev_nullifier_tree_root = nullifier_tree.get_root();

        let deposit = Deposit {
            depositor,
            pubkey_salt_hash: Bytes32::rand(&mut rng),
            amount: 100.into(),
            token_index: 0,
            is_eligible: true,
        };
        let nullifier_proof = nullifier_tree
            .prove_and_insert(deposit.poseidon_hash().into())
            .unwrap();
        let allow_list_membership_proof = allow_list_tree.prove_membership(depositor);
        let deny_list_membership_proof = deny_list_tree.prove_membership(depositor);

        let value = InnocenceInnerValue::new(
            true,
            allow_list_tree.get_root(),
            deny_list_tree.get_root(),
            prev_nullifier_tree_root,
            deposit,
            nullifier_proof,
            allow_list_membership_proof,
            deny_list_membership_proof,
        )
        .unwrap();

        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        let target = InnocenceInnerTarget::new::<F, C, D>(&mut builder, true);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        target.set_witness(&mut pw, &value);
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
