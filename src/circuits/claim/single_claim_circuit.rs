use super::error::ClaimError;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

use crate::{
    circuits::{
        claim::deposit_time::{DepositTimePublicInputs, DepositTimePublicInputsTarget},
        validity::validity_pis::{ValidityPublicInputs, ValidityPublicInputsTarget},
    },
    common::{
        claim::ClaimTarget,
        trees::{
            account_tree::{AccountMembershipProof, AccountMembershipProofTarget},
            block_hash_tree::{BlockHashMerkleProof, BlockHashMerkleProofTarget},
        },
    },
    constants::{ACCOUNT_TREE_HEIGHT, BLOCK_HASH_TREE_HEIGHT},
    ethereum_types::{
        address::{Address, AddressTarget},
        bytes32::{Bytes32, Bytes32Target},
        u32limb_trait::U32LimbTargetTrait,
        u64::U64Target,
    },
    utils::{conversion::ToU64, recursively_verifiable::add_proof_target_and_verify},
};

#[derive(Debug, Clone)]
pub struct SingleClaimValue<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub recipient: Address,
    pub block_hash: Bytes32,
    pub block_number: u32,
    pub block_merkle_proof: BlockHashMerkleProof,
    pub account_membership_proof: AccountMembershipProof,
    pub validity_proof: ProofWithPublicInputs<F, C, D>,
    pub deposit_time_proof: ProofWithPublicInputs<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    SingleClaimValue<F, C, D>
{
    pub fn new(
        validity_vd: &VerifierCircuitData<F, C, D>,
        deposit_time_vd: &VerifierCircuitData<F, C, D>,
        recipient: Address,
        block_merkle_proof: &BlockHashMerkleProof,
        account_membership_proof: &AccountMembershipProof,
        validity_proof: &ProofWithPublicInputs<F, C, D>,
        deposit_time_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<Self, ClaimError> {
        validity_vd.verify(validity_proof.clone()).map_err(|e| {
            ClaimError::VerificationFailed(format!("Validity proof is invalid: {:?}", e))
        })?;

        let validity_pis = ValidityPublicInputs::from_pis(&validity_proof.public_inputs);

        deposit_time_vd
            .verify(deposit_time_proof.clone())
            .map_err(|e| {
                ClaimError::VerificationFailed(format!("Deposit time proof is invalid: {:?}", e))
            })?;

        let deposit_time_pis =
            DepositTimePublicInputs::from_u64_slice(&deposit_time_proof.public_inputs.to_u64_vec());

        block_merkle_proof
            .verify(
                &deposit_time_pis.block_hash,
                deposit_time_pis.block_number as u64,
                validity_pis.public_state.block_tree_root,
            )
            .map_err(|e| {
                ClaimError::VerificationFailed(format!("Block merkle proof is invalid: {:?}", e))
            })?;

        account_membership_proof
            .verify(
                deposit_time_pis.pubkey,
                validity_pis.public_state.account_tree_root,
            )
            .map_err(|e| {
                ClaimError::VerificationFailed(format!(
                    "Account membership proof is invalid: {:?}",
                    e
                ))
            })?;

        let last_block_number = account_membership_proof.get_value() as u32;

        if deposit_time_pis.block_number <= last_block_number {
            return Err(ClaimError::InvalidBlockNumber(format!(
                "Last block number {} of the account is not older than the deposit block number {}",
                last_block_number, deposit_time_pis.block_number
            )));
        }

        if validity_pis.public_state.timestamp
            < deposit_time_pis.block_timestamp + (deposit_time_pis.lock_time as u64)
        {
            return Err(ClaimError::InvalidLockTime(format!(
                "Lock time is not passed yet. Deposit time: {}, lock time: {}, current time: {}",
                deposit_time_pis.block_timestamp,
                deposit_time_pis.lock_time,
                validity_pis.public_state.timestamp
            )));
        }

        let block_hash = validity_pis.public_state.block_hash;
        let block_number = validity_pis.public_state.block_number;

        Ok(Self {
            recipient,
            block_hash,
            block_number,
            block_merkle_proof: block_merkle_proof.clone(),
            account_membership_proof: account_membership_proof.clone(),
            validity_proof: validity_proof.clone(),
            deposit_time_proof: deposit_time_proof.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SingleClaimTarget<const D: usize> {
    pub recipient: AddressTarget,
    pub block_hash: Bytes32Target,
    pub block_number: Target,
    pub block_merkle_proof: BlockHashMerkleProofTarget,
    pub account_membership_proof: AccountMembershipProofTarget,
    pub validity_proof: ProofWithPublicInputsTarget<D>,
    pub deposit_time_proof: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> SingleClaimTarget<D> {
    pub fn new<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static>(
        validity_vd: &VerifierCircuitData<F, C, D>,
        deposit_time_vd: &VerifierCircuitData<F, C, D>,
        builder: &mut CircuitBuilder<F, D>,
        is_checked: bool,
    ) -> Self
    where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let validity_proof = add_proof_target_and_verify(validity_vd, builder);
        let deposit_time_proof = add_proof_target_and_verify(deposit_time_vd, builder);
        let validity_pis = ValidityPublicInputsTarget::from_pis(&validity_proof.public_inputs);
        let deposit_time_pis =
            DepositTimePublicInputsTarget::from_slice(&deposit_time_proof.public_inputs);

        let block_merkle_proof = BlockHashMerkleProofTarget::new(builder, BLOCK_HASH_TREE_HEIGHT);
        let account_membership_proof =
            AccountMembershipProofTarget::new(builder, ACCOUNT_TREE_HEIGHT, is_checked);
        block_merkle_proof.verify::<F, C, D>(
            builder,
            &deposit_time_pis.block_hash,
            deposit_time_pis.block_number,
            validity_pis.public_state.block_tree_root,
        );
        account_membership_proof.verify::<F, C, D>(
            builder,
            deposit_time_pis.pubkey,
            validity_pis.public_state.account_tree_root,
        );
        let last_block_number = account_membership_proof.get_value(builder);
        // assert last_block_number < deposit_time_pis.block_number
        let diff = builder.sub(deposit_time_pis.block_number, last_block_number);
        builder.range_check(diff, 32);
        let zero = builder.zero();
        let is_diff_zero = builder.is_equal(diff, zero);
        builder.assert_zero(is_diff_zero.target);

        let lock_time = U64Target::from_u32_target(builder, deposit_time_pis.lock_time);
        let maturity = deposit_time_pis.block_timestamp.add(builder, &lock_time);
        let is_mature = maturity.is_le(builder, &validity_pis.public_state.timestamp);
        builder.assert_one(is_mature.target);

        let block_hash = validity_pis.public_state.block_hash;
        let block_number = validity_pis.public_state.block_number;

        let recipient = AddressTarget::new(builder, is_checked);

        Self {
            recipient,
            block_hash,
            block_number,
            block_merkle_proof,
            account_membership_proof,
            validity_proof,
            deposit_time_proof,
        }
    }

    pub fn set_witness<
        W: WitnessWrite<F>,
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    >(
        &self,
        witness: &mut W,
        value: &SingleClaimValue<F, C, D>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.recipient.set_witness(witness, value.recipient);
        self.block_hash.set_witness(witness, value.block_hash);
        witness.set_target(self.block_number, F::from_canonical_u32(value.block_number));
        self.block_merkle_proof
            .set_witness(witness, &value.block_merkle_proof);
        self.account_membership_proof
            .set_witness(witness, &value.account_membership_proof);
        witness.set_proof_with_pis_target(&self.validity_proof, &value.validity_proof);
        witness.set_proof_with_pis_target(&self.deposit_time_proof, &value.deposit_time_proof);
    }
}

#[derive(Debug)]
pub struct SingleClaimCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, C, D>,
    pub target: SingleClaimTarget<D>,
}

impl<F, C, const D: usize> SingleClaimCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn new(
        validity_vd: &VerifierCircuitData<F, C, D>,
        deposit_time_vd: &VerifierCircuitData<F, C, D>,
    ) -> Self {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let target = SingleClaimTarget::new(validity_vd, deposit_time_vd, &mut builder, true);
        let deposit_time_pis =
            DepositTimePublicInputsTarget::from_slice(&target.deposit_time_proof.public_inputs);
        let claim = ClaimTarget {
            recipient: target.recipient,
            amount: deposit_time_pis.deposit_amount,
            nullifier: deposit_time_pis.nullifier,
            block_hash: target.block_hash,
            block_number: target.block_number,
        };
        builder.register_public_inputs(&claim.to_vec());
        let data = builder.build();
        Self { data, target }
    }

    pub fn prove(
        &self,
        value: &SingleClaimValue<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ClaimError> {
        let mut pw = PartialWitness::<F>::new();
        self.target.set_witness(&mut pw, value);
        self.data
            .prove(pw)
            .map_err(|e| ClaimError::ProofGenerationError(format!("{:?}", e)))
    }
}
