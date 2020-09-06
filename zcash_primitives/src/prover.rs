//! Abstractions over the proving system and parameters.

use crate::{
    jubjub::{edwards, fs::Fs, Unknown},
    primitives::{AssetType, Diversifier, PaymentAddress, ProofGenerationKey},
};
use pairing::bls12_381::{Bls12, Fr};

use crate::{
    merkle_tree::MerklePath,
    redjubjub::{PublicKey, Signature},
    sapling::Node,
    transaction::components::{Amount, GROTH_PROOF_SIZE},
};

/// Interface for creating zero-knowledge proofs for shielded transactions.
pub trait TxProver {
    /// Type for persisting any necessary context across multiple Sapling proofs.
    type SaplingProvingContext;

    /// Instantiate a new Sapling proving context.
    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext;

    /// Create the value commitment, re-randomized key, and proof for a Sapling
    /// [`SpendDescription`], while accumulating its value commitment randomness inside
    /// the context for later use.
    ///
    /// [`SpendDescription`]: crate::transaction::components::SpendDescription
    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey<Bls12>,
        diversifier: Diversifier,
        rcm: Fs,
        ar: Fs,
        value: u64,
        anchor: Fr,
        merkle_path: MerklePath<Node>,
        asset_type: AssetType<Bls12>,
    ) -> Result<
        (
            [u8; GROTH_PROOF_SIZE],
            edwards::Point<Bls12, Unknown>,
            PublicKey<Bls12>,
        ),
        (),
    >;

    /// Create the value commitment and proof for a Sapling [`OutputDescription`],
    /// while accumulating its value commitment randomness inside the context for later
    /// use.
    ///
    /// [`OutputDescription`]: crate::transaction::components::OutputDescription
    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: Fs,
        payment_address: PaymentAddress<Bls12>,
        rcm: Fs,
        value: u64,
        asset_type: AssetType<Bls12>,
    ) -> ([u8; GROTH_PROOF_SIZE], edwards::Point<Bls12, Unknown>);

    /// Create the `bindingSig` for a Sapling transaction. All calls to
    /// [`TxProver::spend_proof`] and [`TxProver::output_proof`] must be completed before
    /// calling this function.
    fn single_binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        asset_type: AssetType<Bls12>,
        value_balance: i64,
        sighash: &[u8; 32],
    ) -> Result<Signature, ()>;

    fn multi_binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        asset_and_value: &[ (AssetType<Bls12>, i64) ],
        sighash: &[u8; 32],
    ) -> Result<Signature, ()>; 
}

#[cfg(test)]
pub(crate) mod mock {
    use ff::Field;
    use pairing::bls12_381::{Bls12, Fr};
    use rand_core::OsRng;

    use crate::{
        jubjub::{PrimeOrder, JubjubBls12, edwards, fs::Fs, FixedGenerators, Unknown},
        primitives::{AssetType, Diversifier, PaymentAddress, ProofGenerationKey},
    };

    use crate::{
        merkle_tree::MerklePath,
        redjubjub::{PublicKey, Signature},
        sapling::Node,
        transaction::components::{Amount, GROTH_PROOF_SIZE},
        JUBJUB,
    };

    use super::TxProver;

    pub(crate) struct MockTxProver;

    #[cfg(test)]
    impl TxProver for MockTxProver {
        type SaplingProvingContext = ();

        fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {}

        fn spend_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            proof_generation_key: ProofGenerationKey<Bls12>,
            _diversifier: Diversifier,
            _rcm: Fs,
            ar: Fs,
            value: u64,
            _anchor: Fr,
            _merkle_path: MerklePath<Node>,
            asset_type: AssetType<Bls12>,
        ) -> Result<
            (
                [u8; GROTH_PROOF_SIZE],
                edwards::Point<Bls12, Unknown>,
                PublicKey<Bls12>,
            ),
            (),
        > {
            let mut rng = OsRng;

            let cv = asset_type.value_commitment(
                value, 
                Fs::random(&mut rng),
                &JUBJUB)
            .cm(&JUBJUB)
            .into();

            let rk = PublicKey::<Bls12>(proof_generation_key.ak.clone().into()).randomize(
                ar,
                FixedGenerators::SpendingKeyGenerator,
                &JUBJUB,
            );

            Ok(([0u8; GROTH_PROOF_SIZE], cv, rk))
        }

        fn output_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _esk: Fs,
            _payment_address: PaymentAddress<Bls12>,
            _rcm: Fs,
            value: u64,
            asset_type: AssetType<Bls12>,
        ) -> ([u8; GROTH_PROOF_SIZE], edwards::Point<Bls12, Unknown>) {
            let mut rng = OsRng;

            let cv = asset_type.value_commitment(
                value,
                Fs::random(&mut rng),
                &JUBJUB)
            .cm(&JUBJUB)
            .into();

            ([0u8; GROTH_PROOF_SIZE], cv)
        }

        fn single_binding_sig(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _asset_type : AssetType<Bls12>,
            _value_balance: i64,
            _sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            Err(())
        }

        fn multi_binding_sig(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _assets_and_values : &[(AssetType<Bls12>,i64)],
            _sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            Err(())
        }
    }
}
