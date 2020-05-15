//! Structs for core Zcash primitives.

use ff::{Field, PrimeField, PrimeFieldRepr};

use crate::constants;

//use crate::group_hash::group_hash;
use crate::group_hash::{find_group_hash, group_hash};

use crate::pedersen_hash::{pedersen_hash, Personalization};

use byteorder::{LittleEndian, WriteBytesExt};

use crate::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, PrimeOrder, Unknown};

use blake2s_simd::Params as Blake2sParams;
use std::marker::PhantomData;

#[derive(Copy, Clone, Debug)]
pub struct AssetType<E: JubjubEngine> {
    identifier: [u8; constants::ASSET_TYPE_LENGTH], //32 byte asset type preimage
    _marker: PhantomData<E>,
}

impl<E: JubjubEngine> AssetType<E> {
    pub fn new(
        name: &[u8], 
        params: &E::Params,
    ) -> AssetType::<E> {
        assert_eq!(constants::ASSET_TYPE_PERSONALIZATION.len(), 8);
        let mut blake2s_state = Blake2sParams::new()
            .hash_length(constants::ASSET_TYPE_LENGTH)
            .personal(constants::ASSET_TYPE_PERSONALIZATION)
            .to_state();

        blake2s_state.update(&name); 

        loop {
            let h = blake2s_state.finalize();
            if let Some(p) = AssetType::<E>::hash_to_point(h.as_array(), params) {
                break AssetType::<E>{ identifier: *h.as_array(), _marker: PhantomData };
            }
            blake2s_state.update(h.as_ref());
        }
    }
    fn hash_to_point(
        name: &[u8; 32], 
        params: &E::Params,
    ) -> Option<edwards::Point<E, Unknown>> {
        assert_eq!(constants::VALUE_COMMITMENT_GENERATOR_PERSONALIZATION.len(), 8);

        // Check to see that scalar field is 255 bits
        assert!(E::Fr::NUM_BITS == 255);

        let h = Blake2sParams::new()
            .hash_length(32)
            .personal(constants::VALUE_COMMITMENT_GENERATOR_PERSONALIZATION)
            .to_state()
            .update(constants::GH_FIRST_BLOCK)
            .update(name)
            .finalize();
 
        if let Ok(p) = edwards::Point::<E, _>::read(h.as_ref(), params) {
            if p.mul_by_cofactor(params) != edwards::Point::zero() {
                return Some(p);
            }
        } 
        return None;
    }
    pub fn get_identifier(&self) -> &[u8; constants::ASSET_TYPE_LENGTH] {
        &self.identifier
    }
    pub fn value_commitment_generator(
        &self,
        params: &E::Params,
    ) -> edwards::Point<E, Unknown> {
        AssetType::<E>::hash_to_point(self.get_identifier(), params)
            .expect("AssetType internal identifier state inconsistent")
    }
    pub fn to_bits(&self) -> Vec<Option<bool>> {
        self.get_identifier()
            .iter()
            .flat_map(|&v| (0..8).map(move |i| Some((v >> i) & 1 == 1)))
            .collect()
    }    
}
impl<E: JubjubEngine> PartialEq for AssetType<E> {
    fn eq(&self, other: &Self) -> bool {
        self.get_identifier() == other.get_identifier() 
    }
}

#[derive(Clone)]
pub struct ValueCommitment<E: JubjubEngine> {
    pub asset_generator: edwards::Point<E, Unknown>,
    pub value: u64,
    pub randomness: E::Fs,
}

impl<E: JubjubEngine> ValueCommitment<E> {
    pub fn cm(
        &self,
        params: &E::Params
    ) -> edwards::Point<E, PrimeOrder>
    {
        self.asset_generator.mul_by_cofactor(params).mul(self.value, params)
              .add(
                  &params.generator(FixedGenerators::ValueCommitmentRandomness)
                  .mul(self.randomness, params),
                  params
              )
    }
}

#[derive(Clone)]
pub struct ProofGenerationKey<E: JubjubEngine> {
    pub ak: edwards::Point<E, PrimeOrder>,
    pub nsk: E::Fs,
}

impl<E: JubjubEngine> ProofGenerationKey<E> {
    pub fn to_viewing_key(&self, params: &E::Params) -> ViewingKey<E> {
        ViewingKey {
            ak: self.ak.clone(),
            nk: params
                .generator(FixedGenerators::ProofGenerationKey)
                .mul(self.nsk, params),
        }
    }
}

#[derive(Debug)]
pub struct ViewingKey<E: JubjubEngine> {
    pub ak: edwards::Point<E, PrimeOrder>,
    pub nk: edwards::Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> ViewingKey<E> {
    pub fn rk(&self, ar: E::Fs, params: &E::Params) -> edwards::Point<E, PrimeOrder> {
        self.ak.add(
            &params
                .generator(FixedGenerators::SpendingKeyGenerator)
                .mul(ar, params),
            params,
        )
    }

    pub fn ivk(&self) -> E::Fs {
        let mut preimage = [0; 64];

        self.ak.write(&mut preimage[0..32]).unwrap();
        self.nk.write(&mut preimage[32..64]).unwrap();

        let mut h = [0; 32];
        h.copy_from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::CRH_IVK_PERSONALIZATION)
                .hash(&preimage)
                .as_bytes(),
        );

        // Drop the most significant five bits, so it can be interpreted as a scalar.
        h[31] &= 0b0000_0111;

        let mut e = <E::Fs as PrimeField>::Repr::default();
        e.read_le(&h[..]).unwrap();

        E::Fs::from_repr(e).expect("should be a valid scalar")
    }

    pub fn to_payment_address(
        &self,
        diversifier: Diversifier,
        params: &E::Params,
    ) -> Option<PaymentAddress<E>> {
        diversifier.g_d(params).and_then(|g_d| {
            let pk_d = g_d.mul(self.ivk(), params);

            PaymentAddress::from_parts(diversifier, pk_d)
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d<E: JubjubEngine>(
        &self,
        params: &E::Params,
    ) -> Option<edwards::Point<E, PrimeOrder>> {
        group_hash::<E>(
            &self.0,
            constants::KEY_DIVERSIFICATION_PERSONALIZATION,
            params,
        )
    }
}

/// A Sapling payment address.
///
/// # Invariants
///
/// `pk_d` is guaranteed to be prime-order (i.e. in the prime-order subgroup of Jubjub,
/// and not the identity).
#[derive(Clone, Debug)]
pub struct PaymentAddress<E: JubjubEngine> {
    pk_d: edwards::Point<E, PrimeOrder>,
    diversifier: Diversifier,
}

impl<E: JubjubEngine> PartialEq for PaymentAddress<E> {
    fn eq(&self, other: &Self) -> bool {
        self.pk_d == other.pk_d && self.diversifier == other.diversifier
    }
}

impl<E: JubjubEngine> PaymentAddress<E> {
    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Returns None if `pk_d` is the identity.
    pub fn from_parts(
        diversifier: Diversifier,
        pk_d: edwards::Point<E, PrimeOrder>,
    ) -> Option<Self> {
        if pk_d == edwards::Point::zero() {
            None
        } else {
            Some(PaymentAddress { pk_d, diversifier })
        }
    }

    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Only for test code, as this explicitly bypasses the invariant.
    #[cfg(test)]
    pub(crate) fn from_parts_unchecked(
        diversifier: Diversifier,
        pk_d: edwards::Point<E, PrimeOrder>,
    ) -> Self {
        PaymentAddress { pk_d, diversifier }
    }

    /// Parses a PaymentAddress from bytes.
    pub fn from_bytes(bytes: &[u8; 43], params: &E::Params) -> Option<Self> {
        let diversifier = {
            let mut tmp = [0; 11];
            tmp.copy_from_slice(&bytes[0..11]);
            Diversifier(tmp)
        };
        // Check that the diversifier is valid
        if diversifier.g_d::<E>(params).is_none() {
            return None;
        }

        edwards::Point::<E, _>::read(&bytes[11..43], params)
            .ok()?
            .as_prime_order(params)
            .and_then(|pk_d| PaymentAddress::from_parts(diversifier, pk_d))
    }

    /// Returns the byte encoding of this `PaymentAddress`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0; 43];
        bytes[0..11].copy_from_slice(&self.diversifier.0);
        self.pk_d.write(&mut bytes[11..]).unwrap();
        bytes
    }

    /// Returns the [`Diversifier`] for this `PaymentAddress`.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// Returns `pk_d` for this `PaymentAddress`.
    pub fn pk_d(&self) -> &edwards::Point<E, PrimeOrder> {
        &self.pk_d
    }

    pub fn g_d(&self, params: &E::Params) -> Option<edwards::Point<E, PrimeOrder>> {
        self.diversifier.g_d(params)
    }

    pub fn create_note(
        &self,
        asset_type: AssetType<E>,
        value: u64,
        randomness: E::Fs,
        params: &E::Params
    ) -> Option<Note<E>>
    {
        self.g_d(params).map(|g_d| {
            Note {
                asset_type,
                value: value,
                r: randomness,
                g_d: g_d,
                pk_d: self.pk_d.clone()
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct Note<E: JubjubEngine> {
    /// The asset type that the note represents
    pub asset_type: AssetType<E>,
    /// The value of the note
    pub value: u64,
    /// The diversified base of the address, GH(d)
    pub g_d: edwards::Point<E, PrimeOrder>,
    /// The public key of the address, g_d^ivk
    pub pk_d: edwards::Point<E, PrimeOrder>,
    /// The commitment randomness
    pub r: E::Fs,
}

impl<E: JubjubEngine> PartialEq for Note<E> {
    fn eq(&self, other: &Self) -> bool {
        self.asset_type == other.asset_type
            && self.value == other.value
            && self.g_d == other.g_d
            && self.pk_d == other.pk_d
            && self.r == other.r
    }
}

impl<E: JubjubEngine> Note<E> {
    pub fn uncommitted() -> E::Fr {
        // The smallest u-coordinate that is not on the curve
        // is one.
        // TODO: This should be relocated to JubjubEngine as
        // it's specific to the curve we're using, not all
        // twisted edwards curves.
        E::Fr::one()
    }

    /// Computes the note commitment, returning the full point.
    fn cm_full_point(&self, params: &E::Params) -> edwards::Point<E, PrimeOrder> {
        // Calculate the note contents, as bytes
        let mut note_contents = vec![];

        // Write the asset type
        self.asset_type
            .value_commitment_generator(params)
            .write(&mut note_contents)
            .unwrap();

        // Writing the value in little endian
        (&mut note_contents)
            .write_u64::<LittleEndian>(self.value)
            .unwrap();

        // Write g_d
        self.g_d.write(&mut note_contents).unwrap();

        // Write pk_d
        self.pk_d.write(&mut note_contents).unwrap();

        assert_eq!(note_contents.len(), 
            32 + // asset_generator bytes
            32 + // g_d bytes 
            32 + // p_d bytes
            8 // value bytes
        );

        // Compute the Pedersen hash of the note contents
        let hash_of_contents = pedersen_hash(
            Personalization::NoteCommitment,
            note_contents
                .into_iter()
                .flat_map(|byte| (0..8).map(move |i| ((byte >> i) & 1) == 1)),
            params,
        );

        // Compute final commitment
        params
            .generator(FixedGenerators::NoteCommitmentRandomness)
            .mul(self.r, params)
            .add(&hash_of_contents, params)
    }

    /// Computes the nullifier given the viewing key and
    /// note position
    pub fn nf(&self, viewing_key: &ViewingKey<E>, position: u64, params: &E::Params) -> Vec<u8> {
        // Compute rho = cm + position.G
        let rho = self.cm_full_point(params).add(
            &params
                .generator(FixedGenerators::NullifierPosition)
                .mul(position, params),
            params,
        );

        // Compute nf = BLAKE2s(nk | rho)
        let mut nf_preimage = [0u8; 64];
        viewing_key.nk.write(&mut nf_preimage[0..32]).unwrap();
        rho.write(&mut nf_preimage[32..64]).unwrap();
        Blake2sParams::new()
            .hash_length(32)
            .personal(constants::PRF_NF_PERSONALIZATION)
            .hash(&nf_preimage)
            .as_bytes()
            .to_vec()
    }

    /// Computes the note commitment
    pub fn cm(&self, params: &E::Params) -> E::Fr {
        // The commitment is in the prime order subgroup, so mapping the
        // commitment to the x-coordinate is an injective encoding.
        self.cm_full_point(params).to_xy().0
    }
}

#[test]
fn test_value_commitment_generator() {
    use crate::{JUBJUB, ASSET_TYPE_DEFAULT};
    use pairing::bls12_381::{Fr, FrRepr};
    //use crate::jubjub::FsRepr;
    // x = 3790613555693612828818682379666141921367273985728786062989149673866758941597
    // y = 38047597154758313335818136376762946319677624718662006883117362874901807918505)
    let y_repr = FrRepr([
        0xaa5be3a88cbe6da9, 
        0xc0984861419d93fd, 
        0x645df9720449ef94, 
        0x541e2d45da62a4fd
    ]);

    let asset = ASSET_TYPE_DEFAULT.clone();
    let p = asset.value_commitment_generator(&JUBJUB);
    println!("{:?}", asset.get_identifier());

    // [244, 69, 109, 192, 127, 68, 191, 17, 135, 229, 105, 236, 141, 18, 193, 29, 199, 205, 139, 99, 9, 198, 96, 154, 118, 8, 227, 188, 144, 55, 118, 237]
    ///sage
    // [169, 109, 190, 140, 168, 227, 91, 170, 253, 147, 157, 65, 97, 72, 152, 192, 148, 239, 73, 4, 114, 249, 93, 100, 253, 164, 98, 218, 69, 45, 30, 84]

    if let Ok(y) = Fr::from_repr(y_repr) {
        let xy = p.to_xy();
        let p_y = xy.1.into_repr();
        println!("{}", p_y.as_ref()[0]);
        println!("{}", p_y.as_ref()[1]);
        println!("{}", p_y.as_ref()[2]);
        println!("{}", p_y.as_ref()[3]);

        //println!("{}", y);
        assert_eq!(xy.1, y);
    } else {
        assert!(false);
    }
    //assert_eq!(p.1[1], y[1]);
    //assert_eq!(p.1[2], y[2]);
    //assert_eq!(p.1[3], y[3]);

}