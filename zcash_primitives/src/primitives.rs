//! Structs for core Zcash primitives.

use ff::{Field, PrimeField, PrimeFieldRepr};

use crate::constants;

use crate::group_hash::group_hash;

use crate::pedersen_hash::{pedersen_hash, Personalization};

use byteorder::{LittleEndian, WriteBytesExt};

use crate::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, PrimeOrder, Unknown};

use blake2s_simd::Params as Blake2sParams;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct AssetType<E: JubjubEngine> {
    identifier: [u8; constants::ASSET_IDENTIFIER_LENGTH], //32 byte asset type preimage
    _marker: PhantomData<E>,
}

// Abstract type representing an asset
impl<E: JubjubEngine> AssetType<E> {
    /// Create a new AssetType from a unique asset name
    pub fn new(
        name: &[u8], 
        params: &E::Params,
    ) -> AssetType::<E> {

        // Check the personalization is acceptable length
        assert_eq!(constants::ASSET_IDENTIFIER_PERSONALIZATION.len(), 8);

        // Create a new BLAKE2s state for deriving the asset identifier
        let mut blake2s_state = Blake2sParams::new()
            .hash_length(constants::ASSET_IDENTIFIER_LENGTH)
            .personal(constants::ASSET_IDENTIFIER_PERSONALIZATION)
            .to_state();

        // Hash the random beacon and asset name
        blake2s_state.update(constants::GH_FIRST_BLOCK)
            .update(&name);
        
        loop {
            let h = blake2s_state.finalize();
            
            // If the hash state is a valid asset identifier, use it
            if AssetType::<E>::hash_to_point(h.as_array(), params).is_some() {
                break AssetType::<E>{ identifier: *h.as_array(), _marker: PhantomData };
            }

            // Otherwise, rehash the output into itself
            blake2s_state.update(h.as_ref());
        }
    }

    // Attempt to hash an identifier to a curve point
    fn hash_to_point(
        identifier: &[u8; ASSET_IDENTIFIER_LENGTH], 
        params: &E::Params,
    ) -> Option<edwards::Point<E, Unknown>> {

        // Check the personalization is acceptable length
        assert_eq!(constants::VALUE_COMMITMENT_GENERATOR_PERSONALIZATION.len(), 8);

        // Check to see that scalar field is 255 bits
        assert!(E::Fr::NUM_BITS == 255);

        let h = Blake2sParams::new()
            .hash_length(32)
            .personal(constants::VALUE_COMMITMENT_GENERATOR_PERSONALIZATION)
            .to_state()
            .update(identifier)
            .finalize();
 
        // Check to see if the BLAKE2s hash of the identifier is on the curve
        if let Ok(p) = edwards::Point::<E, _>::read(h.as_ref(), params) {
            // Check to see if the hashed point is small order
            if p.mul_by_cofactor(params) != edwards::Point::zero() {
                // If not small order, return *without* clearing the cofactor
                return Some(p);
            }
        } 
        None // invalid asset identifier
    }

    /// Return the identifier of this asset type
    pub fn get_identifier(&self) -> &[u8; constants::ASSET_IDENTIFIER_LENGTH] {
        &self.identifier
    }

    /// Attempt to construct an asset type from an existing asset identifier
    pub fn from_identifier(
        identifier : &[u8 ; constants::ASSET_IDENTIFIER_LENGTH],
        params: &E::Params,
    ) -> Option<AssetType::<E>> {
        
        // Attempt to hash to point
        if AssetType::<E>::hash_to_point(identifier, params).is_some() {
            Some(AssetType::<E>{ identifier : *identifier, _marker: PhantomData })
        } else {
            None // invalid asset identifier
        }
    }

    /// Produces an asset generator without cofactor cleared
    pub fn asset_generator(
        &self,
        params: &E::Params,
    ) -> edwards::Point<E, Unknown> {
        AssetType::<E>::hash_to_point(self.get_identifier(), params)
            .expect("AssetType internal identifier state inconsistent")
    }

    /// Produces a value commitment generator with cofactor cleared
    pub fn value_commitment_generator(
        &self,
        params: &E::Params,
    ) -> edwards::Point<E, PrimeOrder> {
        self.asset_generator(params).mul_by_cofactor(params)
    }

    /// Get the asset identifier as a vector of bools
    pub fn identifier_bits(&self) -> Vec<Option<bool>> {
        self.get_identifier()
            .iter()
            .flat_map(|&v| (0..8).map(move |i| Some((v >> i) & 1 == 1)))
            .collect()
    }
    
    /// Construct a value commitment from given value and randomness
    pub fn value_commitment(
        &self,
        value: u64,
        randomness: E::Fs,
        params: &E::Params,
    ) -> ValueCommitment<E> {
        ValueCommitment::<E> {
            asset_generator: self.asset_generator(params),
            value,
            randomness,
        }
    }
}

impl<E: JubjubEngine> Copy for AssetType<E> { }

impl<E: JubjubEngine> Clone for AssetType<E> {
    fn clone(&self) -> Self { 
        AssetType::<E> {
            identifier: self.identifier,
            _marker: PhantomData,
        }
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
        self.asset_generator
            .mul_by_cofactor(params) // clear cofactor before using
            .mul(self.value, params)
            .add(
                &params
                    .generator(FixedGenerators::ValueCommitmentRandomness)
                    .mul(self.randomness, params),
                    params,
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
            .asset_generator(params) // Cofactor not cleared
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
    use crate::{JUBJUB};
    use pairing::bls12_381::{Bls12, Fr, FrRepr};

    let test_assets = vec![ AssetType::<Bls12>::new(b"default", &JUBJUB),
        AssetType::<Bls12>::new(b"", &JUBJUB), 
        AssetType::<Bls12>::new(b"The Magic Words are Squeamish Ossifrage", &JUBJUB),
        AssetType::<Bls12>::new(b"AliceToken", &JUBJUB),
        AssetType::<Bls12>::new(b"BobToken", &JUBJUB),
        AssetType::<Bls12>::new(b"EveToken", &JUBJUB),
        AssetType::<Bls12>::new(b"JoeToken", &JUBJUB),
        AssetType::<Bls12>::new(constants::GH_FIRST_BLOCK, &JUBJUB),
        AssetType::<Bls12>::new(b"3.1415926535 8979323846 2643383279", &JUBJUB),
        AssetType::<Bls12>::new(b"KT1000000000000000000000000000000000000", &JUBJUB),
        AssetType::<Bls12>::new(b"KT1ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", &JUBJUB),
        AssetType::<Bls12>::new(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &JUBJUB), 
        AssetType::<Bls12>::new(b"\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf0", &JUBJUB),
    ];

    let test_asset_x = vec![
        [0x1c0b9dd3c1e32b2c, 0x93a209a48966adda, 0xf7b09627ec4e07c0, 0x0a239cdca7f9e681], 
        [0x974b7dddeda05977, 0xd4ef35aa8c139b15, 0x2783bbcc28a9d7fe, 0x45e7b2c6a5c3f153], 
        [0x93d0e2440d2b934d, 0xc7a2c7c7f149fa68, 0xef2f94225c0cbbe9, 0x40ecc9793c238921], 
        [0x03b640150bbc55dc, 0x766875ef478d8a43, 0xf4eb51ebb5db7554, 0x59c27c261b952991], 
        [0xdf43daeeb6530ea7, 0x846a4f2f4415c4c0, 0x922a8e3815bfaa90, 0x5bdcd8f5f0f586f6], 
        [0x8facfbcffebe75dc, 0xbd3560878dc50c4a, 0x575f593adf330127, 0x70a8b8a4a03e0f4f], 
        [0x8fcf1d2c3d11c244, 0x0d41c9c9c6b7d19c, 0x0444f7af697b4a22, 0x2d22190c7ba048f5], 
        [0x0b8280a215d19f7b, 0xee140ffda101c9b5, 0x9ceefa770fd3d857, 0x5268a3740214b8d0], 
        [0x476c52f34ed73c26, 0x62a4d4cdfe9bd17a, 0x2986bb6c9152ae15, 0x165f1e99cd4cb450], 
        [0xb6a90e836ffef9b4, 0x0c88c466d77369ef, 0xbfc7290bea098a8c, 0x5fb353290e00c1d6], 
        [0x31932dc7744b68ee, 0x1c7ef583d808a42d, 0x896d632b86fdc452, 0x1800b830e1d8f024], 
        [0x9d790c36a597149c, 0xa9758d2c6cf58210, 0x2eaf907878d4ca14, 0x6bb34f8ce656aab2], 
        [0xfeceaafb3a075a49, 0x5e5757eb70163a7e, 0x78c265970b9494f1, 0x44a601617fa4a106], 
    ];
    let test_asset_y = vec![
        [0x557ca8bd3ab90632, 0x4abc28769a4b6eb2, 0x4b37d10d60b0ebc6, 0x3c18b8c104abd547], 
        [0x5f62d7855be9a32b, 0x20d9e8762ab65412, 0xbbcb12f7149712e9, 0x6fc7b78767f782c8], 
        [0x9cc454c1007f7786, 0x20859a2b98ffbfe2, 0xd414b0cdf860b271, 0x309b0581fee203fa], 
        [0x49ee0fe075aa348a, 0xe89b7b327745ab64, 0xb5486988abd53c3, 0x3d67a89c0fcd3d3b], 
        [0x2cb14ab7fff092e2, 0xd75e6ce86c5bd76f, 0x2858179d891a581d, 0x538bb4812e5c24e7], 
        [0x916e70b879b2e823, 0xb90ab682ef9fb386, 0x601bb2033ef3e19, 0x10b7ef0c16b0c544], 
        [0xa86469d4364fda4c, 0x19c7391e088b0e30, 0xa1e5454533dc3c78, 0x104bf76da39b6b0f], 
        [0x95315488b7aaaadf, 0xba288f74d59cb97, 0x896dd7d03b708e44, 0x53ff4ed77c5b075], 
        [0x182a5c8ab081b9e, 0x74072f96723f63a3, 0x30c1245bc40ac999, 0x63b136ba2fc1ef7f], 
        [0xb4b96a2163e990da, 0x2d3a98bef113afff, 0xe79e33d49c57c055, 0x338bdf7465e11260], 
        [0x95716344b39bba22, 0x8a167e7749867aa0, 0x1d6f8fa715af2856, 0x17c259e78e0532c1], 
        [0x80ce09c051c482e2, 0x9f3e611ba2d3f2e3, 0xebace3e438c2ce2e, 0x5cf111c5d0499147], 
        [0x3b7ffb7dd82ab26e, 0xc31288116810e8e0, 0x62ccbfde95d1c29, 0x55eccb099c2a442a], 
    ];
    
    for i in 0..13 {
        let asset = &test_assets[i];
        let x = Fr::from_repr(FrRepr(test_asset_x[i])).expect("Test case value generator x invalid");
        let y = Fr::from_repr(FrRepr(test_asset_y[i])).expect("Test case value generator y invalid");
        let p = asset.asset_generator(&JUBJUB);

        assert_eq!(p.to_xy().0, x);
        assert_eq!(p.to_xy().1, y);
    }
}
