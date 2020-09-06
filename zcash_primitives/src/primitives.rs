//! Structs for core Zcash primitives.

use ff::{Field, PrimeField, PrimeFieldRepr};

use crate::constants;

use crate::group_hash::group_hash;

use crate::pedersen_hash::{pedersen_hash, Personalization};

use byteorder::{LittleEndian, WriteBytesExt};

use crate::jubjub::{edwards, FixedGenerators, JubjubEngine, JubjubParams, PrimeOrder, Unknown};
use crate::constants::{
    ASSET_IDENTIFIER_LENGTH, 
    ASSET_IDENTIFIER_PERSONALIZATION,
    VALUE_COMMITMENT_GENERATOR_PERSONALIZATION,
    GH_FIRST_BLOCK,
};

use blake2s_simd::Params as Blake2sParams;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct AssetType<E: JubjubEngine> {
    identifier: [u8; ASSET_IDENTIFIER_LENGTH], //32 byte asset type preimage
    nonce: Option<u8>,
    _marker: PhantomData<E>,
}

// Abstract type representing an asset
impl<E: JubjubEngine> AssetType<E> {
    /// Create a new AssetType from a unique asset name
    pub fn new(
        name: &[u8], 
        nonce: Option<u8>,
        params: &E::Params,
    ) -> AssetType::<E> {
        use std::slice::from_ref;
        let nonce = nonce.unwrap_or(0b0);

        // Check the personalization is acceptable length
        assert_eq!(ASSET_IDENTIFIER_PERSONALIZATION.len(), 8);

        // Create a new BLAKE2s state for deriving the asset identifier
        let h = Blake2sParams::new()
            .hash_length(ASSET_IDENTIFIER_LENGTH)
            .personal(ASSET_IDENTIFIER_PERSONALIZATION)
            .to_state()
            .update(GH_FIRST_BLOCK)
            .update(&name)
            .update(from_ref(&nonce))
            .finalize();
        
        // If the hash state is a valid asset identifier, use it
        if AssetType::<E>::hash_to_point(h.as_array(), params).is_some() {
            AssetType::<E> { 
                identifier: *h.as_array(), 
                nonce: Some(nonce),
                _marker: PhantomData 
            }
        } else {
            AssetType::<E>::new(name, 
                Some(nonce.checked_add(1).unwrap()), 
                params)
        }
    }

    // Attempt to hash an identifier to a curve point
    fn hash_to_point(
        identifier: &[u8; ASSET_IDENTIFIER_LENGTH], 
        params: &E::Params,
    ) -> Option<edwards::Point<E, Unknown>> {

        // Check the personalization is acceptable length
        assert_eq!(VALUE_COMMITMENT_GENERATOR_PERSONALIZATION.len(), 8);

        // Check to see that scalar field is 255 bits
        assert!(E::Fr::NUM_BITS == 255);

        let h = Blake2sParams::new()
            .hash_length(32)
            .personal(VALUE_COMMITMENT_GENERATOR_PERSONALIZATION)
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
            Some(AssetType::<E> { 
                identifier : *identifier, 
                nonce: None,
                _marker: PhantomData })
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
            nonce: self.nonce,
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

    let test_assets = vec![ AssetType::<Bls12>::new(b"default", None, &JUBJUB),
        AssetType::<Bls12>::new(b"", None, &JUBJUB), 
        AssetType::<Bls12>::new(b"The Magic Words are Squeamish Ossifrage", None, &JUBJUB),
        AssetType::<Bls12>::new(b"AliceToken", None, &JUBJUB),
        AssetType::<Bls12>::new(b"BobToken", None, &JUBJUB),
        AssetType::<Bls12>::new(b"EveToken", None, &JUBJUB),
        AssetType::<Bls12>::new(b"JoeToken", None, &JUBJUB),
        AssetType::<Bls12>::new(constants::GH_FIRST_BLOCK, None, &JUBJUB),
        AssetType::<Bls12>::new(b"3.1415926535 8979323846 2643383279", None, &JUBJUB),
        AssetType::<Bls12>::new(b"KT1000000000000000000000000000000000000", None, &JUBJUB),
        AssetType::<Bls12>::new(b"KT1ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", None, &JUBJUB),
        AssetType::<Bls12>::new(b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", None, &JUBJUB), 
        AssetType::<Bls12>::new(b"\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xf0", None, &JUBJUB),
    ];

    let test_asset_x = vec![
        [0xd0d1cc06e2a8c701, 0xecab2b6a5908c621, 0x88abc909d17e51b7, 0x0ad06a441281655e], 
        [0xe7af6c91597b7921, 0x8ade9e54dcac82ae, 0x5497c2ebb30f3a84, 0x7033a0446d8a9350], 
        [0x4fda04bc89a203f8, 0xc55340f842dc0f89, 0xd5b2d35aee48d836, 0x3fefc22e7f0a1bd1], 
        [0xd17196ec0caf78da, 0x29e1f0eef037540e, 0xfabf35ce1af8ef7b, 0x3af46478aeafe66a], 
        [0x317ded582a091e9f, 0x3a33a3df191c68b4, 0x602ec7972517579c, 0x219f52d8610a5c83], 
        [0x50c2c952795e3336, 0x63534ee96fb982b5, 0x63496060759c946f, 0x4276d7c083f357a7], 
        [0x13768db213dc1b8e, 0xe1b98eb8b1a6ae98, 0x3c57c5f7b955b9cf, 0x0a4e19501f85d545], 
        [0x4c32e4dab2ea62c2, 0x55c29e841191c66d, 0x8a856f4a677f542a, 0x3a63915c45a8c3b0], 
        [0xe3287daa11aafce2, 0xf76cea51aa02d844, 0x181d743be7b7855a, 0x16ff2846ad7863ca], 
        [0x2b9653afafc511a3, 0x5558627be2acb664, 0x361870285f691601, 0x62c5d9ce81a929e8], 
        [0x6a293bb13f3c6503, 0x5706f289dd18dc1b, 0x306f3f7742c52ab7, 0x593b3c1ab9b56366], 
        [0x25d73914273b4c8d, 0x6f71608af99a25d8, 0xe74e3635ff27eb28, 0x3841cc32274ca184], 
        [0xd5a580695b6a1c1d, 0x037b0b789edb0468, 0x47e836a82bea2ef2, 0x48de21241d412e54], 
        ];
    let test_asset_y = vec![
        [0x9bcac7532f04e919, 0x961da8bf207edb87, 0xc3c627ca7d362f99, 0x5efe1928acc90404], 
        [0xdb9e7c485fa2d6c9, 0xa6171e2bb3c5dd26, 0xe37c6f10d978ccd2, 0x6b21a02247f361e9], 
        [0xaa97101ca0d34db2, 0x1815d4cbef70f8f1, 0x83a35895d1dbe23d, 0x5d119aa42dc87aab], 
        [0xd5dc174369eaa894, 0x305bfecbe41ba747, 0xf88af722acb2535c, 0x36452685cea5789c], 
        [0xe2c02a85e15f5d29, 0xb1782310436ade8b, 0x4f90be1af7ece152, 0x1fe001f090d63785], 
        [0x71357d8dcfdc713, 0xbe63f8b3d5406d7c, 0xf40709a8cb71b14e, 0x654f65c12316c371], 
        [0x223d151d5d6aae3a, 0xf2ee1b3949f098a6, 0x2114a1e2d31aa2a9, 0x400837888df6d6e2], 
        [0xc7ec82a0d7469979, 0xa72cb6d5f5e41cc5, 0xc6695fc13a620157, 0x662c16464ba01ddd], 
        [0xcf8bb99b7698dab7, 0x9bfeeba948524ac5, 0x21b316672fa0f7fa, 0x1a08da6e6dcee341], 
        [0x5156307ea5c86dce, 0xb5f4b87dbafa641a, 0xb98d68e1313b4992, 0x6da0b1c852934297], 
        [0x1d816301cb3ac4ee, 0xf38db6cbc7c9b57a, 0xb898f40a35634fa, 0x420fa77b59469d81], 
        [0x106d91449269de4d, 0xb48c4043d6b5a31d, 0xeab7f990979121eb, 0x40ae4b1f9b7e1ecf], 
        [0xe72a4f850a992e21, 0x8850787ee5ec4ebc, 0x5d02f5fc81d332de, 0x70ba444f140875eb], 
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
