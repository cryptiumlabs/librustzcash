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

        blake2s_state.update(constants::GH_FIRST_BLOCK)
            .update(&name);
        
        loop {
            let h = blake2s_state.finalize();
            if AssetType::<E>::hash_to_point(h.as_array(), params).is_some() {
                break AssetType::<E>{ identifier: *h.as_array(), _marker: PhantomData };
            }
            blake2s_state.update(h.as_ref());
        }
    }
    fn hash_to_point(
        identifier: &[u8; 32], 
        params: &E::Params,
    ) -> Option<edwards::Point<E, Unknown>> {
        assert_eq!(constants::VALUE_COMMITMENT_GENERATOR_PERSONALIZATION.len(), 8);

        // Check to see that scalar field is 255 bits
        assert!(E::Fr::NUM_BITS == 255);

        let h = Blake2sParams::new()
            .hash_length(32)
            .personal(constants::VALUE_COMMITMENT_GENERATOR_PERSONALIZATION)
            .to_state()
            .update(identifier)
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
    pub fn identifier_bits(&self) -> Vec<Option<bool>> {
        self.get_identifier()
            .iter()
            .flat_map(|&v| (0..8).map(move |i| Some((v >> i) & 1 == 1)))
            .collect()
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
        // it"s specific to the curve we're using, not all
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
        [0xe0879910d871cb2b, 0xfb7a2ceffe853a20, 0xd7d14c48a4944d37, 0x05037eb3b92f6bf7], 
        [0x96545c483d30090b, 0x23fc05c78d8028bd, 0x536b953d5e65b99d, 0x4f090f1172f171ae], 
        [0x86dc9613aa7ca240, 0x66d1d90259c02cc2, 0x4dcdcbc1a91e6192, 0x6489b3ab46560072], 
        [0xd3c14bf30517dce0, 0x292a846661ed0a5e, 0xeb422e217ad53bea, 0x5df6c90834104bdb], 
        [0x9189788cdec335f9, 0xbb94b9ccbbe7772d, 0x9a7ac632fda3f0d8, 0x69c86d931a07b522], 
        [0x6ac4addc39f1233f, 0xde7626dbea4f0bce, 0xf248583018c6084d, 0x17734e1f30d51a54], 
        [0xea44fe5bc5eafefe, 0x1775f40b34be866c, 0xb0e9f36585ad17d3, 0x6f4ea7c3c2a937b3], 
        [0x9b87bcaf37b4e815, 0x84f4b87cca8589c7, 0x0679c9b5bec619ff, 0x55d40c7c71ec2653], 
        [0x68ebdf3f6d025f46, 0xc1856dee8140b734, 0x19d8f6c6770a3b68, 0x3c08a74c4daaaeb0], 
        [0xc4f9e1dc37cf7a7c, 0x5f65d49689b13e3c, 0x4809ab4a798710cb, 0x298b75bd60e8515f], 
        [0x545d366cf3de078c, 0xbc8eb83a9172483a, 0x650e41c1f9f4be93, 0x690db47d6662907d], 
        [0xeb92094630617ffb, 0x46927e8d1c10fa35, 0x4a102a7b7645e008, 0x7365da37f711b5db], 
        [0xac5fb48d2fee3bfa, 0x8e5ffa1f5af9b11a, 0x93605f7270d15d70, 0x2e9a1d01a2540b81], 
    ];

    let test_asset_y = vec![
        [0x60df5ed73f0d76f0, 0x5c879f102de6ff9c, 0xe147060d1b0352a, 0x2fec7b1f2a0df2cb], 
        [0xa02f5a976bbbeb6c, 0x42c9411d8c2475d0, 0x3d0e7d283c1e2649, 0x5035512106f2e271], 
        [0xdbc237631a6dc574, 0xcf07d4b501ac1f30, 0xc77f9418d7b44638, 0x4c560a3017720d59], 
        [0x5303f78241a0d89, 0x7840d04761a77c4d, 0x11e714cfc1c6fc81, 0x69545ca858c70149], 
        [0x97b445cf29abb41f, 0xb22d481b003857be, 0xcfad7a7669c3731, 0x3bc5c9f5d36a2bee], 
        [0xca6ecc0c4f498694, 0x10851027ebd70d4e, 0x4c7080b7dc866972, 0x4fa38d1be066b7c1], 
        [0xb01b90f645c755e1, 0xe020578452853993, 0x248dae4cac54d407, 0x4a5347ed7ccb9133], 
        [0xa891abd9dfecd5d3, 0xff2cddc1942824f3, 0xa989cd40c7143556, 0x49c4987bd1511d1c], 
        [0x64d7f8493742c418, 0x24f3ed7c66fb9a5a, 0xb26184b6929d5ee1, 0x26cf96947b196f43], 
        [0xbe7312d347802253, 0x9b492d07c10e0aa, 0xcee6006c5011f005, 0xa9b4730d17c9712], 
        [0x8dd0193dea871cf4, 0x9bc9b110f84a8fd5, 0x18b6ce6d237a572d, 0x3032be91e07999df], 
        [0xceac2f393ed6f78e, 0xde3497c1d2829ed2, 0x46cd16cddd9ac241, 0x604a56bfe040559a], 
        [0x414ea56a70d41865, 0x901a88554fd0d29, 0x48b7a1788e8ab76e, 0x404bd595dc14cb7c], 
    ];
    
    for i in 0..13 {
        let asset = &test_assets[i];
        let x = Fr::from_repr(FrRepr(test_asset_x[i])).expect("Test case value generator x invalid");
        let y = Fr::from_repr(FrRepr(test_asset_y[i])).expect("Test case value generator y invalid");
        let p = asset.value_commitment_generator(&JUBJUB);

        assert_eq!(p.to_xy().0, x);
        assert_eq!(p.to_xy().1, y);
    }
}