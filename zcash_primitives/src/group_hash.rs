//! Implementation of [group hashing into Jubjub][grouphash].
//!
//! [grouphash]: https://zips.z.cash/protocol/protocol.pdf#concretegrouphashjubjub

use crate::jubjub::{edwards, JubjubEngine, PrimeOrder};

use ff::PrimeField;

use crate::constants;
use blake2s_simd::Params;

/// Produces a random point in the Jubjub curve.
/// The point is guaranteed to be prime order
/// and not the identity.
pub fn group_hash<E: JubjubEngine>(
    tag: &[u8],
    personalization: &[u8],
    params: &E::Params,
) -> Option<edwards::Point<E, PrimeOrder>> {
    assert_eq!(personalization.len(), 8);

    // Check to see that scalar field is 255 bits
    assert!(E::Fr::NUM_BITS == 255);

    let h = Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state()
        .update(constants::GH_FIRST_BLOCK)
        .update(tag)
        .finalize();

    match edwards::Point::<E, _>::read(h.as_ref(), params) {
        Ok(p) => {
            let p = p.mul_by_cofactor(params);

            if p != edwards::Point::zero() {
                Some(p)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

pub fn find_group_hash<E: JubjubEngine>(
    m: &[u8],
    personalization: &[u8; 8],
    params: &E::Params
) -> edwards::Point<E, PrimeOrder>
{
    let mut tag = m.to_vec();
    let i = tag.len();
    tag.push(0u8);

    // Rejection sampling hash to curve point:
    // The following loop exists because hashing a tag to a group element
    // (point on the JubJub curve) can fail in one of three ways:
    //
    // 1. The tag could hash to a small order point on the curve. Since the JubJub
    // curve is the direct sum of a small order subgroup with a large 
    // prime order subgroup, the BLAKE2s image of the tag may be the y
    // coordinate of a small order point on the curve, and so when 
    // multiplied by the cofactor gives the identity. The small order subgroup
    // contains very few elements, so the probability of hashing to one of these 
    // points is extremely small (exponentially small).
    // Tags whose BLAKE2s hash is a small order point are rejected.
    // 
    // 2. The tag could hash to a 255 bit integer that is at least the modulus 
    // of the underlying field of the JubJub curve, and therefore is not a 
    // valid field element unless taken modulo the order of the field.
    // The probability of this event is approximately 9.431% and so it occurs
    // reasonably often.
    // Tags whose BLAKE2s hash is larger than the field modulus are rejected.
    // 
    // 3. The tag could hash to a field element such that no point on 
    // the curve has that y coordinate. Then it is not possible to interpret
    // the BLAKE2s hash image as a curve point/group element at all.
    // The probability of this event is approximately (but not precisely) 1/2
    // Tags whose BLAKE2s hash is not the y coordinate of some curve point 
    // are rejected.
    //
    // The overall probability that a uniformly random tag hashes successfully
    // is approximately 0.5 * 0.9057 = 0.453 and so the expected
    // number of loops is approximately 2.2

    loop {
        let gh = group_hash(
            &tag,
            personalization,
            params
        );

        // We don't want to overflow and start reusing generators
        assert!(tag[i] != u8::max_value());
        tag[i] += 1;

        if let Some(gh) = gh {
            break gh;
        }
    }
}
