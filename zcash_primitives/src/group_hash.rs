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


    // The following loop exists because of the (extremely small) probability of
    // hashing to a point in a small order subgroup. Since the JubJub curve is the
    // direct sum of a small order subgroup with a large prime order subgroup,
    // the tag could hash to the identity in the prime order subgroup
    // Since the prime order subgroup is large, this is unlikely to happen, so this
    // loop is expected to run only once
    // When it (rarely) hashes badly, detect this by multiplying by the cofactor
    // which gives the identity when the hash is in the small order subgroup.
    // Similarly, the assertion is unlikely to trigger
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
