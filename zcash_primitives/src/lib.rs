//! *General Zcash primitives.*
//!
//! `zcash_primitives` is a library that provides the core structs and functions necessary
//! for working with Zcash.

// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

use lazy_static::lazy_static;

pub mod block;
pub mod consensus;
pub mod constants;
pub mod group_hash;
pub mod jubjub;
pub mod keys;
pub mod legacy;
pub mod merkle_tree;
pub mod note_encryption;
pub mod pedersen_hash;
pub mod primitives;
pub mod prover;
pub mod redjubjub;
pub mod sapling;
pub mod serialize;
pub mod transaction;
mod util;
pub mod zip32;

#[cfg(test)]
mod test_vectors;

use crate::jubjub::JubjubBls12;
use crate::primitives::AssetType;
use pairing::bls12_381::Bls12;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };

    pub static ref ASSET_TYPE_DEFAULT: AssetType<Bls12> = AssetType::<Bls12>::new(b"default", None, &JUBJUB);
}
