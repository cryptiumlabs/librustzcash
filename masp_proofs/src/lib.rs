//! *MASP circuits and proofs.*
//!
//! `masp_proofs` contains the zk-SNARK circuits used by MASP, and the APIs for creating
//! and verifying proofs.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

use bellman::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey};
use bls12_381::Bls12;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

#[cfg(feature = "directories")]
use directories::BaseDirs;
#[cfg(feature = "directories")]
use std::path::PathBuf;

pub mod circuit;
mod constants;
pub use zcash_proofs::hashreader;
pub mod sapling;

#[cfg(any(feature = "local-prover", feature = "bundled-prover"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "local-prover", feature = "bundled-prover")))
)]
pub mod prover;

// Circuit names
#[cfg(feature = "local-prover")]
const MASP_SPEND_NAME: &str = "masp-spend.params";
#[cfg(feature = "local-prover")]
const MASP_OUTPUT_NAME: &str = "masp-output.params";

// Circuit hashes
const MASP_SPEND_HASH: &str = "5523057113d7daa078714f9859ea03da3c959f4fe3756a0ace4eb25f7cf41d1e21099dac768c2e0045400fee03c1f8bc14eeac2190c3f282e0092419d3b967e5";
const MASP_OUTPUT_HASH: &str = "89fe551ad6c0281aebb857eb203dbf35854979503d374c83b12512dcd737e12a255869a34e3ff0f6609b78accc81ea5f5e94202e124a590730494eeeee86e755";

#[cfg(feature = "download-params")]
const DOWNLOAD_URL: &str = "https://download.z.cash/downloads";

/// Returns the default folder that the Zcash proving parameters are located in.
#[cfg(feature = "directories")]
#[cfg_attr(docsrs, doc(cfg(feature = "directories")))]
pub fn default_params_folder() -> Option<PathBuf> {
    BaseDirs::new().map(|base_dirs| {
        if cfg!(any(windows, target_os = "macos")) {
            base_dirs.data_dir().join("MASPParams")
        } else {
            base_dirs.home_dir().join(".masp-params")
        }
    })
}

/// Download the Zcash Sapling parameters, storing them in the default location.
///
/// This mirrors the behaviour of the `fetch-params.sh` script from `zcashd`.
#[cfg(feature = "download-params")]
#[cfg_attr(docsrs, doc(cfg(feature = "download-params")))]
pub fn download_parameters() -> Result<(), minreq::Error> {
    // Ensure that the default Zcash parameters location exists.
    let params_dir = default_params_folder().ok_or(io::Error::new(
        io::ErrorKind::Other,
        "Could not load default params folder",
    ))?;
    std::fs::create_dir_all(&params_dir)?;

    let fetch_params = |name: &str, expected_hash: &str| -> Result<(), minreq::Error> {
        use std::io::Write;

        // Download the parts directly (Sapling parameters are small enough for this).
        let part_1 = minreq::get(format!("{}/{}.part.1", DOWNLOAD_URL, name)).send()?;
        let part_2 = minreq::get(format!("{}/{}.part.2", DOWNLOAD_URL, name)).send()?;

        // Verify parameter file hash.
        let hash = blake2b_simd::State::new()
            .update(part_1.as_bytes())
            .update(part_2.as_bytes())
            .finalize()
            .to_hex();
        if &hash != expected_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} failed validation (expected: {}, actual: {}, fetched {} bytes)",
                    name,
                    expected_hash,
                    hash,
                    part_1.as_bytes().len() + part_2.as_bytes().len()
                ),
            )
            .into());
        }

        // Write parameter file.
        let mut f = File::create(params_dir.join(name))?;
        f.write_all(part_1.as_bytes())?;
        f.write_all(part_2.as_bytes())?;
        Ok(())
    };

    fetch_params(MASP_SPEND_NAME, MASP_SPEND_HASH)?;
    fetch_params(MASP_OUTPUT_NAME, MASP_OUTPUT_HASH)?;

    Ok(())
}

pub fn load_parameters(
    spend_path: &Path,
    output_path: &Path,
) -> (
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
) {
    // Load from each of the paths
    let spend_fs = File::open(spend_path).expect("couldn't load MASP spend parameters file");
    let output_fs = File::open(output_path).expect("couldn't load MASP output parameters file");

    parse_parameters(
        BufReader::with_capacity(1024 * 1024, spend_fs),
        BufReader::with_capacity(1024 * 1024, output_fs),
    )
}

fn parse_parameters<R: io::Read>(
    spend_fs: R,
    output_fs: R,
) -> (
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
    Parameters<Bls12>,
    PreparedVerifyingKey<Bls12>,
) {
    let mut spend_fs = hashreader::HashReader::new(spend_fs);
    let mut output_fs = hashreader::HashReader::new(output_fs);

    // Deserialize params
    let spend_params = Parameters::<Bls12>::read(&mut spend_fs, false)
        .expect("couldn't deserialize MASP spend parameters file");
    let output_params = Parameters::<Bls12>::read(&mut output_fs, false)
        .expect("couldn't deserialize MASP spend parameters file");

    // There is extra stuff (the transcript) at the end of the parameter file which is
    // used to verify the parameter validity, but we're not interested in that. We do
    // want to read it, though, so that the BLAKE2b computed afterward is consistent
    // with `b2sum` on the files.
    let mut sink = io::sink();
    io::copy(&mut spend_fs, &mut sink)
        .expect("couldn't finish reading MASP spend parameter file");
    io::copy(&mut output_fs, &mut sink)
        .expect("couldn't finish reading MASP output parameter file");

    if spend_fs.into_hash() != MASP_SPEND_HASH {
        panic!("MASP spend parameter file is not correct, please clean your `~/.masp-params/` and re-run `fetch-params`.");
    }

    if output_fs.into_hash() != MASP_OUTPUT_HASH {
        panic!("MASP output parameter file is not correct, please clean your `~/.masp-params/` and re-run `fetch-params`.");
    }

    // Prepare verifying keys
    let spend_vk = prepare_verifying_key(&spend_params.vk);
    let output_vk = prepare_verifying_key(&output_params.vk);

    (spend_params, spend_vk, output_params, output_vk)
}
