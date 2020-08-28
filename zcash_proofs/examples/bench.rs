use bellman::groth16::*;
use ff::Field;
use pairing::bls12_381::{Bls12, Fr};
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::time::{Duration, Instant};
use zcash_primitives::jubjub::{edwards, fs, JubjubBls12};
use zcash_primitives::primitives::{Diversifier, ProofGenerationKey, ValueCommitment};
use zcash_primitives::ASSET_TYPE_DEFAULT;
use zcash_proofs::circuit::sapling::{Spend, Output};

const TREE_DEPTH: usize = 32;

fn main() {
    let jubjub_params = &JubjubBls12::new();
    let rng = &mut XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    println!("Creating sample Spend parameters...");
    /*let groth_spend_params = generate_random_parameters::<Bls12, _, _>(
        Spend {
            params: jubjub_params,
            value_commitment: None,
            proof_generation_key: None,
            payment_address: None,
            commitment_randomness: None,
            ar: None,
            auth_path: vec![None; TREE_DEPTH],
            anchor: None,
        },
        rng,
    )
    .unwrap();*/

    const SAMPLES: u32 = 50;

    let asset_type = *ASSET_TYPE_DEFAULT;

    /*let mut total_spend_time = Duration::new(0, 0);
    for i in 0..SAMPLES {
        println!("Running Spend sample {}", i);
        let value_commitment = ValueCommitment {
            asset_generator: asset_type.value_commitment_generator(jubjub_params),
            value: 1,
            randomness: fs::Fs::random(rng),
        };

        let nsk = fs::Fs::random(rng);
        let ak = edwards::Point::rand(rng, jubjub_params).mul_by_cofactor(jubjub_params);

        let proof_generation_key = ProofGenerationKey {
            ak: ak.clone(),
            nsk: nsk.clone(),
        };

        let viewing_key = proof_generation_key.to_viewing_key(jubjub_params);

        let payment_address;

        loop {
            let diversifier = {
                let mut d = [0; 11];
                rng.fill_bytes(&mut d);
                Diversifier(d)
            };

            if let Some(p) = viewing_key.to_payment_address(diversifier, jubjub_params) {
                payment_address = p;
                break;
            }
        }

        let commitment_randomness = fs::Fs::random(rng);
        let auth_path = vec![Some((Fr::random(rng), rng.next_u32() % 2 != 0)); TREE_DEPTH];
        let ar = fs::Fs::random(rng);
        let anchor = Fr::random(rng);

        let start = Instant::now();
        let _ = create_random_proof(
            Spend {
                params: jubjub_params,
                value_commitment: Some(value_commitment),
                proof_generation_key: Some(proof_generation_key),
                payment_address: Some(payment_address),
                commitment_randomness: Some(commitment_randomness),
                ar: Some(ar),
                auth_path: auth_path,
                anchor: Some(anchor),
            },
            &groth_spend_params,
            rng,
        )
        .unwrap();
        total_spend_time += start.elapsed();
    }
    let spend_avg = total_spend_time / SAMPLES;
    let spend_avg = spend_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (spend_avg.as_secs() as f64);

    println!("Average Spend proving time (in seconds): {}", spend_avg);
    */
    let mut total_output_time = Duration::new(0, 0);

    println!("Creating sample Output parameters...");
    let groth_output_params = generate_random_parameters::<Bls12, _, _>(
        Output {
            params: jubjub_params,
            value_commitment: None,
            payment_address: None,
            commitment_randomness: None,
            esk: None,
            asset_identifier: vec![None; 256],
        },
        rng,
    )
    .unwrap();

    for i in 0..50 {
        println!("Running Output sample {}", i);
        let value_commitment = ASSET_TYPE_DEFAULT.value_commitment(
            rng.next_u64(),
            fs::Fs::random(rng),
            jubjub_params);
    
        let nsk = fs::Fs::random(rng);
        let ak = edwards::Point::rand(rng, jubjub_params).mul_by_cofactor(jubjub_params);
    
        let proof_generation_key = ProofGenerationKey {
            ak: ak.clone(),
            nsk: nsk.clone(),
        };
    
        let viewing_key = proof_generation_key.to_viewing_key(jubjub_params);
    
        let payment_address;
    
        loop {
            let diversifier = {
                let mut d = [0; 11];
                rng.fill_bytes(&mut d);
                Diversifier(d)
            };
    
            if let Some(p) = viewing_key.to_payment_address(diversifier, jubjub_params) {
                payment_address = p;
                break;
            }
        }
    
        let commitment_randomness = fs::Fs::random(rng);
        let esk = fs::Fs::random(rng);
    
        let start = Instant::now();
        let _ = create_random_proof(
            Output {
                params: jubjub_params,
                value_commitment: Some(value_commitment.clone()),
                payment_address: Some(payment_address.clone()),
                commitment_randomness: Some(commitment_randomness),
                esk: Some(esk.clone()),
                asset_identifier: ASSET_TYPE_DEFAULT.identifier_bits(),
            },
            &groth_output_params,
            rng,
        )
        .unwrap();
        total_output_time += start.elapsed();
    }
    let output_avg = total_output_time / SAMPLES;
    let output_avg = output_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (output_avg.as_secs() as f64);

    println!("Average Output proving time (in seconds): {}", output_avg);
}
