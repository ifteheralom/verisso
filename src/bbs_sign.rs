use ark_serialize::Compress;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use bbs_plus::prelude::{Signature23G1};
use bbs_plus::setup::{KeypairG2, SignatureParams23G1};
use blake2::Blake2b512;
use rand::prelude::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::{rngs::StdRng, SeedableRng}, UniformRand};
use bbs_plus::proof_23::{PoKOfSignature23G1Proof, PoKOfSignature23G1Protocol};
use dock_crypto_utils::{signature::{MessageOrBlinding}};
use schnorr_pok::compute_random_oracle_challenge;

fn measure_time<T, F>(operation: F) -> (T, std::time::Duration)
    where
        F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = operation();
    let elapsed = start.elapsed();
    (result, elapsed)
}

pub fn setup_keys<R: rand::RngCore>(
    rng: &mut R,
    message_count: u32
) -> KeypairG2<Bls12_381> {
    let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(rng, message_count);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
    return keypair;
}

pub fn setup_messages<R: rand::RngCore>(
    rng: &mut R,
    message_count: u32
) -> Vec<Fr> {
    let messages: Vec<Fr> = (0..message_count).map(|_| {
        Fr::rand(rng)
    }).collect();
    return messages;
}

pub fn sig_setup<R: RngCore>(
    rng: &mut R,
    message_count: u32,
) -> (
    Vec<Fr>,
    SignatureParams23G1<Bls12_381>,
    KeypairG2<Bls12_381>,
) {
    let messages: Vec<Fr> = (0..message_count).map(|_| Fr::rand(rng)).collect();
    let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(rng, message_count);
    let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
    // let sig = Signature23G1::<Bls12_381>::new(rng, &messages, &keypair.secret_key, &params).unwrap();
    (messages, params, keypair)
}

pub fn bbs_sign() {
    // Create and verify proof of knowledge of a signature when some messages are revealed
    let mut rng = StdRng::seed_from_u64(0u64);
    let message_count = 20;
    let (messages, params, keypair) = sig_setup(&mut rng, message_count);

    let (sig, sign_create_duration) = measure_time(|| {
        let res = Signature23G1::<Bls12_381>::new(&mut rng, &messages, &keypair.secret_key, &params).unwrap();
        return res;
    });

    let (res, sign_verif_duration) = measure_time(|| {
        sig.verify(&messages, keypair.public_key.clone(), params.clone()).unwrap()
    });


    println!(
        "Time to sign multi-message of size {} is {:?}",
        message_count,
        sign_create_duration
    );
    println!(
        "Time to verify signature over multi-message of size {} is {:?}",
        message_count,
        sign_verif_duration
    );

    // let fr_byte_size = Fr::default().serialized_size(Compress::No);
    // println!("Size of each Fr element: {} bytes", fr_byte_size);

    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(0);
    revealed_indices.insert(2);
    let mut revealed_msgs = BTreeMap::new();
    for i in revealed_indices.iter() {
        revealed_msgs.insert(*i, messages[*i]);
    }

    let (proof, proof_create_duration) = measure_time(|| {
        let pok = PoKOfSignature23G1Protocol::init(
            &mut rng,
            None,
            None,
            &sig,
            &params,
            messages.iter().enumerate().map(|(idx, msg)| {
                if revealed_indices.contains(&idx) {
                    MessageOrBlinding::RevealMessage(msg)
                } else {
                    MessageOrBlinding::BlindMessageRandomly(msg)
                }
            }),
        ).unwrap();

        let mut chal_bytes_prover = vec![];
        pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover).unwrap();
        let challenge_prover = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
        let res = pok.gen_proof(&challenge_prover).unwrap();
        return res;
    });

    let public_key = &keypair.public_key;
    let mut chal_bytes_verifier = vec![];
    proof
        .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
        .unwrap();
    let challenge_verifier =
        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

    let (res, proof_verif_duration) = measure_time(|| {
        proof.verify(&revealed_msgs, &challenge_verifier, public_key.clone(), params.clone(),
        ).unwrap();
    });

    println!(
        "Time to create proof with message size {} and revealing {} messages is {:?}",
        message_count,
        revealed_indices.len(),
        proof_create_duration
    );
    println!(
        "Time to verify proof with message size {} and revealing {} messages is {:?}",
        message_count,
        revealed_indices.len(),
        proof_verif_duration
    );
}