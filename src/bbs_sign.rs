// Ref: https://github.com/docknetwork/crypto/tree/main/bbs_plus

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use bbs_plus::prelude::{PublicKeyG2, Signature23G1};
use bbs_plus::setup::{KeypairG2, SecretKey, SignatureParams23G1};
use blake2::Blake2b512;
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::{rand::{rngs::StdRng, SeedableRng}};
use bbs_plus::proof_23::{PoKOfSignature23G1Protocol};
use dock_crypto_utils::{signature::{MessageOrBlinding}};
use schnorr_pok::compute_random_oracle_challenge;
use crate::exp_utils::*;

pub fn setup_keys<R: rand::RngCore>(
    rng: &mut R,
    params: &SignatureParams23G1<Bls12_381>
) -> KeypairG2<Bls12_381> {
    return KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(
        rng,
        &params
    );
}

pub fn sign<R: rand::RngCore>(
    messages: Vec<Fr>,
    secret_key: SecretKey<Fr>,
    params: SignatureParams23G1<Bls12_381>,
    rng: &mut R
) -> Signature23G1<Bls12_381> {
    return Signature23G1::<Bls12_381>::new(
        rng,
        &messages,
        &secret_key,
        &params
    ).unwrap();
}

pub fn verify_sign(
    messages: Vec<Fr>,
    signature: Signature23G1<Bls12_381>,
    public_key: PublicKeyG2<Bls12_381>,
    params: SignatureParams23G1<Bls12_381>
) {
    return signature.verify(
        &messages,
        public_key.clone(),
        params.clone()
    ).unwrap();
}

pub fn make_proof<R: rand::RngCore>(
    messages: Vec<Fr>,
    revealed_msgs: BTreeMap<usize, Fr>,
    revealed_indices: BTreeSet<usize>,
    signature: Signature23G1<Bls12_381>,
    params: SignatureParams23G1<Bls12_381>,
    rng: &mut R
) -> bbs_plus::proof_23::PoKOfSignature23G1Proof<Bls12_381> {
    let pok = PoKOfSignature23G1Protocol::init(
        rng,
        None,
        None,
        &signature,
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
    let res: bbs_plus::proof_23::PoKOfSignature23G1Proof<Bls12_381> = pok.gen_proof(&challenge_prover).unwrap();
    return res;
}

pub fn verify_proof(
    proof: bbs_plus::proof_23::PoKOfSignature23G1Proof<Bls12_381>,
    revealed_msgs: BTreeMap<usize, Fr>,
    challenge_verifier: Fr,
    public_key: PublicKeyG2<Bls12_381>,
    params: SignatureParams23G1<Bls12_381>
) {
    return proof.verify(
        &revealed_msgs,
        &challenge_verifier,
        public_key.clone(),
        params.clone(),
    ).unwrap();
}

pub fn test_credential() {
    let message_count = 15;
    let mut rng = StdRng::seed_from_u64(0u64);
    let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(&mut rng, message_count);

    let keypair = setup_keys(&mut rng, &params);
    let messages = setup_messages(&mut rng, message_count);
    // let (messages, params, keypair) = sig_setup(&mut rng, message_count);

    // For experimental purposes
    let mTimer = Timer::new();
    let mut elapsed: Option<Duration>;
    let mut vc_issue_time: f64;
    let mut vc_verify_time: f64;
    let mut proof_gen_time: f64;
    let mut proof_verify_time: f64;
    //

    mTimer.start();
    let sig = Signature23G1::<Bls12_381>::new(&mut rng, &messages, &keypair.secret_key, &params).unwrap();
    elapsed = mTimer.stop();
    vc_issue_time = get_as_millis(elapsed.unwrap());


    mTimer.start();
    sig.verify(&messages, keypair.public_key.clone(), params.clone()).unwrap();
    elapsed = mTimer.stop();
    vc_verify_time = get_as_millis(elapsed.unwrap());

    // let fr_byte_size = Fr::default().serialized_size(Compress::No);
    // println!("Size of each Fr element: {} bytes", fr_byte_size);

    let mut revealed_indices = BTreeSet::new();
    revealed_indices.insert(0);
    revealed_indices.insert(2);
    revealed_indices.insert(4);
    let mut revealed_msgs = BTreeMap::new();
    for i in revealed_indices.iter() {
        revealed_msgs.insert(*i, messages[*i]);
    }

    mTimer.start();
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
    let proof = pok.gen_proof(&challenge_prover).unwrap();
    elapsed = mTimer.stop();
    proof_gen_time = get_as_millis(elapsed.unwrap());

    let public_key: &PublicKeyG2<Bls12_381> = &keypair.public_key;
    let mut chal_bytes_verifier = vec![];
    proof.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier).unwrap();
    let challenge_verifier = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

    mTimer.start();
    proof.verify(&revealed_msgs, &challenge_verifier, public_key.clone(), params.clone()).unwrap();
    elapsed = mTimer.stop();
    proof_verify_time = get_as_millis(elapsed.unwrap());

    println!();
    println!(
        "Verifiable Credential (VC)  of {:?} total attributes, \n\
         and indexes {:?} revealed.\n\
        VC Issuance phase: {:.2}ms \n\
        VC Verification phase: {:.2}ms \n\
        VP Creation phase: {:.2}ms \n\
        VP Verification phase: {:.2}ms",
        message_count,
        revealed_indices,
        vc_issue_time,
        vc_verify_time,
        proof_gen_time,
        proof_verify_time
    );
}