// Ref: https://github.com/docknetwork/crypto/tree/main/bbs_plus

mod exp_utils;

use crate::exp_utils::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use bbs_plus::prelude::{PublicKeyG2, Signature23G1};
use bbs_plus::proof_23::PoKOfSignature23G1Protocol;
use bbs_plus::setup::{KeypairG2, SecretKey, SignatureParams23G1};
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use schnorr_pok::compute_random_oracle_challenge;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

pub fn setup_keys<R: rand::RngCore>(
    rng: &mut R,
    params: &SignatureParams23G1<Bls12_381>,
) -> KeypairG2<Bls12_381> {
    return KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
}

pub fn sign<R: rand::RngCore>(
    messages: Vec<Fr>,
    secret_key: SecretKey<Fr>,
    params: SignatureParams23G1<Bls12_381>,
    rng: &mut R,
) -> Signature23G1<Bls12_381> {
    return Signature23G1::<Bls12_381>::new(rng, &messages, &secret_key, &params).unwrap();
}

pub fn verify_sign(
    messages: Vec<Fr>,
    signature: Signature23G1<Bls12_381>,
    public_key: PublicKeyG2<Bls12_381>,
    params: SignatureParams23G1<Bls12_381>,
) {
    return signature
        .verify(&messages, public_key.clone(), params.clone())
        .unwrap();
}

pub fn make_proof<R: rand::RngCore>(
    messages: Vec<Fr>,
    revealed_msgs: BTreeMap<usize, Fr>,
    revealed_indices: BTreeSet<usize>,
    signature: Signature23G1<Bls12_381>,
    params: SignatureParams23G1<Bls12_381>,
    rng: &mut R,
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
    )
    .unwrap();

    let mut chal_bytes_prover = vec![];
    pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
        .unwrap();
    let challenge_prover = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
    let res: bbs_plus::proof_23::PoKOfSignature23G1Proof<Bls12_381> =
        pok.gen_proof(&challenge_prover).unwrap();
    return res;
}

pub fn verify_proof(
    proof: bbs_plus::proof_23::PoKOfSignature23G1Proof<Bls12_381>,
    revealed_msgs: BTreeMap<usize, Fr>,
    challenge_verifier: Fr,
    public_key: PublicKeyG2<Bls12_381>,
    params: SignatureParams23G1<Bls12_381>,
) {
    return proof
        .verify(
            &revealed_msgs,
            &challenge_verifier,
            public_key.clone(),
            params.clone(),
        )
        .unwrap();
}

pub fn test_credential(message_count: u32, revealed_indices_count: u32) -> (f64, f64) {
    // let message_count = 15;
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
    let sig =
        Signature23G1::<Bls12_381>::new(&mut rng, &messages, &keypair.secret_key, &params).unwrap();
    elapsed = mTimer.stop();
    vc_issue_time = get_as_millis(elapsed.unwrap());

    mTimer.start();
    sig.verify(&messages, keypair.public_key.clone(), params.clone())
        .unwrap();
    elapsed = mTimer.stop();
    vc_verify_time = get_as_millis(elapsed.unwrap());

    // let fr_byte_size = Fr::default().serialized_size(Compress::No);
    // println!("Size of each Fr element: {} bytes", fr_byte_size);

    // MSG COUNT = 20, 40, 60,
    // REVEAL = 20, 40, 60, 80, 100
    // 20: 4, 8, 12, 16, 20
    // 40: 8, 16, 24, 32, 40
    // 60: 12, 24, 36, 48, 60

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
    )
    .unwrap();

    let mut chal_bytes_prover = vec![];
    pok.challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_prover)
        .unwrap();
    let challenge_prover = compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_prover);
    let proof = pok.gen_proof(&challenge_prover).unwrap();
    elapsed = mTimer.stop();
    proof_gen_time = get_as_millis(elapsed.unwrap());

    let public_key: &PublicKeyG2<Bls12_381> = &keypair.public_key;
    let mut chal_bytes_verifier = vec![];
    proof
        .challenge_contribution(&revealed_msgs, &params, &mut chal_bytes_verifier)
        .unwrap();
    let challenge_verifier =
        compute_random_oracle_challenge::<Fr, Blake2b512>(&chal_bytes_verifier);

    mTimer.start();
    proof
        .verify(
            &revealed_msgs,
            &challenge_verifier,
            public_key.clone(),
            params.clone(),
        )
        .unwrap();
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

    (proof_gen_time, proof_verify_time)
}

pub fn run_exp() {
    // let message_counts = vec![20, 40, 60];
    // let revealed_indices_percentages = vec![20, 40, 60, 80, 100];
    // for &msg_count in message_counts.iter() {
    //     // 20%, 40%, 60%, 80%, 100%
    //     let revealed_indices_count = revealed_indices_percentages
    //         .iter()
    //         .map(|&p| (msg_count * p) / 100)
    //         .collect::<Vec<_>>();
    //     for (i, &rev_count) in revealed_indices_count.iter().enumerate() {
    //         let mut total_proof_gen_time = 0.0;
    //         let mut total_proof_verify_time = 0.0;
    //         let total_runs = 5;
    //         for i in 0..total_runs {
    //             let (proof_gen_time, proof_verify_time) = test_credential(msg_count, rev_count);
    //             total_proof_gen_time += proof_gen_time;
    //             total_proof_verify_time += proof_verify_time;
    //         }
    //         let avg_proof_gen_time = total_proof_gen_time / 5.0;
    //         let avg_proof_verify_time = total_proof_verify_time / 5.0;

    //         // Write to a file
    //         let file_name = format!(
    //             "./op/bbs_msg_{}_revealpercentage_{}.json",
    //             msg_count, revealed_indices_percentages[i]
    //         );
    //         let json_data = json!({
    //             "total_runs": total_runs,
    //             "msg_count": msg_count,
    //             "revealed_percentage": revealed_indices_percentages[i],
    //             "revealed_count": rev_count,
    //             "proof_gen_time": avg_proof_gen_time,
    //             "proof_verify_time": avg_proof_verify_time,
    //         });
    //         let mut file = File::create(file_name).unwrap();
    //         serde_json::to_writer_pretty(&mut file, &json_data).unwrap();
    //     }
    // }

    // let msg_count = 60;
    // let revealed_indices = [10, 20, 30, 40, 50];
    // for (i, &rev_count) in revealed_indices.iter().enumerate() {
    //     let mut total_proof_gen_time = 0.0;
    //     let mut total_proof_verify_time = 0.0;
    //     let total_runs = 5;
    //     for i in 0..total_runs {
    //         let (proof_gen_time, proof_verify_time) = test_credential(msg_count, rev_count);
    //         total_proof_gen_time += proof_gen_time;
    //         total_proof_verify_time += proof_verify_time;
    //     }
    //     let avg_proof_gen_time = total_proof_gen_time / 5.0;
    //     let avg_proof_verify_time = total_proof_verify_time / 5.0;

    //     // Write to a file
    //     let file_name = format!(
    //         "./op/bbs_runtime_msg_{}_revealcount_{}.json",
    //         msg_count, rev_count
    //     );
    //     let json_data = json!({
    //         "total_runs": total_runs,
    //         "msg_count": msg_count,
    //         // "revealed_percentage": revealed_indices_percentages[i],
    //         "revealed_count": rev_count,
    //         "proof_gen_time": avg_proof_gen_time,
    //         "proof_verify_time": avg_proof_verify_time,
    //     });
    //     let mut file = File::create(file_name).unwrap();
    //     serde_json::to_writer_pretty(&mut file, &json_data).unwrap();
    // }

    let msg_count = 15;
    let revealed_indices = [5];
    for (i, &rev_count) in revealed_indices.iter().enumerate() {
        let mut total_proof_gen_time = 0.0;
        let mut total_proof_verify_time = 0.0;
        let total_runs = 5;
        for i in 0..total_runs {
            let (proof_gen_time, proof_verify_time) = test_credential(msg_count, rev_count);
            total_proof_gen_time += proof_gen_time;
            total_proof_verify_time += proof_verify_time;
        }
        let avg_proof_gen_time = total_proof_gen_time / 5.0;
        let avg_proof_verify_time = total_proof_verify_time / 5.0;

        // Write to a file
        let file_name = format!(
            "./op/bbs_runtime_msg_{}_revealcount_{}.json",
            msg_count, rev_count
        );
        let json_data = json!({
            "total_runs": total_runs,
            "msg_count": msg_count,
            // "revealed_percentage": revealed_indices_percentages[i],
            "revealed_count": rev_count,
            "proof_gen_time": avg_proof_gen_time,
            "proof_verify_time": avg_proof_verify_time,
        });
        let mut file = File::create(file_name).unwrap();
        serde_json::to_writer_pretty(&mut file, &json_data).unwrap();
    }
}

pub fn main() {
    run_exp();
}
