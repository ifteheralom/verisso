use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::UniformRand;
use bbs_plus::prelude::{KeypairG2, SignatureParams23G1};
use rand::RngCore;

pub fn measure_time<T, F>(operation: F) -> (T, std::time::Duration)
    where
        F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = operation();
    let elapsed = start.elapsed();
    (result, elapsed)
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

pub fn reveal_messages(
    messages: Vec<Fr>,
    revealed_indices: BTreeSet<usize>,
) -> BTreeMap<usize, Fr> {
    // let mut revealed_indices = BTreeSet::new();
    // revealed_indices.insert(0);
    // revealed_indices.insert(2);
    let mut revealed_msgs = BTreeMap::new();
    for i in revealed_indices.iter() {
        revealed_msgs.insert(*i, messages[*i]);
    }
    return revealed_msgs;
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