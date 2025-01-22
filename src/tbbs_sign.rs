//Ref: https://github.com/docknetwork/crypto/tree/main/bbs_plus

use std::collections::{ BTreeSet};
use std::time::{Duration, Instant};
use blake2::Blake2b512;
use bbs_plus::setup::{PublicKeyG2, SignatureParams23G1, SecretKey};
use rand::prelude::*;
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{PrimeField};
use ark_std::{rand::{rngs::StdRng, SeedableRng}, Zero};
use bbs_plus::signature_23::Signature23G1;
use bbs_plus::threshold::multiplication_phase::Phase2;
use bbs_plus::threshold::randomness_generation_phase::Phase1;
use bbs_plus::threshold::threshold_bbs::BBSSignatureShare;
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
};
use oblivious_transfer_protocols::*;
use oblivious_transfer_protocols::ot_based_multiplication::base_ot_multi_party_pairwise::BaseOTOutput;
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use crate::exp_utils::{get_as_millis, setup_messages, Timer};
use crate::ot::*;

const BASE_OT_KEY_SIZE: u16 = 128;
const KAPPA: u16 = 256;
const STATISTICAL_SECURITY_PARAMETER: u16 = 80;
const SIG_BATCH_SIZE: u32 = 1;
const THRESHOLD_SIGNERS: u16 = 5;
const TOTAL_SIGNERS: u16 = 8;

pub fn trusted_party_keygen<R: RngCore>(
    rng: &mut R,
    threshold: ParticipantId,
    total: ParticipantId,
    params: SignatureParams23G1<Bls12_381>
) -> (PublicKeyG2<Bls12_381>, Fr, Vec<Fr>) {
    let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
    let secret_shares = shares.0.into_iter().map(|s| s.share).collect();
    let public_key = PublicKeyG2::generate_using_secret_key_and_bbs23_params(&SecretKey(secret), &params);
    (public_key, secret, secret_shares)
}

pub fn setup_public_key<F: PrimeField>(
    secret : Fr,
    params: SignatureParams23G1<Bls12_381>
) -> PublicKeyG2<Bls12_381> {
    return PublicKeyG2::generate_using_secret_key_and_bbs23_params(&SecretKey(secret), &params);
}

pub fn sign<R: rand::RngCore>(
    messages: Vec<Fr>,
    secret_key_shares: Vec<Fr>,
    params: SignatureParams23G1<Bls12_381>,
    rng: &mut R,
    threshold_party_set: BTreeSet<u16>,
    protocol_id: Vec<u8>,
    base_ot_outputs: Vec<BaseOTOutput>,
    ote_params: MultiplicationOTEParams<KAPPA, STATISTICAL_SECURITY_PARAMETER>,
    gadget_vector: GadgetVector<Fr, 256, 80>,
) -> Signature23G1<Bls12_381> {
    // Following have to happen for each new batch of signatures. Batch size can be 1 when creating one signature at a time
    let mut round1s = vec![];
    let mut commitments = vec![];
    let mut commitments_zero_share = vec![];
    let mut round1outs = vec![];

    // Signers initiate round-1 and each signer sends commitments to others
    for i in 1..=THRESHOLD_SIGNERS {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        let (round1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs(
            rng,
            SIG_BATCH_SIZE,
            i,
            others,
            protocol_id.clone(),
        )
            .unwrap();
        round1s.push(round1);
        commitments.push(comm);
        commitments_zero_share.push(comm_zero);
    }

    // Signers process round-1 commitments received from others
    for i in 1..=THRESHOLD_SIGNERS {
        for j in 1..=THRESHOLD_SIGNERS {
            if i != j {
                round1s[i as usize - 1]
                    .receive_commitment(
                        j,
                        commitments[j as usize - 1].clone(),
                        commitments_zero_share[j as usize - 1]
                            .get(&i)
                            .unwrap()
                            .clone(),
                    )
                    .unwrap();
            }
        }
    }

    // Signers create round-1 shares once they have the required commitments from others
    for i in 1..=THRESHOLD_SIGNERS {
        for j in 1..=THRESHOLD_SIGNERS {
            if i != j {
                let share = round1s[j as usize - 1].get_comm_shares_and_salts();
                let zero_share = round1s[j as usize - 1]
                    .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                round1s[i as usize - 1]
                    .receive_shares(j, share, zero_share)
                    .unwrap();
            }
        }
    }

    // Signers finish round-1 to generate the output
    let mut expected_sk = Fr::zero();
    for (i, round1) in round1s.into_iter().enumerate() {
        let out = round1.finish_for_bbs::<Blake2b512>(&secret_key_shares[i]).unwrap();
        expected_sk += out.masked_signing_key_shares.iter().sum::<Fr>();
        round1outs.push(out);
    }

    let mut round2s = vec![];
    let mut all_msg_1s = vec![];

    // Signers initiate round-2 and each signer sends messages to others
    for i in 1..=THRESHOLD_SIGNERS {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        let (phase, U) = Phase2::init(
            rng,
            i,
            round1outs[i as usize - 1].masked_signing_key_shares.clone(),
            round1outs[i as usize - 1].masked_rs.clone(),
            base_ot_outputs[i as usize - 1].clone(),
            others,
            ote_params,
            &gadget_vector,
        )
            .unwrap();
        round2s.push(phase);
        all_msg_1s.push((i, U));
    }

    // Signers process round-2 messages received from others
    let mut all_msg_2s = vec![];
    for (sender_id, msg_1s) in all_msg_1s {
        for (receiver_id, m) in msg_1s {
            let m2 = round2s[receiver_id as usize - 1]
                .receive_message1::<Blake2b512>(sender_id, m, &gadget_vector)
                .unwrap();
            all_msg_2s.push((receiver_id, sender_id, m2));
        }
    }

    for (sender_id, receiver_id, m2) in all_msg_2s {
        round2s[receiver_id as usize - 1]
            .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
            .unwrap();
    }

    let round2_outputs = round2s.into_iter().map(|p| p.finish()).collect::<Vec<_>>();
    let mut shares = vec![];
    let mut signature = BBSSignatureShare::aggregate(shares.clone()).unwrap();

    for k in 0..SIG_BATCH_SIZE as usize {
        for i in 0..THRESHOLD_SIGNERS as usize {
            let share = BBSSignatureShare::new(
                &messages,
                k,
                &round1outs[i],
                &round2_outputs[i],
                &params,
            ).unwrap();
            shares.push(share);
        }
        signature = BBSSignatureShare::aggregate(shares.clone()).unwrap();
    }
    return signature;
}

pub fn verify(
    signature: Signature23G1<Bls12_381>,
    messages: Vec<Fr>,
    public_key: PublicKeyG2<Bls12_381>,
    params: SignatureParams23G1<Bls12_381>
) {
    return signature.verify(
        &messages,
        public_key.clone(),
        params.clone()
    ).unwrap();
}

pub fn test_token() {
    let mut rng = StdRng::seed_from_u64(0u64);
    let message_count = 3;
    let params: SignatureParams23G1<Bls12_381> = SignatureParams23G1::<Bls12_381>::generate_using_rng(&mut rng, message_count);

    let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
    let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
        Blake2b512,
    >(ote_params, b"test-gadget-vector");
    let protocol_id = b"test".to_vec();

    let all_party_set = (1..=TOTAL_SIGNERS).into_iter().collect::<BTreeSet<_>>();
    let threshold_party_set = (1..=THRESHOLD_SIGNERS).into_iter().collect::<BTreeSet<_>>();

    let messages = setup_messages(&mut rng, message_count);
    let (public_key, sk, sk_shares) = trusted_party_keygen(&mut rng, THRESHOLD_SIGNERS, TOTAL_SIGNERS, params.clone());
    let base_ot_outputs = do_pairwise_base_ot::<BASE_OT_KEY_SIZE>(
        &mut rng,
        ote_params.num_base_ot(),
        TOTAL_SIGNERS,
        all_party_set.clone(),
    );

    // println!(
    //     "For a batch size of {} BBS signatures and {} signers",
    //     SIG_BATCH_SIZE, THRESHOLD_SIGNERS
    // );

    // For experimental purposes
    let mTimer = Timer::new();
    let mut elapsed: Option<Duration>;
    let mut token_issue_time: f64;
    let mut token_verify_time: f64;
    //

    // Following have to happen for each new batch of signatures. Batch size can be 1 when creating one signature at a time
    let mut round1s = vec![];
    let mut commitments = vec![];
    let mut commitments_zero_share = vec![];
    let mut round1outs = vec![];

    // PHASE: 1 - Signers initiate round-1 and each signer sends commitments to others
    for i in 1..=THRESHOLD_SIGNERS {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        let (round1, comm, comm_zero) = Phase1::<Fr, 256>::init_for_bbs(
            &mut rng,
            SIG_BATCH_SIZE,
            i,
            others,
            protocol_id.clone(),
        )
            .unwrap();
        round1s.push(round1);
        commitments.push(comm);
        commitments_zero_share.push(comm_zero);
    }

    // Signers process round-1 commitments received from others
    for i in 1..=THRESHOLD_SIGNERS {
        for j in 1..=THRESHOLD_SIGNERS {
            if i != j {
                round1s[i as usize - 1]
                    .receive_commitment(
                        j,
                        commitments[j as usize - 1].clone(),
                        commitments_zero_share[j as usize - 1]
                            .get(&i)
                            .unwrap()
                            .clone(),
                    )
                    .unwrap();
            }
        }
    }

    // Signers create round-1 shares once they have the required commitments from others
    for i in 1..=THRESHOLD_SIGNERS {
        for j in 1..=THRESHOLD_SIGNERS {
            if i != j {
                let share = round1s[j as usize - 1].get_comm_shares_and_salts();
                let zero_share = round1s[j as usize - 1]
                    .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                round1s[i as usize - 1]
                    .receive_shares(j, share, zero_share)
                    .unwrap();
            }
        }
    }

    // Signers finish round-1 to generate the output
    let mut expected_sk = Fr::zero();
    for (i, round1) in round1s.into_iter().enumerate() {
        let out = round1.finish_for_bbs::<Blake2b512>(&sk_shares[i]).unwrap();
        expected_sk += out.masked_signing_key_shares.iter().sum::<Fr>();
        round1outs.push(out);
    }

    let mut round2s = vec![];
    let mut all_msg_1s = vec![];

    // PHASE: 2 - Signers initiate round-2 and each signer sends messages to others
    for i in 1..=THRESHOLD_SIGNERS {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        let (phase, U) = Phase2::init(
            &mut rng,
            i,
            round1outs[i as usize - 1].masked_signing_key_shares.clone(),
            round1outs[i as usize - 1].masked_rs.clone(),
            base_ot_outputs[i as usize - 1].clone(),
            others,
            ote_params,
            &gadget_vector,
        )
            .unwrap();
        round2s.push(phase);
        all_msg_1s.push((i, U));
    }

    // Signers process round-2 messages received from others
    let mut all_msg_2s = vec![];
    for (sender_id, msg_1s) in all_msg_1s {
        for (receiver_id, m) in msg_1s {
            let m2 = round2s[receiver_id as usize - 1]
                .receive_message1::<Blake2b512>(sender_id, m, &gadget_vector)
                .unwrap();
            all_msg_2s.push((receiver_id, sender_id, m2));
        }
    }

    for (sender_id, receiver_id, m2) in all_msg_2s {
        round2s[receiver_id as usize - 1]
            .receive_message2::<Blake2b512>(sender_id, m2, &gadget_vector)
            .unwrap();
    }
    let round2_outputs = round2s.into_iter().map(|p| p.finish()).collect::<Vec<_>>();

    mTimer.start();
    let mut shares = vec![];
    let start = Instant::now();
    for i in 0..THRESHOLD_SIGNERS as usize {
        let share = BBSSignatureShare::new(
            &messages,
            0,
            &round1outs[i],
            &round2_outputs[i],
            &params,
        )
            .unwrap();
        shares.push(share);
    }

    // Client aggregate the shares to get the final signature
    let sig = BBSSignatureShare::aggregate(shares).unwrap();
    elapsed = mTimer.stop();
    token_issue_time = get_as_millis(elapsed.unwrap());

    mTimer.start();
    sig.verify(&messages, public_key.clone(), params.clone())
        .unwrap();
    elapsed = mTimer.stop();
    token_verify_time = get_as_millis(elapsed.unwrap());

    println!();
    println!("ID token of {:?} total attributes, \n\
     total AS signers {:?} and threshold {:?}. \n\
      Token Issuance phase: {:.2}ms\n\
       Token Verification phase: {:.2}ms",
             message_count,
             TOTAL_SIGNERS,
             THRESHOLD_SIGNERS,
             token_issue_time,
             token_verify_time
    );
}