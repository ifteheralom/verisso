//Ref: https://github.com/docknetwork/crypto/tree/main/bbs_plus

use std::collections::{BTreeMap, BTreeSet};
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
use bbs_plus::threshold::threshold_bbs::{BBSSignatureShare, Phase1Output};
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
};
use oblivious_transfer_protocols::*;
use oblivious_transfer_protocols::cointoss::Commitments;
use oblivious_transfer_protocols::ot_based_multiplication::base_ot_multi_party_pairwise::BaseOTOutput;
use oblivious_transfer_protocols::ot_based_multiplication::batch_mul_multi_party::Message1;
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use crate::exp_utils::{get_as_millis, setup_messages, Timer};
use crate::ot::*;
use crate::Signer::Signer;
use crate::constants::{*};

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

    let mut signers: Vec<Signer> = (1..=THRESHOLD_SIGNERS)
        .map(|id| Signer::new(id, sk_shares[id as usize - 1]))
        .collect();


    println!("\nSSO Authentication Phase");
    println!("ID token of {:?} total attributes, \n\
     total AS signers {:?} and threshold {:?}. \n",
             message_count,
             TOTAL_SIGNERS,
             THRESHOLD_SIGNERS
    );

    // Following have to happen for each new batch of signatures. Batch size can be 1 when creating one signature at a time
    let mut round1s = vec![];
    let mut commitments = vec![];
    let mut commitments_zero_share = vec![];
    let mut round1outs = vec![];

    // PHASE: 1 - Signers initiate round-1 and each signer sends commitments to others
    let fn1_timer = Timer::with_label("fn1_timer");
    fn1_timer.start();
    for i in 1..=THRESHOLD_SIGNERS {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        let (round1, comm, comm_zero)
            = signers[(i - 1) as usize].do_round1 (i);

        round1s.push(round1);
        commitments.push(comm);
        commitments_zero_share.push(comm_zero);
    }
    fn1_timer.stop_and_print_ms();

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
        let out = signers[(i) as usize].finish_round1(round1);
        expected_sk += out.masked_signing_key_shares.iter().sum::<Fr>();
        round1outs.push(out);
    }

    let mut round2s = vec![];
    let mut all_msg_1s = vec![];

    // PHASE: 2 - Signers initiate round-2 and each signer sends messages to others
    let fn2_timer = Timer::with_label("fn2_timer");
    fn2_timer.start();
    for i in 1..=THRESHOLD_SIGNERS {
        let mut others = threshold_party_set.clone();
        others.remove(&i);
        let (phase, U) = signers[(i - 1) as usize].do_round2 (
            i,
            round1outs[i as usize - 1].masked_signing_key_shares.clone(),
            round1outs[i as usize - 1].masked_rs.clone()
        );
        round2s.push(phase);
        all_msg_1s.push((i, U));
    }
    fn2_timer.stop_and_print_ms();

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

    let token_issue_time = Timer::with_label("token_issue_time");
    token_issue_time.start();
    let mut shares = vec![];
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
    token_issue_time.stop_and_print_ms();

    let token_verify_time = Timer::with_label("token_verify_time");
    token_verify_time.start();
    sig.verify(&messages, public_key.clone(), params.clone())
        .unwrap();
    token_verify_time.stop_and_print_ms();
}