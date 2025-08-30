use crate::config::Config;
use crate::exp_utils::setup_messages;
use crate::exp_utils::*;
use crate::helper::encoder::Encoder;

use crate::constant::*;
use crate::helper::message::{Message, Payload};
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::Zero;
use bbs_plus::threshold::multiplication_phase::Phase2;
use bbs_plus::threshold::randomness_generation_phase::Phase1;
use bbs_plus::threshold::threshold_bbs::BBSSignatureShare;
use bbs_plus::{
    setup::{PublicKeyG2, SecretKey, SignatureParams23G1},
    threshold::threshold_bbs::Phase1Output,
};
use blake2::Blake2b512;
use oblivious_transfer_protocols::cointoss::Commitments;
use oblivious_transfer_protocols::ot_based_multiplication::batch_mul_multi_party::Message1;
use oblivious_transfer_protocols::ot_based_multiplication::{
    dkls18_mul_2p::MultiplicationOTEParams, dkls19_batch_mul_2p::GadgetVector,
};
use oblivious_transfer_protocols::*;
use rand::prelude::*;
use secret_sharing_and_dkg::shamir_ss::deal_random_secret;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

fn trusted_party_keygen<R: RngCore>(
    rng: &mut R,
    threshold: ParticipantId,
    total: ParticipantId,
    params: SignatureParams23G1<Bls12_381>,
) -> (PublicKeyG2<Bls12_381>, Fr, Vec<Fr>) {
    let (secret, shares, _) = deal_random_secret(rng, threshold, total).unwrap();
    let secret_shares = shares.0.into_iter().map(|s| s.share).collect();
    let public_key =
        PublicKeyG2::generate_using_secret_key_and_bbs23_params(&SecretKey(secret), &params);
    (public_key, secret, secret_shares)
}

async fn send_message(
    stream: &mut tokio::net::TcpStream,
    payload: &Payload,
) -> tokio::io::Result<()> {
    let mut serialized = serde_json::to_vec(payload)?;
    serialized.push(b'\n');
    stream.write_all(&serialized).await?;
    Ok(())
}

pub struct AuthenticationService {
    config: Config,
    peers: Arc<Mutex<HashMap<u16, Arc<Mutex<tokio::net::TcpStream>>>>>,
    params: SignatureParams23G1<Bls12_381>,
    sk_shares: Vec<Fr>,
    messages: Vec<Fr>,
    public_key: PublicKeyG2<Bls12_381>,

    round1s: HashMap<ParticipantId, Phase1<Fr, 256>>,
    commitments: HashMap<ParticipantId, Commitments>,
    commitments_zero_share: HashMap<ParticipantId, BTreeMap<ParticipantId, Commitments>>,
    round1outs: HashMap<ParticipantId, Phase1Output<Fr>>,
    threshold_signers: u16,
    expected_sk: Fr,
    round2s: HashMap<ParticipantId, Phase2<Fr, 256, 80>>,
    all_msg_1s: HashMap<ParticipantId, BTreeMap<ParticipantId, Message1<Fr>>>,
    fn1_timer: Timer,
    fn2_timer: Timer,
    token_issue_timer: Timer,
    token_verify_timer: Timer,
}

impl AuthenticationService {
    pub fn init(
        config: Config,
        threshold_signers: u16,
        peers: Arc<Mutex<HashMap<u16, Arc<Mutex<tokio::net::TcpStream>>>>>,
    ) -> Self {
        let total_signers = config.total_nodes;

        let mut rng = StdRng::seed_from_u64(0u64);

        let params = SignatureParams23G1::<Bls12_381>::generate_using_rng(&mut rng, MESSAGE_COUNT);

        let messages = setup_messages(&mut rng, MESSAGE_COUNT);

        // Add sk_shares logic
        let (public_key, _sk, sk_shares) =
            trusted_party_keygen(&mut rng, threshold_signers, total_signers, params.clone());

        let round1s = HashMap::new();
        let commitments = HashMap::new();
        let commitments_zero_share = HashMap::new();
        let round1outs = HashMap::new();

        let expected_sk = Fr::zero();

        let round2s = HashMap::new();
        let all_msg_1s = HashMap::new();

        let fn1_timer = Timer::with_label("fn1");
        let fn2_timer = Timer::with_label("fn2");
        let token_issue_timer = Timer::with_label("token_issue");
        let token_verify_timer = Timer::with_label("token_verify");

        Self {
            config,
            peers,
            params,
            sk_shares,
            messages,
            public_key,
            round1s,
            commitments,
            commitments_zero_share,
            round1outs,
            threshold_signers,
            expected_sk,
            round2s,
            all_msg_1s,
            fn1_timer,
            fn2_timer,
            token_issue_timer,
            token_verify_timer,
        }
    }

    pub async fn share_sk_shares(&mut self) {
        let guard = self.peers.lock().await;
        for (node_id, peer) in guard.iter() {
            let node_id = *node_id;

            if !(1..=self.threshold_signers).contains(&node_id) {
                continue;
            }

            let peer = peer.clone();

            let sk_share = self.sk_shares.get((node_id - 1) as usize).unwrap();
            let payload = Payload {
                sender: self.config.node_id,
                msg: Message::SkShares {
                    shares: Encoder::encode_sk_share(sk_share),
                },
            };

            tokio::spawn(async move {
                let mut stream = peer.lock().await;
                if let Err(e) = send_message(&mut *stream, &payload).await {
                    eprintln!(
                        "Failed to send message to {}: {}",
                        stream.local_addr().unwrap(),
                        e
                    );
                }
            });
        }
    }

    pub async fn send_round1_request(&mut self) {
        self.fn1_timer.start();
        let guard = self.peers.lock().await;
        for (_node_id, peer) in guard.iter() {
            if !(1..=self.threshold_signers).contains(&_node_id) {
                continue;
            }

            let peer = peer.clone();
            let payload = Payload {
                sender: self.config.node_id,
                msg: Message::Round1Request,
            };
            tokio::spawn(async move {
                let mut stream = peer.lock().await;
                if let Err(e) = send_message(&mut *stream, &payload).await {
                    eprintln!(
                        "Failed to send message to {}: {}",
                        stream.local_addr().unwrap(),
                        e
                    );
                }
            });
        }
    }

    async fn complete_round1(&mut self) {
        for i in 1..=self.threshold_signers {
            let round1s = self.round1s.get_mut(&i).unwrap();
            for j in 1..=self.threshold_signers {
                if i != j {
                    round1s
                        .receive_commitment(
                            j,
                            self.commitments.get(&j).unwrap().clone(),
                            self.commitments_zero_share
                                .get(&j)
                                .unwrap()
                                .get(&i)
                                .unwrap()
                                .clone(),
                        )
                        .unwrap();
                }
            }
        }

        for i in 1..=self.threshold_signers {
            for j in 1..=self.threshold_signers {
                if i != j {
                    let share = self.round1s.get(&j).unwrap().get_comm_shares_and_salts();
                    let zero_share = self
                        .round1s
                        .get(&j)
                        .unwrap()
                        .get_comm_shares_and_salts_for_zero_sharing_protocol_with_other(&i);
                    self.round1s
                        .get_mut(&i)
                        .unwrap()
                        .receive_shares(j, share, zero_share)
                        .unwrap();
                }
            }
        }

        for (i, round1) in self.round1s.drain().collect::<Vec<_>>() {
            // Acquire the peer Arc<Mutex<TcpStream>> by locking the peers map briefly and cloning the entry,
            // then lock the stream's mutex inside the spawned task to avoid holding both locks across await.
            let peer = {
                let guard = self.peers.lock().await;
                guard.get(&i).unwrap().clone()
            };

            // if i == 1 {
            //     println!("round1: {:?}", round1);
            // }

            let payload = Payload {
                sender: self.config.node_id,
                msg: Message::Round1FinalRequest {
                    phase1: Encoder::encode_phase1(&round1),
                },
            };

            tokio::spawn(async move {
                let mut stream = peer.lock().await;
                if let Err(e) = send_message(&mut *stream, &payload).await {
                    eprintln!(
                        "Failed to send message to {}: {}",
                        stream.local_addr().unwrap(),
                        e
                    );
                }
            });
        }
    }

    pub async fn process_round1_response(
        &mut self,
        sender: ParticipantId,
        phase1: Phase1<Fr, 256>,
        comm: Commitments,
        comm_zero: BTreeMap<ParticipantId, Commitments>,
    ) {
        /*!
         * Process the round 1 response from other signers.
         * Store the round 1 data and commitments for later use.
         */
        self.round1s.insert(sender, phase1);
        self.commitments.insert(sender, comm);
        self.commitments_zero_share.insert(sender, comm_zero);

        self.fn1_timer.stop_and_print_ms();

        if self.round1s.len() as u16 == self.threshold_signers {
            self.complete_round1().await;
        }
    }

    pub async fn initiate_round2(&mut self) {
        // for i in 2..=self.threshold_signers + 1 {}
        for i in 1..=self.threshold_signers {
            // Acquire the peer Arc<Mutex<TcpStream>> by locking the peers map briefly and cloning the entry,
            // then lock the stream's mutex inside the spawned task to avoid holding both locks across await.
            let peer = {
                let guard = self.peers.lock().await;
                guard.get(&i).unwrap().clone()
            };

            let masked_rs = self.round1outs.get(&i).unwrap().masked_rs.clone();
            let masked_signing_key_share = self
                .round1outs
                .get(&i)
                .unwrap()
                .masked_signing_key_shares
                .clone();

            self.fn2_timer.start();

            let payload = Payload {
                sender: self.config.node_id,
                msg: Message::Round2Request {
                    masked_rs: Encoder::encode_vec_fr(&masked_rs),
                    masked_signing_key_share: Encoder::encode_vec_fr(&masked_signing_key_share),
                },
            };

            tokio::spawn(async move {
                let mut stream = peer.lock().await;
                if let Err(e) = send_message(&mut *stream, &payload).await {
                    eprintln!(
                        "Failed to send message to {}: {}",
                        stream.local_addr().unwrap(),
                        e
                    );
                }
            });
        }
    }

    pub async fn process_round1_final_response(
        &mut self,
        sender: ParticipantId,
        round1: Phase1Output<Fr>,
    ) {
        self.expected_sk += round1.masked_signing_key_shares.iter().sum::<Fr>();

        self.round1outs.insert(sender, round1);

        if self.round1outs.len() as u16 == self.threshold_signers {
            self.initiate_round2().await;
        }
    }

    async fn complete_round2(&mut self) {
        let ote_params = MultiplicationOTEParams::<KAPPA, STATISTICAL_SECURITY_PARAMETER> {};
        let gadget_vector = GadgetVector::<Fr, KAPPA, STATISTICAL_SECURITY_PARAMETER>::new::<
            Blake2b512,
        >(ote_params, b"test-gadget-vector");

        let mut all_msg_2s = vec![];

        for sender_id in 1..=self.threshold_signers {
            // consume to avoid reprocessing
            let msg_1s = self.all_msg_1s.get(&sender_id).unwrap();
            for (receiver_id, m) in msg_1s {
                let m2 = self
                    .round2s
                    .get_mut(&receiver_id)
                    .unwrap()
                    .receive_message1::<Blake2b512>(sender_id, m.clone(), &gadget_vector)
                    .unwrap();

                // Store as (target_id = sender_id, from_id = receiver_id, m2)
                all_msg_2s.push((receiver_id, sender_id, m2));
            }
        }

        for (sender_id, receiver_id, m2) in all_msg_2s {
            self.round2s
                .get_mut(&receiver_id)
                .unwrap()
                .receive_message2::<Blake2b512>(*sender_id, m2, &gadget_vector)
                .unwrap();
        }

        let round2_outputs: BTreeMap<ParticipantId, _> = self
            .round2s
            .drain()
            .map(|(id, p)| (id, p.finish()))
            .collect();

        self.token_issue_timer.start();
        let mut shares = vec![];
        for i in 1..=self.threshold_signers {
            let share = BBSSignatureShare::new(
                &self.messages,
                0,
                self.round1outs.get(&i).unwrap(),
                round2_outputs.get(&i).unwrap(),
                &self.params,
            )
            .unwrap();
            shares.push(share);
        }

        let sig = BBSSignatureShare::aggregate(shares).unwrap();
        self.token_issue_timer.stop_and_print_ms();

        self.token_verify_timer.start();
        if let Err(err) = sig.verify(&self.messages, self.public_key.clone(), self.params.clone()) {
            eprintln!("Signature verification failed: {:?}", err);
        } else {
            println!("Signature verified successfully");
        }
        self.token_verify_timer.stop_and_print_ms();

        let now = SystemTime::now();
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut file = tokio::fs::File::create(format!("./op/timings_{}.json", timestamp))
            .await
            .unwrap();

        let timings = json!({
            "fn1": self.fn1_timer.get_duration(),
            "fn2": self.fn2_timer.get_duration(),
            "token_issue": self.token_issue_timer.get_duration(),
            "token_verify": self.token_verify_timer.get_duration(),
        });
        file.write_all(timings.to_string().as_bytes())
            .await
            .unwrap();
    }

    pub async fn process_round2_response(
        &mut self,
        sender: ParticipantId,
        phase2: Phase2<Fr, 256, 80>,
        map: BTreeMap<ParticipantId, Message1<Fr>>,
    ) {
        self.round2s.insert(sender, phase2);
        self.all_msg_1s.insert(sender, map);

        self.fn2_timer.stop_and_print_ms();

        if self.round2s.len() as u16 == self.threshold_signers {
            self.complete_round2().await;
        }
    }
}
