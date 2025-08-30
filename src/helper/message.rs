use serde::{Deserialize, Serialize};

pub type ParticipantId = u16;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Start,
    SkShares {
        shares: String,
    },
    Round1Request,
    Round1Response {
        phase1: String,
        commitments: String,
        commitments_map: String,
    },
    Round1FinalRequest {
        phase1: String,
    },
    Round1FinalResponse {
        round1: String,
    },
    Round2Request {
        masked_signing_key_share: String,
        masked_rs: String,
    },
    Round2Response {
        phase2: String,
        map: String,
    },
   
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    pub sender: ParticipantId,
    // pub receiver: ParticipantId,
    pub msg: Message,
}
