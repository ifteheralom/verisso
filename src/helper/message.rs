use serde::{Deserialize, Serialize};

pub type ParticipantId = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MessageType {
    Phase1Commitment,
    Phase1Response,
    Phase2Commitment,
    Phase2Response,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    pub sender: ParticipantId,
    pub receiver: ParticipantId,
    pub msg_type: MessageType,
    pub data: Vec<u8>,
}
