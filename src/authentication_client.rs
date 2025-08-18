use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

mod helper {
    pub mod message;
}
use helper::message::{MessageType, Payload};

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8001".to_string());
    let mut stream = TcpStream::connect(&addr).await?;

    let payload = Payload {
        sender: "client".into(),
        receiver: "server".into(),
        msg_type: MessageType::Phase1Commitment,
        data: b"Hello, server!".to_vec(),
    };

    let serialized = serde_json::to_vec(&payload)?;
    stream.write_all(&serialized).await?;

    Ok(())
}
