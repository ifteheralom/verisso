use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

mod helper {
    pub mod message;
}
use helper::message::{Message, Payload};

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".to_string());
    let mut stream = TcpStream::connect(&addr).await?;

    let payload = Payload {
        sender: 0,
        msg: Message::Start,
    };

    let serialized = serde_json::to_vec(&payload)?;
    stream.write_all(&serialized).await?;

    Ok(())
}
