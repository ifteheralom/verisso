use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

mod helper {
    pub mod message;
}

use helper::message::{MessageType, Payload};

fn handle_payload(payload: Payload) {
    // Process the payload as needed
    match payload.msg_type {
        MessageType::Phase1Commitment => println!("Processing Phase 1 Commitment"),
        MessageType::Phase1Response => println!("Processing Phase 1 Response"),
        MessageType::Phase2Commitment => println!("Processing Phase 2 Commitment"),
        MessageType::Phase2Response => println!("Processing Phase 2 Response"),
    }
}

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let node_id = std::env::var("NODE_ID")
        .unwrap_or_else(|_| {
            eprintln!("NODE_ID must be set. NODE_ID=<node_id> ...");
            std::process::exit(1);
        })
        .parse::<u16>()
        .unwrap_or_else(|_| {
            eprintln!("NODE_ID must be a number.");
            std::process::exit(1);
        });

    let port = 8000 + node_id;
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Listening on {}", listener.local_addr()?);

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        tokio::spawn(async move {
            let mut buffer = [0; 1024];

            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) => {
                        println!("Connection closed by {}", addr);
                        break;
                    }
                    Ok(n) => {
                        let payload: Payload = match serde_json::from_slice(&buffer[..n]) {
                            Ok(payload) => payload,
                            Err(e) => {
                                eprintln!("Failed to deserialize payload from {}: {}", addr, e);
                                continue;
                            }
                        };

                        handle_payload(payload);

                        if let Err(e) = socket.write_all(&buffer[..n]).await {
                            eprintln!("Failed to send response to {}: {}", addr, e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from {}: {}", addr, e);
                        break;
                    }
                }
            }
        });
    }
}
