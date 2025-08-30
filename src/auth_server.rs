use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

mod helper {
    pub mod encoder;
    pub mod message;
}
mod auth_service;
mod config;
mod constant;
mod exp_utils;
mod ot;
mod signer;

use config::Config;
use helper::encoder::Encoder;
use helper::message::{Message, Payload};

use crate::auth_service::AuthenticationService;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Round1CommitmentMsg {
    round1: u32,
    commitment: Vec<u8>,
    commitment_zero_share: Vec<(u16, Vec<u8>)>,
}

async fn handle_listener(
    listener: TcpListener,
    auth_service: Arc<Mutex<AuthenticationService>>,
) -> tokio::io::Result<()> {
    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        let auth_service = Arc::clone(&auth_service);

        tokio::task::spawn(async move {
            let mut reader = BufReader::new(socket);
            let mut line = String::new();

            // println!("Buffer: {:?}", buffer);

            loop {
                line.clear();

                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        println!("Connection closed by {}", addr);
                        break;
                    }
                    Ok(_) => {
                        let text = line.trim_end_matches(&['\r', '\n'][..]);
                        if text.is_empty() {
                            continue;
                        }
                        let payload: Payload = match serde_json::from_str(text) {
                            Ok(payload) => payload,
                            Err(e) => {
                                eprintln!("Failed to deserialize payload from {}: {}", addr, e);
                                continue;
                            }
                        };

                        if let Err(e) = handle_payload(payload, &auth_service).await {
                            eprintln!("Failed to handle payload from {}: {}", addr, e);
                            continue;
                        };
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

// made async so we can await the Tokio mutex
async fn handle_payload(
    payload: Payload,
    auth_service: &Arc<Mutex<AuthenticationService>>,
) -> Result<(), String> {
    // Process the payload as needed
    match payload.msg {
        Message::Start => {
            // println!("Received Start from {}", payload.sender);
            let mut auth_service = auth_service.lock().await;
            auth_service.send_round1_request().await;
            Ok(())
        }
        Message::Round1Response {
            phase1,
            commitments,
            commitments_map,
        } => {
            let mut auth_service = auth_service.lock().await;

            let phase1 = Encoder::decode_phase1(phase1.as_str())
                .map_err(|e| format!("Decode error: {}", e))?;
            let commitments = Encoder::decode_commitments(commitments.as_str())
                .map_err(|e| format!("Decode error: {}", e))?;
            let commitments_map = Encoder::decode_map_commitments(commitments_map.as_str())
                .map_err(|e| format!("Decode error: {}", e))?;

            auth_service
                .process_round1_response(payload.sender, phase1, commitments, commitments_map)
                .await;
            Ok(())
        }
        Message::Round1FinalResponse { round1 } => {
            let mut auth_service = auth_service.lock().await;

            let round1 = Encoder::decode_phase1_output(round1.as_str())
                .map_err(|e| format!("Decode error: {}", e))?;

            auth_service
                .process_round1_final_response(payload.sender, round1)
                .await;
            Ok(())
        }
        Message::Round2Response { phase2, map } => {
            let mut auth_service = auth_service.lock().await;

            let phase2 = Encoder::decode_phase2(phase2.as_str())
                .map_err(|e| format!("Decode error: {}", e))?;
            let map =
                Encoder::decode_map(map.as_str()).map_err(|e| format!("Decode error: {}", e))?;

            auth_service
                .process_round2_response(payload.sender, phase2, map)
                .await;
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn connect_to_peer(addr: &str) -> tokio::io::Result<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    Ok(stream)
}

async fn connect_to_peers(
    self_id: &u16,
    total_nodes: &u16,
) -> HashMap<u16, Arc<Mutex<tokio::net::TcpStream>>> {
    let mut peers = HashMap::new();
    for node_id in 1..*total_nodes {
        if node_id == *self_id {
            continue;
        }
        let addr = format!("node{}:{}", node_id, 8000 + node_id);
        match connect_to_peer(&addr).await {
            Ok(stream) => {
                println!("Connected to peer {}", addr);
                peers.insert(node_id, Arc::new(Mutex::new(stream)));
            }
            Err(e) => {
                eprintln!("Failed to connect to peer {}: {}", addr, e);
            }
        }
    }
    peers
}

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let config = Config::from_env();

    // Save fields we need later before moving `config`
    let node_id = config.node_id;
    let total_nodes = config.total_nodes;

    let port = 8000;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Listening on {}", listener.local_addr()?);

    // Sleep for a few seconds to allow all nodes to start
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    let peers = Arc::new(Mutex::new(connect_to_peers(&node_id, &total_nodes).await));

    let auth_service = Arc::new(Mutex::new(AuthenticationService::init(
        config,
        5,
        peers.clone(),
    )));

    let auth_service_clone = Arc::clone(&auth_service);

    let listener_fut = handle_listener(listener, auth_service_clone);

    auth_service.lock().await.share_sk_shares().await;

    listener_fut.await?;
    Ok(())
}
