use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod helper {
    pub mod encoder;
    pub mod message;
}
// mod auth_service;
mod auth_service;
mod config;
mod constant;
mod exp_utils;
mod ot;
mod signer;

use config::Config;
use helper::encoder::Encoder;
use helper::message::{Message, Payload};
use signer::Signer;

async fn handle_listener(
    listener: TcpListener,
    config: Arc<Config>,
    signer: Arc<Mutex<Signer>>,
    main_stream: Arc<Mutex<tokio::net::TcpStream>>,
) -> tokio::io::Result<()> {
    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection from {}", addr);

        let signer = Arc::clone(&signer);
        let main_stream = Arc::clone(&main_stream);

        let config = Arc::clone(&config);

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

                        if let Err(e) =
                            handle_payload(payload, &config, &signer, &main_stream).await
                        {
                            eprintln!("Failed to handle payload from {}: {}", addr, e);
                            continue;
                        };

                        // if let Err(e) = socket.write_all(&buffer[..n]).await {
                        //     eprintln!("Failed to send response to {}: {}", addr, e);
                        //     break;
                        // }
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

async fn send_message(
    stream: &mut tokio::net::TcpStream,
    payload: &Payload,
) -> tokio::io::Result<()> {
    let mut serialized = serde_json::to_vec(payload)?;
    serialized.push(b'\n');
    stream.write_all(&serialized).await?;
    Ok(())
}

// made async so we can await the Tokio mutex
async fn handle_payload(
    payload: Payload,
    config: &Arc<Config>,
    signer: &Arc<Mutex<Signer>>,
    main_stream: &Arc<Mutex<tokio::net::TcpStream>>,
) -> Result<(), String> {
    // Process the payload as needed
    match payload.msg {
        Message::Start => Ok(()),
        Message::SkShares { shares } => {
            let sk_share_fr = Encoder::decode_sk_share(shares.as_str())
                .map_err(|e| format!("Decode error: {}", e))?;
            let mut s = signer.lock().await;
            s.set_sk_share(sk_share_fr);
            Ok(())
        }
        Message::Round1Request => {
            // println!("Received Round1Request from {}", payload.sender);
            let s = signer.lock().await;
            let (round1, comm, comm_zero) = s.do_round1();
            // Lock the main stream and pass a mutable reference to send_message
            let mut stream_guard = main_stream.lock().await;

            let payload = Payload {
                sender: config.node_id,
                msg: Message::Round1Response {
                    phase1: Encoder::encode_phase1(&round1),
                    commitments: Encoder::encode_commitments(&comm).unwrap(),
                    commitments_map: Encoder::encode_map_commitments(&comm_zero).unwrap(),
                },
            };

            // println!("Sending {:?}", payload);

            send_message(&mut *stream_guard, &payload)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Message::Round1FinalRequest { phase1 } => {
            let phase1 = Encoder::decode_phase1(phase1.as_str())
                .map_err(|e| format!("Decode error: {}", e))?;
            let s = signer.lock().await;
            let out = s.finish_round1(phase1);

            // Lock the main stream and pass a mutable reference to send_message
            let mut stream_guard = main_stream.lock().await;

            let payload = Payload {
                sender: config.node_id,
                msg: Message::Round1FinalResponse {
                    round1: Encoder::encode_phase1_output(&out),
                },
            };

            send_message(&mut *stream_guard, &payload)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        Message::Round2Request {
            masked_signing_key_share,
            masked_rs,
        } => {
            let masked_signing_key_share =
                Encoder::decode_vec_fr(&masked_signing_key_share).unwrap();
            let masked_rs = Encoder::decode_vec_fr(&masked_rs).unwrap();

            let s = signer.lock().await;
            let (round2, map) = s.do_round2(masked_signing_key_share, masked_rs);

            let payload = Payload {
                sender: config.node_id,
                msg: Message::Round2Response {
                    phase2: Encoder::encode_phase2(&round2),
                    map: Encoder::encode_map(&map).unwrap(),
                },
            };

            // Lock the main stream and pass a mutable reference to send_message
            let mut stream_guard = main_stream.lock().await;

            send_message(&mut *stream_guard, &payload)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn connect_to_peer(addr: &str) -> tokio::io::Result<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    Ok(stream)
}

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let config = Arc::new(Config::from_env());

    // Save fields we need later before moving `config`
    let node_id = config.node_id;
    // let total_nodes = config.total_nodes;

    let port = 8000 + node_id;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    println!("Listening on {}", listener.local_addr()?);

    // Sleep for a few seconds to allow all nodes to start
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let main_stream = connect_to_peer("node0:8000").await?;

    let signer = Arc::new(Mutex::new(Signer::new((*config).clone())));
    let main_stream = Arc::new(Mutex::new(main_stream));

    handle_listener(listener, config, signer, main_stream).await?;

    Ok(())
}
