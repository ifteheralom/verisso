#[derive(Clone)]
pub struct Config {
    pub node_id: u16,
    pub total_nodes: u16,
    pub message_count: u32,
    pub threshold_signers: u16,
    pub current_run: u32,
}

impl Config {
    pub fn from_env() -> Self {
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

        let total_nodes = std::env::var("TOTAL_NODES")
            .unwrap_or_else(|_| {
                eprintln!("TOTAL_NODES must be set. TOTAL_NODES=<total_nodes> ...");
                std::process::exit(1);
            })
            .parse::<u16>()
            .unwrap_or_else(|_| {
                eprintln!("TOTAL_NODES must be a number.");
                std::process::exit(1);
            });

        let message_count: u32 = std::env::var("MESSAGE_COUNT").map_or(5, |s| {
            s.parse::<u32>().unwrap_or_else(|_| {
                eprintln!("MESSAGE_COUNT must be a number, falling back to default 5.");
                5
            })
        });

        let threshold_signers: u16 = std::env::var("THRESHOLD_SIGNERS").map_or(5, |s| {
            s.parse::<u16>().unwrap_or_else(|_| {
                eprintln!("THRESHOLD_SIGNERS must be a number, falling back to default 5.");
                5
            })
        });

        let current_run: u32 = std::env::var("CURRENT_RUN").map_or(0, |s| {
            s.parse::<u32>().unwrap_or_else(|_| {
                eprintln!("CURRENT_RUN must be a number, falling back to default 0.");
                0
            })
        });

        println!(
            "Config - NODE_ID: {}, TOTAL_NODES: {}, MESSAGE_COUNT: {}, THRESHOLD_SIGNERS: {}, CURRENT_RUN: {}",
            node_id, total_nodes, message_count, threshold_signers, current_run
        );

        Config {
            node_id,
            total_nodes,
            message_count,
            threshold_signers,
            current_run,
        }
    }
}
