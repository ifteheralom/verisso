pub struct Config {
    pub node_id: u16,
    pub total_nodes: u16,
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

        Config {
            node_id,
            total_nodes,
        }
    }
}
