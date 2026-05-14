use clap::{Parser, Subcommand};

mod cmd;

#[derive(Parser)]
#[command(name = "wires", about = "Local-first encrypted gossip for agents")]
struct Cli {
    /// Data directory (default: ~/.wires)
    #[arg(long, global = true)]
    data_dir: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize identity and config in the data directory
    Init {
        /// Root pubkey hex. Defaults to a freshly generated local root (for testing).
        #[arg(long)]
        root: Option<String>,
    },
    /// Print identity, derived topic ids, and config summary
    Status,
    /// Topic management
    #[command(subcommand)]
    Topic(TopicCmd),
    /// Publish a message to a topic
    Publish {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        cap: String,
        #[arg(long, default_value = "agent.note")]
        r#type: String,
        text: String,
        #[arg(long)]
        data: Option<String>,
    },
    /// Tail a topic
    Cat {
        topic: String,
        #[arg(long)]
        tail: bool,
    },
    /// Mint a new capability for an agent
    Invite {
        #[arg(long)]
        agent_pubkey: String,
        #[arg(long, value_delimiter = ',')]
        topics: Vec<String>,
        #[arg(long, value_delimiter = ',', default_values_t = vec!["read".to_string(), "write".to_string()])]
        rights: Vec<String>,
    },
    /// Revoke a capability by id
    Revoke {
        cap_id: String,
    },
}

#[derive(Subcommand)]
enum TopicCmd {
    /// Create a new topic
    Create { name: String },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        dirs_data_dir().unwrap_or_else(|| std::path::PathBuf::from(".wires"))
    });

    let result = match cli.command {
        Cmd::Init { root } => cmd::init::run(&data_dir, root).await,
        Cmd::Status => cmd::status::run(&data_dir).await,
        Cmd::Topic(TopicCmd::Create { name }) => cmd::topic::create(&data_dir, &name).await,
        Cmd::Publish { topic, cap, r#type, text, data } => {
            cmd::publish::run(&data_dir, &topic, &cap, &r#type, &text, data.as_deref()).await
        }
        Cmd::Cat { topic, tail } => cmd::cat::run(&data_dir, &topic, tail).await,
        Cmd::Invite { agent_pubkey, topics, rights } => {
            cmd::invite::run(&data_dir, &agent_pubkey, &topics, &rights).await
        }
        Cmd::Revoke { cap_id } => cmd::revoke::run(&data_dir, &cap_id).await,
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn dirs_data_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".wires"))
}
