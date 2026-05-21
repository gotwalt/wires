use clap::{Parser, Subcommand};

use wires_cli::cmd;

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
    /// Initialize identity (Ed25519 + X25519) in the data directory.
    Init {
        /// Generate a fresh local root key in addition to identity. Use this for
        /// the fabric operator (Alice). Without it, `init` writes identity
        /// only and the agent has no fabric pinning until paired.
        #[arg(long)]
        new_root: bool,
    },
    /// Print identity, derived topic ids, and config summary
    Status,
    /// Topic management
    #[command(subcommand)]
    Topic(TopicCmd),
    /// Channel management (spec: wires-channels-design)
    #[command(subcommand)]
    Channel(ChannelCmd),
    /// Direct messages.
    #[command(subcommand)]
    Dm(DmCmd),
    /// Update this agent's self-described member metadata (kind/display_name/description).
    /// Republishes into every channels.* topic the agent participates in.
    Me {
        #[arg(long)]
        kind: String,
        #[arg(long = "display-name")]
        display_name: String,
        #[arg(long)]
        description: Option<String>,
    },
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
    /// Revoke a capability by id
    Revoke { cap_id: String },
    /// Host control: pair this fabric with a host, register topics, view status.
    #[command(subcommand)]
    Host(HostCmd),
    /// Start a pair-listen window; print a PairRequest token; wait for a
    /// pair-approve dial.
    PairListen {
        #[arg(long)]
        role: String,
        #[arg(long)]
        description: String,
        /// Topic-name + rights, e.g. "home.notes:read+write". Repeatable.
        #[arg(long = "request", required = true)]
        request: Vec<String>,
        /// Pair window TTL. Examples: "5m", "60s", "1h".
        #[arg(long, default_value = "5m")]
        ttl: humantime::Duration,
        #[arg(long)]
        qr: bool,
    },
    /// Decode and approve a PairRequest from an agent.
    PairApprove {
        /// Base64 PairRequest token.
        token: String,
        /// Narrow per-topic rights, e.g. `--scope home.notes:read`. Repeatable.
        #[arg(long = "scope")]
        scope: Vec<String>,
        /// Narrow to a subset of requested topic names. Comma-separated.
        #[arg(long = "topics", value_delimiter = ',')]
        topics: Option<Vec<String>>,
        /// Omit host info from the grant.
        #[arg(long)]
        no_host: bool,
        /// Skip the interactive prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum TopicCmd {
    /// Create a new topic
    Create { name: String },
}

#[derive(Subcommand)]
enum ChannelCmd {
    /// Create a named channel.
    Create {
        name: String,
        #[arg(long)]
        description: Option<String>,
    },
    /// List channels this agent is a full member of.
    List,
    /// Show the member roster for a channel.
    Members { name: String },
    /// Invite an agent to a channel (publishes a sealed history_grant + a public invite).
    Invite { name: String, agent: String },
}

#[derive(Subcommand)]
enum DmCmd {
    /// Open or send to a DM with another agent (by their ed25519 pubkey hex).
    Open {
        agent: String,
        #[arg(long)]
        message: Option<String>,
    },
    /// List local DM topics.
    List,
}

#[derive(Subcommand)]
enum HostCmd {
    /// Pair with a host: decode a HostTicket, register this fabric (signed by
    /// your local root key), persist the host info.
    Pair {
        /// HostTicket string (base64), or `@<path>` to read from a file.
        #[arg(long)]
        ticket: String,
    },
    /// Register a topic with the paired host so it persists envelopes for it.
    TopicRegister { topic: String },
    /// Unregister a topic: the host stops persisting new envelopes (existing
    /// data is retained until eviction).
    TopicUnregister { topic: String },
    /// Unregister this fabric from the host: the host drops its fabric record,
    /// every topic_index entry for this root, and the on-disk fabric directory.
    /// Clears the local `config.toml` host block on success.
    FabricUnregister {
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Print this fabric's host-side status.
    Status,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let data_dir = cli
        .data_dir
        .unwrap_or_else(|| dirs_data_dir().unwrap_or_else(|| std::path::PathBuf::from(".wires")));

    let result = match cli.command {
        Cmd::Init { new_root } => cmd::init::run(&data_dir, new_root).await,
        Cmd::Status => cmd::status::run(&data_dir).await,
        Cmd::Topic(TopicCmd::Create { name }) => cmd::topic::create(&data_dir, &name).await,
        Cmd::Channel(ChannelCmd::Create { name, description }) => {
            cmd::channel::create(&data_dir, &name, description.as_deref()).await
        }
        Cmd::Channel(ChannelCmd::List) => cmd::channel::list(&data_dir).await,
        Cmd::Channel(ChannelCmd::Members { name }) => cmd::channel::members(&data_dir, &name).await,
        Cmd::Channel(ChannelCmd::Invite { name, agent }) => {
            cmd::channel::invite(&data_dir, &name, &agent).await
        }
        Cmd::Dm(DmCmd::Open { agent, message }) => {
            cmd::dm::open(&data_dir, &agent, message.as_deref()).await
        }
        Cmd::Dm(DmCmd::List) => cmd::dm::list(&data_dir).await,
        Cmd::Me {
            kind,
            display_name,
            description,
        } => cmd::me::set(&data_dir, &kind, &display_name, description.as_deref()).await,
        Cmd::Publish {
            topic,
            cap,
            r#type,
            text,
            data,
        } => cmd::publish::run(&data_dir, &topic, &cap, &r#type, &text, data.as_deref()).await,
        Cmd::Cat { topic, tail } => cmd::cat::run(&data_dir, &topic, tail).await,
        Cmd::Revoke { cap_id } => cmd::revoke::run(&data_dir, &cap_id).await,
        Cmd::Host(HostCmd::Pair { ticket }) => cmd::host::pair(&data_dir, &ticket).await,
        Cmd::Host(HostCmd::TopicRegister { topic }) => {
            cmd::host::topic_register(&data_dir, &topic).await
        }
        Cmd::Host(HostCmd::TopicUnregister { topic }) => {
            cmd::host::topic_unregister(&data_dir, &topic).await
        }
        Cmd::Host(HostCmd::FabricUnregister { yes }) => {
            cmd::host::fabric_unregister(&data_dir, yes).await
        }
        Cmd::Host(HostCmd::Status) => cmd::host::status(&data_dir).await,
        Cmd::PairListen {
            role,
            description,
            request,
            ttl,
            qr,
        } => cmd::pair_listen::run(&data_dir, role, description, request, ttl.into(), qr).await,
        Cmd::PairApprove {
            token,
            scope,
            topics,
            no_host,
            yes,
        } => cmd::pair_approve::run(&data_dir, &token, scope, topics, no_host, yes).await,
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
