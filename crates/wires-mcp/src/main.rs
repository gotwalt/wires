use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "wires-mcp", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Subcommand, Debug)]
enum Cmd {
    /// Run the gateway HTTPS service + tenant supervisor.
    Serve,
    /// List all registered users.
    UserList {
        #[arg(long, default_value = "/etc/wires-mcp/config.toml")]
        config: std::path::PathBuf,
    },
    /// Delete a user and all their data.
    UserDelete {
        root_pubkey_hex: String,
        #[arg(long, default_value = "/etc/wires-mcp/config.toml")]
        config: std::path::PathBuf,
    },
    /// List registered OAuth clients.
    ClientList {
        #[arg(long, default_value = "/etc/wires-mcp/config.toml")]
        config: std::path::PathBuf,
    },
    /// Revoke an OAuth client.
    ClientRevoke {
        client_id: String,
        #[arg(long, default_value = "/etc/wires-mcp/config.toml")]
        config: std::path::PathBuf,
    },
    /// Rotate the token signing key (archive old, generate new).
    KeysRotate {
        #[arg(long, default_value = "/etc/wires-mcp/config.toml")]
        config: std::path::PathBuf,
    },
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve => {
            let cfg_path = std::path::PathBuf::from(std::env::var("WIRES_MCP_CONFIG").unwrap_or_else(|_| "/etc/wires-mcp/config.toml".into()));
            let cfg: wires_mcp::config::GatewayConfig = match std::fs::read_to_string(&cfg_path) {
                Ok(s) => match toml::from_str(&s) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("config parse failed: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                },
                Err(e) => {
                    eprintln!("config read failed at {}: {e}", cfg_path.display());
                    return std::process::ExitCode::FAILURE;
                }
            };
            let sk = match wires_mcp::keys::load_or_create(&cfg.token_signing_path()) {
                Ok(sk) => sk,
                Err(e) => {
                    eprintln!("token signing key load failed: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let store = match wires_mcp::store::Store::open(&cfg.gateway_db_path()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("store open failed: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let supervisor = wires_mcp::tenants::TenantSupervisor::new(
                cfg.users_dir(),
                std::time::Duration::from_secs(600),
            );
            let pair_bridge = std::sync::Arc::new(wires_mcp::pair_bridge::PairBridge::new(
                cfg.pending_pairs_dir(),
                cfg.public_url.clone(),
                store.clone(),
                supervisor.clone(),
            ));
            let state = wires_mcp::http::ServiceState {
                config: std::sync::Arc::new(cfg),
                store,
                signing_key: std::sync::Arc::new(sk),
                supervisor,
                pair_bridge,
            };
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("tokio runtime: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            match rt.block_on(wires_mcp::http::serve(state)) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("serve failed: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        Cmd::UserList { config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::user_list(&cfg) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("user-list: {e}"); std::process::ExitCode::FAILURE }
            }
        }
        Cmd::UserDelete { root_pubkey_hex, config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::user_delete(&cfg, &root_pubkey_hex) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("user-delete: {e}"); std::process::ExitCode::FAILURE }
            }
        }
        Cmd::ClientList { config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::client_list(&cfg) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("client-list: {e}"); std::process::ExitCode::FAILURE }
            }
        }
        Cmd::ClientRevoke { client_id, config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::client_revoke(&cfg, &client_id) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("client-revoke: {e}"); std::process::ExitCode::FAILURE }
            }
        }
        Cmd::KeysRotate { config } => {
            let cfg = match wires_mcp::admin::load_config(&config) {
                Ok(c) => c,
                Err(e) => { eprintln!("config: {e}"); return std::process::ExitCode::FAILURE; }
            };
            match wires_mcp::admin::keys_rotate(&cfg) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => { eprintln!("keys rotate: {e}"); std::process::ExitCode::FAILURE }
            }
        }
    }
}
