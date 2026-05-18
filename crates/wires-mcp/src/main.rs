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
            let state = wires_mcp::http::ServiceState {
                config: std::sync::Arc::new(cfg),
                store,
                signing_key: std::sync::Arc::new(sk),
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
    }
}
