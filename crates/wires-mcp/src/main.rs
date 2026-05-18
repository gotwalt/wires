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
            tracing::info!("wires-mcp serve: scaffold only, see plan task 7");
            std::process::ExitCode::SUCCESS
        }
    }
}
