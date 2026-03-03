use clap::{Parser, Subcommand};
use firecracker_orchestrator::{
    build_firecracker_config, build_plan, build_seccomp_profile, readiness_report, CapManifest, TaskSpec,
};

#[derive(Debug, Parser)]
#[command(name = "firecracker-orchestrator")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Plan {
        #[arg(long)]
        task_id: String,
        #[arg(long)]
        kernel: String,
        #[arg(long)]
        rootfs: String,
        #[arg(long)]
        seccomp_path: String,
        #[arg(long)]
        workdir: String,
        #[arg(long)]
        snapshot: Option<String>,
    },
    Seccomp {
        #[arg(long)]
        manifest: String,
    },
    Bench {
        #[arg(long, value_delimiter = ',')]
        samples: Vec<f64>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Plan {
            task_id,
            kernel,
            rootfs,
            seccomp_path,
            workdir,
            snapshot,
        } => {
            let spec = TaskSpec {
                task_id,
                kernel_image: kernel,
                rootfs_image: rootfs,
                vcpu_count: 1,
                mem_mib: 128,
            };
            let cfg = build_firecracker_config(&spec, &seccomp_path, snapshot.as_deref());
            let plan = build_plan(&spec, &seccomp_path, snapshot.as_deref(), &workdir);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "firecracker": cfg,
                    "plan": plan
                }))?
            );
        }
        Commands::Seccomp { manifest } => {
            let raw = std::fs::read_to_string(manifest)?;
            let cap: CapManifest = if raw.trim_start().starts_with('{') {
                serde_json::from_str(&raw)?
            } else {
                serde_yaml::from_str(&raw)?
            };
            let profile = build_seccomp_profile(&cap);
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
        Commands::Bench { samples } => {
            let rep = readiness_report(&samples)?;
            println!("{}", serde_json::to_string_pretty(&rep)?);
        }
    }

    Ok(())
}
