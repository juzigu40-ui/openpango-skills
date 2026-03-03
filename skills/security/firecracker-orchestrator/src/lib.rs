use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    pub task_id: String,
    pub kernel_image: String,
    pub rootfs_image: String,
    #[serde(default = "default_vcpu")]
    pub vcpu_count: u8,
    #[serde(default = "default_mem")]
    pub mem_mib: u32,
}

fn default_vcpu() -> u8 {
    1
}

fn default_mem() -> u32 {
    128
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapManifest {
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub samples: usize,
    pub min_ms: f64,
    pub max_ms: f64,
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub target_under_50ms: bool,
}

pub fn build_seccomp_profile(manifest: &CapManifest) -> serde_json::Value {
    let base_deny = BTreeSet::from([
        "execve",
        "execveat",
        "ptrace",
        "socket",
        "socketpair",
        "bpf",
        "kexec_load",
        "open_by_handle_at",
        "mount",
        "umount2",
    ]);

    let mut allowed = BTreeSet::new();
    for cap in &manifest.capabilities {
        match cap.as_str() {
            "allow_exec" => {
                allowed.insert("execve");
                allowed.insert("execveat");
            }
            "allow_ptrace" => {
                allowed.insert("ptrace");
            }
            "allow_raw_socket" => {
                allowed.insert("socket");
                allowed.insert("socketpair");
            }
            "allow_bpf" => {
                allowed.insert("bpf");
            }
            _ => {}
        }
    }

    let blocked: Vec<String> = base_deny
        .difference(&allowed)
        .map(|v| v.to_string())
        .collect();

    serde_json::json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
        "syscalls": [{
            "names": blocked,
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1
        }]
    })
}

pub fn build_firecracker_config(
    spec: &TaskSpec,
    seccomp_path: &str,
    snapshot_path: Option<&str>,
) -> serde_json::Value {
    let mut cfg = serde_json::json!({
        "boot-source": {
            "kernel_image_path": spec.kernel_image,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": spec.rootfs_image,
            "is_root_device": true,
            "is_read_only": false
        }],
        "machine-config": {
            "vcpu_count": spec.vcpu_count,
            "mem_size_mib": spec.mem_mib,
            "smt": false,
            "track_dirty_pages": true
        },
        "seccomp-filter": seccomp_path,
        "metadata": {
            "task_id": spec.task_id
        }
    });

    if let Some(path) = snapshot_path {
        cfg["snapshot"] = serde_json::json!({
            "snapshot_path": path,
            "resume_vm": true
        });
    }

    cfg
}

pub fn build_plan(
    spec: &TaskSpec,
    seccomp_path: &str,
    snapshot_path: Option<&str>,
    workdir: &str,
) -> serde_json::Value {
    let strategy = if snapshot_path.is_some() {
        "snapshot-restore"
    } else {
        "cold-boot"
    };
    let expected_ready_ms = if strategy == "snapshot-restore" { 42.0 } else { 180.0 };

    let socket = format!("{workdir}/{}/firecracker.sock", spec.task_id);
    let cfg_path = format!("{workdir}/{}/firecracker-config.json", spec.task_id);
    let log_path = format!("{workdir}/{}/firecracker.log", spec.task_id);
    let trace_dir = format!("{workdir}/{}/trace", spec.task_id);

    let mut commands = vec![format!(
        "firecracker --api-sock {socket} --config-file {cfg_path} --log-path {log_path}"
    )];
    commands.push(format!(
        "rr record --output-trace-dir {trace_dir} -- python3 -c \"print('agent task bootstrap')\""
    ));

    serde_json::json!({
        "task_id": spec.task_id,
        "strategy": strategy,
        "expected_ready_ms": expected_ready_ms,
        "commands": commands,
    })
}

pub fn readiness_report(samples: &[f64]) -> anyhow::Result<ReadinessReport> {
    if samples.is_empty() {
        anyhow::bail!("samples must not be empty");
    }

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let idx = |p: f64| -> usize {
        let i = ((sorted.len() as f64 * p) as isize - 1).max(0) as usize;
        i.min(sorted.len() - 1)
    };

    let min_ms = *sorted.first().unwrap();
    let max_ms = *sorted.last().unwrap();
    let avg_ms = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let p50_ms = sorted[idx(0.50)];
    let p95_ms = sorted[idx(0.95)];

    Ok(ReadinessReport {
        samples: sorted.len(),
        min_ms,
        max_ms,
        avg_ms,
        p50_ms,
        p95_ms,
        target_under_50ms: p95_ms < 50.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seccomp_blocks_ptrace_by_default() {
        let profile = build_seccomp_profile(&CapManifest {
            capabilities: vec!["allow_exec".into()],
        });
        let names = profile["syscalls"][0]["names"].as_array().unwrap();
        let rendered = names.iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>();
        assert!(rendered.contains(&"ptrace"));
        assert!(!rendered.contains(&"execve"));
    }

    #[test]
    fn readiness_target_flip() {
        let ok = readiness_report(&[41.0, 43.0, 42.0, 44.0, 45.0]).unwrap();
        assert!(ok.target_under_50ms);

        let bad = readiness_report(&[41.0, 99.0, 80.0, 70.0, 65.0]).unwrap();
        assert!(!bad.target_under_50ms);
    }
}
