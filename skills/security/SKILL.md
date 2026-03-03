---
name: "Secure Enclaves Sandbox"
description: "Firecracker/eBPF-capable secure enclave orchestration for untrusted skill execution."
version: "2.0.0"
user-invocable: false
system-daemon: true
metadata:
  capabilities:
    - security/sandbox
    - security/firecracker
    - security/ebpf-policy
    - debugging/record-replay
  author: "OpenPango Security"
  license: "MIT"
---

# Secure Enclaves Sandbox

This skill provides a two-layer execution boundary:

1. **`EnclaveRunner`**: local fail-closed subprocess sandbox for test/dev fallback.
2. **`FirecrackerOrchestrator`**: production-oriented MicroVM planning layer with:
   - capability manifest -> seccomp policy compilation,
   - snapshot/cold-boot strategy planning,
   - deterministic record/replay command scaffolding,
   - readiness benchmarking against the <50ms objective.

## Core Files

- `enclave_runner.py`: fallback isolated runtime.
- `firecracker_orchestrator.py`: Firecracker/eBPF policy planner.
- `policies/default_caps.yaml`: capability manifest sample.
- `firecracker-orchestrator/`: Rust CLI for plan/seccomp/bench workflows.

## Python Usage

```python
from skills.security.firecracker_orchestrator import FirecrackerOrchestrator, TaskSpec

orchestrator = FirecrackerOrchestrator()
plan = orchestrator.plan_boot(
    TaskSpec(
        task_id="task-001",
        kernel_image="/opt/firecracker/vmlinux.bin",
        rootfs_image="/opt/firecracker/rootfs.ext4",
        capability_manifest="skills/security/policies/default_caps.yaml",
    ),
    use_snapshot=True,
    snapshot_path="/opt/firecracker/snapshots/ready.snap",
)

print(plan.strategy)  # snapshot-restore
print(plan.commands)
```

## Rust CLI Usage

```bash
cd skills/security/firecracker-orchestrator
cargo run -- seccomp --manifest ../policies/default_caps.yaml
cargo run -- bench --samples 41.2,43.1,39.8,44.0,42.5
cargo run -- plan --task-id task-001 --kernel /opt/vmlinux.bin --rootfs /opt/rootfs.ext4 --seccomp-path /tmp/seccomp.json --workdir /tmp --snapshot /tmp/snap.snap
```

## Validation

- Python: `python3 -m unittest skills/security/test_enclave.py skills/security/test_firecracker_orchestrator.py`
- Rust: `cargo test` (inside `skills/security/firecracker-orchestrator`)
