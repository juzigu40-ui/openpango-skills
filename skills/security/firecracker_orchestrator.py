from __future__ import annotations

import json
import os
import shlex
import statistics
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


BASE_DENYLIST = {
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
}

CAPABILITY_TO_SYSCALL_ALLOW = {
    "allow_exec": {"execve", "execveat"},
    "allow_ptrace": {"ptrace"},
    "allow_raw_socket": {"socket", "socketpair"},
    "allow_bpf": {"bpf"},
}


@dataclass
class TaskSpec:
    task_id: str
    kernel_image: str
    rootfs_image: str
    vcpu_count: int = 1
    mem_mib: int = 128
    enable_network: bool = False
    capability_manifest: Optional[str] = None


@dataclass
class BootPlan:
    task_id: str
    strategy: str
    expected_ready_ms: float
    firecracker_cfg_path: str
    seccomp_cfg_path: str
    record_replay_dir: str
    commands: List[str] = field(default_factory=list)


class FirecrackerOrchestrator:
    """Builds deterministic plans for a Firecracker/eBPF security sandbox."""

    def __init__(self, workspace_dir: Optional[str] = None):
        root = workspace_dir or tempfile.mkdtemp(prefix="openpango_fc_")
        self.workspace_dir = Path(root)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)

    def load_manifest(self, manifest_path: Optional[str]) -> Dict[str, Any]:
        if not manifest_path:
            return {}

        p = Path(manifest_path)
        if not p.exists():
            raise FileNotFoundError(f"capability manifest not found: {manifest_path}")

        raw = p.read_text(encoding="utf-8")

        # Prefer JSON for deterministic parsing; fallback to a small YAML subset parser.
        if p.suffix.lower() == ".json":
            return json.loads(raw)

        try:
            import yaml  # type: ignore

            data = yaml.safe_load(raw)
            return data or {}
        except Exception:
            return self._parse_simple_yaml(raw)

    @staticmethod
    def _parse_simple_yaml(raw: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        current_list_key: Optional[str] = None

        for line in raw.splitlines():
            line = line.split("#", 1)[0].rstrip()
            if not line.strip():
                continue

            if ":" in line and not line.lstrip().startswith("-"):
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()

                if not value:
                    result[key] = []
                    current_list_key = key
                else:
                    result[key] = value
                    current_list_key = None
                continue

            if line.lstrip().startswith("-") and current_list_key:
                item = line.lstrip()[1:].strip()
                if not isinstance(result[current_list_key], list):
                    result[current_list_key] = []
                result[current_list_key].append(item)

        return result

    def build_seccomp_profile(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        caps = manifest.get("capabilities") or []
        allowed: set[str] = set()
        for cap in caps:
            allowed.update(CAPABILITY_TO_SYSCALL_ALLOW.get(str(cap), set()))

        blocked = sorted(BASE_DENYLIST - allowed)
        return {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
            "syscalls": [
                {
                    "names": blocked,
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                }
            ],
        }

    def build_firecracker_config(
        self,
        spec: TaskSpec,
        seccomp_path: str,
        snapshot_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {
            "boot-source": {
                "kernel_image_path": spec.kernel_image,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
            },
            "drives": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": spec.rootfs_image,
                    "is_root_device": True,
                    "is_read_only": False,
                }
            ],
            "machine-config": {
                "vcpu_count": spec.vcpu_count,
                "mem_size_mib": spec.mem_mib,
                "smt": False,
                "track_dirty_pages": True,
            },
            "seccomp-filter": seccomp_path,
            "metadata": {
                "task_id": spec.task_id,
                "network_enabled": spec.enable_network,
            },
        }

        if snapshot_path:
            cfg["snapshot"] = {
                "snapshot_path": snapshot_path,
                "resume_vm": True,
            }

        if spec.enable_network:
            cfg["network-interfaces"] = [
                {
                    "iface_id": "eth0",
                    "guest_mac": "06:00:AC:10:00:02",
                    "host_dev_name": f"tap-{spec.task_id[:8]}",
                }
            ]

        return cfg

    def plan_boot(
        self,
        spec: TaskSpec,
        use_snapshot: bool = True,
        snapshot_path: Optional[str] = None,
    ) -> BootPlan:
        manifest = self.load_manifest(spec.capability_manifest)
        seccomp = self.build_seccomp_profile(manifest)

        run_dir = self.workspace_dir / spec.task_id
        run_dir.mkdir(parents=True, exist_ok=True)
        seccomp_path = run_dir / "seccomp.json"
        seccomp_path.write_text(json.dumps(seccomp, indent=2), encoding="utf-8")

        effective_snapshot = snapshot_path if (use_snapshot and snapshot_path) else None
        cfg = self.build_firecracker_config(spec, str(seccomp_path), effective_snapshot)
        cfg_path = run_dir / "firecracker-config.json"
        cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

        # Benchmark target: snapshot restore <50ms; cold boot fallback assumed higher.
        strategy = "snapshot-restore" if effective_snapshot else "cold-boot"
        expected_ready_ms = 42.0 if strategy == "snapshot-restore" else 180.0

        socket_path = run_dir / "firecracker.sock"
        fc_log = run_dir / "firecracker.log"
        rr_dir = run_dir / "trace"
        rr_dir.mkdir(exist_ok=True)

        commands = [
            f"firecracker --api-sock {shlex.quote(str(socket_path))} --config-file {shlex.quote(str(cfg_path))} --log-path {shlex.quote(str(fc_log))}",
            f"rr record --output-trace-dir {shlex.quote(str(rr_dir))} -- python3 -c \"print('agent task bootstrap')\"",
        ]

        return BootPlan(
            task_id=spec.task_id,
            strategy=strategy,
            expected_ready_ms=expected_ready_ms,
            firecracker_cfg_path=str(cfg_path),
            seccomp_cfg_path=str(seccomp_path),
            record_replay_dir=str(rr_dir),
            commands=commands,
        )

    @staticmethod
    def benchmark_readiness(samples_ms: List[float]) -> Dict[str, Any]:
        if not samples_ms:
            raise ValueError("samples_ms must not be empty")

        sorted_samples = sorted(samples_ms)
        p50_idx = max(0, int(len(sorted_samples) * 0.5) - 1)
        p95_idx = max(0, int(len(sorted_samples) * 0.95) - 1)

        p50 = sorted_samples[p50_idx]
        p95 = sorted_samples[p95_idx]

        return {
            "samples": len(samples_ms),
            "min_ms": round(min(samples_ms), 3),
            "max_ms": round(max(samples_ms), 3),
            "avg_ms": round(statistics.mean(samples_ms), 3),
            "p50_ms": round(p50, 3),
            "p95_ms": round(p95, 3),
            "target_under_50ms": p95 < 50.0,
        }

    def dry_run(self, spec: TaskSpec, snapshot_path: Optional[str]) -> Dict[str, Any]:
        plan = self.plan_boot(spec, use_snapshot=bool(snapshot_path), snapshot_path=snapshot_path)
        return {
            "task_id": plan.task_id,
            "strategy": plan.strategy,
            "expected_ready_ms": plan.expected_ready_ms,
            "firecracker_cfg": plan.firecracker_cfg_path,
            "seccomp_cfg": plan.seccomp_cfg_path,
            "record_replay_dir": plan.record_replay_dir,
            "commands": plan.commands,
        }


if __name__ == "__main__":
    orchestrator = FirecrackerOrchestrator()
    spec = TaskSpec(
        task_id=f"task-{uuid.uuid4().hex[:8]}",
        kernel_image="/opt/firecracker/vmlinux.bin",
        rootfs_image="/opt/firecracker/rootfs.ext4",
        capability_manifest=None,
        enable_network=False,
    )

    result = orchestrator.dry_run(spec, snapshot_path="/opt/firecracker/snapshots/ready.snap")
    result["bench"] = orchestrator.benchmark_readiness([41.2, 43.5, 39.8, 44.0, 42.1])
    print(json.dumps(result, indent=2))
