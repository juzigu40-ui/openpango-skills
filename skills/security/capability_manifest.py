from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set


DEFAULT_BLOCKED_CAPABILITIES = {
    "allow_ptrace",
    "allow_raw_socket",
    "allow_bpf",
}

CAPABILITY_TO_SYSCALLS = {
    "allow_exec": {"execve", "execveat"},
    "allow_ptrace": {"ptrace"},
    "allow_raw_socket": {"socket", "socketpair"},
    "allow_bpf": {"bpf"},
    "allow_mount": {"mount", "umount2"},
}

BASE_DENYLIST = {
    "execve",
    "execveat",
    "ptrace",
    "socket",
    "socketpair",
    "bpf",
    "mount",
    "umount2",
    "kexec_load",
}


@dataclass
class CapabilityManifest:
    capabilities: List[str] = field(default_factory=list)
    network_mode: str = "none"
    trace_mode: str = "rr"

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "CapabilityManifest":
        caps = [str(c) for c in (payload.get("capabilities") or [])]
        return cls(
            capabilities=caps,
            network_mode=str(payload.get("network_mode") or "none"),
            trace_mode=str(payload.get("trace_mode") or "rr"),
        )

    @classmethod
    def from_file(cls, path: str) -> "CapabilityManifest":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)

        raw = p.read_text(encoding="utf-8")
        if p.suffix.lower() == ".json":
            return cls.from_dict(json.loads(raw))

        try:
            import yaml  # type: ignore

            return cls.from_dict(yaml.safe_load(raw) or {})
        except Exception:
            return cls.from_dict(cls._parse_simple_yaml(raw))

    @staticmethod
    def _parse_simple_yaml(raw: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        key: str | None = None
        for line in raw.splitlines():
            line = line.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if ":" in line and not line.lstrip().startswith("-"):
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if not v:
                    result[k] = []
                    key = k
                else:
                    result[k] = v
                    key = None
                continue
            if line.lstrip().startswith("-") and key:
                result[key].append(line.lstrip()[1:].strip())
        return result

    def blocked_capabilities(self) -> Set[str]:
        return set(self.capabilities) & DEFAULT_BLOCKED_CAPABILITIES

    def allowed_syscalls(self) -> Set[str]:
        out: Set[str] = set()
        for cap in self.capabilities:
            if cap in DEFAULT_BLOCKED_CAPABILITIES:
                continue
            out.update(CAPABILITY_TO_SYSCALLS.get(cap, set()))
        return out

    def seccomp_profile(self) -> Dict[str, Any]:
        blocked_syscalls = sorted(BASE_DENYLIST - self.allowed_syscalls())
        return {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
            "syscalls": [
                {
                    "names": blocked_syscalls,
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                }
            ],
        }

    def to_policy_summary(self) -> Dict[str, Any]:
        return {
            "capability_count": len(self.capabilities),
            "network_mode": self.network_mode,
            "trace_mode": self.trace_mode,
            "blocked_caps": sorted(self.blocked_capabilities()),
            "allowed_syscalls": sorted(self.allowed_syscalls()),
            "blocked_syscalls": sorted(BASE_DENYLIST - self.allowed_syscalls()),
        }
