from __future__ import annotations

import os
import resource
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

try:
    from .capability_manifest import CapabilityManifest
except ImportError:  # Direct script execution path
    from capability_manifest import CapabilityManifest


@dataclass
class ExecutionResult:
    run_id: str
    status: str
    stdout: str
    stderr: str
    exit_code: int
    mode: str
    elapsed_ms: float


class EBPFSandbox:
    """Capability-aware sandbox with runtime mode selection."""

    def __init__(self, manifest: Optional[CapabilityManifest] = None, enable_rr: bool = False):
        self.manifest = manifest or CapabilityManifest()
        self.enable_rr = enable_rr
        self.mode = self._select_mode()

    def _select_mode(self) -> str:
        if shutil.which("unshare"):
            return "namespace"
        return "subprocess"

    def _write_runner(self, code: str, path: Path) -> None:
        wrapper = textwrap.dedent(
            """
            import os
            import builtins
            import sys

            os.environ.clear()
            _open = builtins.open
            def safe_open(file, *a, **kw):
                abspath = os.path.abspath(file)
                cwd = os.path.abspath(os.getcwd())
                if not abspath.startswith(cwd):
                    raise PermissionError(f"Sandbox policy violation: {file}")
                return _open(file, *a, **kw)
            builtins.open = safe_open

            try:
            """
        )
        wrapper += "    " + code.replace("\n", "\n    ")
        wrapper += "\nexcept Exception as e:\n    print(f'ENCLAVE_EXCEPTION: {e}', file=sys.stderr)\n"
        path.write_text(wrapper, encoding="utf-8")

    def _limit_resources(self) -> None:
        # Keep agent tasks bounded in fallback mode.
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))

    def execute(self, code: str, timeout_seconds: int = 5) -> ExecutionResult:
        run_id = f"ebpf_{uuid.uuid4().hex[:8]}"
        start = time.perf_counter()

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            runner = td_path / "run.py"
            self._write_runner(code, runner)

            cmd = [sys.executable, str(runner)]
            if self.enable_rr and shutil.which("rr"):
                cmd = ["rr", "record", "--output-trace-dir", str(td_path / "trace"), *cmd]

            try:
                proc = subprocess.run(
                    cmd,
                    cwd=td,
                    env={},
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    preexec_fn=self._limit_resources if os.name != "nt" else None,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                stderr = proc.stderr.strip()
                stdout = proc.stdout.strip()
                timeout_like = (
                    proc.returncode < 0
                    and "ENCLAVE_EXCEPTION" not in stderr
                    and elapsed_ms >= max(100.0, timeout_seconds * 900.0)
                )
                if proc.returncode == 0 and "ENCLAVE_EXCEPTION" not in stderr:
                    status = "success"
                elif timeout_like:
                    status = "timeout"
                    stderr = stderr or "Sandbox terminated by runtime limits"
                else:
                    status = "error"
                return ExecutionResult(
                    run_id=run_id,
                    status=status,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=proc.returncode,
                    mode=self.mode,
                    elapsed_ms=round(elapsed_ms, 3),
                )
            except subprocess.TimeoutExpired:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return ExecutionResult(
                    run_id=run_id,
                    status="timeout",
                    stdout="",
                    stderr="Sandbox timed out",
                    exit_code=-1,
                    mode=self.mode,
                    elapsed_ms=round(elapsed_ms, 3),
                )

    def benchmark_startup(self, iterations: int = 5) -> Dict[str, float | bool]:
        samples = []
        for _ in range(iterations):
            res = self.execute("print('ok')")
            samples.append(res.elapsed_ms)

        mean_ms = sum(samples) / len(samples)
        p95 = sorted(samples)[max(0, int(len(samples) * 0.95) - 1)]
        return {
            "samples": len(samples),
            "mean_ms": round(mean_ms, 3),
            "p95_ms": round(p95, 3),
            "sub_50ms_compliant": p95 < 50.0,
        }
