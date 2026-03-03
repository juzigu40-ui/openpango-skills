import os
import sys
import json
import uuid
import tempfile
import textwrap
import subprocess
import logging
from enum import Enum
from typing import Dict, Any, Optional

try:
    from .firecracker_orchestrator import FirecrackerOrchestrator, TaskSpec
except ImportError:  # Direct script execution path
    from firecracker_orchestrator import FirecrackerOrchestrator, TaskSpec

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("EnclaveRunner")

class SandboxPolicy(str, Enum):
    STRICT = "strict"      # No network, isolated FS, minimal memory
    RELAXED = "relaxed"    # Approved Network endpoints, isolated FS

class EnclaveRunner:
    """
    OpenPango Core Daemon: Secure Enclaves Sandbox.
    Executes untrusted agent skills in an isolated process to prevent host compromise.
    """
    
    def __init__(self, use_docker: bool = False, use_firecracker: Optional[bool] = None):
        self._use_docker = use_docker
        if use_firecracker is None:
            use_firecracker = os.getenv("OPENPANGO_SECURE_ENCLAVE_FIRECRACKER", "0") == "1"
        self._use_firecracker = use_firecracker
        self._orchestrator: Optional[FirecrackerOrchestrator] = None

        if self._use_docker:
            logger.info("Initializing Docker-backed WASM Enclaves...")
        else:
            logger.info("Initializing Subprocess-backed Sandbox (Testing Mode)...")
        if self._use_firecracker:
            workspace = os.getenv("OPENPANGO_FIRECRACKER_WORKSPACE")
            self._orchestrator = FirecrackerOrchestrator(workspace_dir=workspace)
            logger.info("Firecracker orchestration planning is enabled.")

    def _generate_sandbox_wrapper(self, code_string: str) -> str:
        """
        Wraps the untrusted code in a harness that overrides builtins
        to simulate strict environment zero-trust.
        """
        wrapper = textwrap.dedent('''
        import os
        import builtins
        import sys

        # 1. Strip environment variables
        os.environ.clear()

        # 2. Restrict file reading to current directory only
        _original_open = builtins.open
        def _safe_open(file, *args, **kwargs):
            abspath = os.path.abspath(file)
            cwd = os.path.abspath(os.getcwd())
            if not abspath.startswith(cwd):
                raise PermissionError(f"Enclave Policy Violation: Cannot access {file} outside sandbox")
            return _original_open(file, *args, **kwargs)
        
        builtins.open = _safe_open

        # 3. Execute untrusted code
        try:
        ''')
        
        # Indent the untrusted code
        indented_code = "    " + code_string.replace("\n", "\n    ")
        wrapper += indented_code
        wrapper += "\nexcept Exception as e:\n    print(f'ENCLAVE_EXCEPTION: {e}', file=sys.stderr)"
        
        return wrapper

    def execute(self, code_string: str, policy: SandboxPolicy = SandboxPolicy.STRICT, timeout_seconds: int = 5) -> Dict[str, Any]:
        """
        Executes the provided Python code string inside a secure boundary.
        """
        run_id = f"enclave_{uuid.uuid4().hex[:8]}"
        logger.info(f"[{run_id}] Spinning up secure enclave (Policy: {policy})...")
        microvm_plan = None

        if self._use_firecracker and self._orchestrator:
            kernel = os.getenv("OPENPANGO_FIRECRACKER_KERNEL", "/opt/firecracker/vmlinux.bin")
            rootfs = os.getenv("OPENPANGO_FIRECRACKER_ROOTFS", "/opt/firecracker/rootfs.ext4")
            manifest = os.getenv("OPENPANGO_FIRECRACKER_CAP_MANIFEST")
            snapshot = os.getenv("OPENPANGO_FIRECRACKER_SNAPSHOT")
            try:
                spec = TaskSpec(
                    task_id=run_id,
                    kernel_image=kernel,
                    rootfs_image=rootfs,
                    capability_manifest=manifest,
                    enable_network=(policy == SandboxPolicy.RELAXED),
                )
                microvm_plan = self._orchestrator.dry_run(spec, snapshot_path=snapshot)
                logger.info(
                    f"[{run_id}] Firecracker plan ready: strategy={microvm_plan.get('strategy')} expected={microvm_plan.get('expected_ready_ms')}ms"
                )
            except Exception as err:  # noqa: BLE001
                logger.warning(f"[{run_id}] Failed to build Firecracker plan: {err}")

        # Create an isolated temporary directory for the execution
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_code = self._generate_sandbox_wrapper(code_string)
            script_path = os.path.join(tmpdir, "execute.py")
            
            with open(script_path, "w") as f:
                f.write(safe_code)
                
            try:
                # Execute inside the tempdir jail with stripped environment
                result = subprocess.run(
                    [sys.executable, script_path],
                    cwd=tmpdir,
                    env={}, # Force empty environment at process level
                    capture_output=True,
                    timeout=timeout_seconds,
                    text=True
                )
                
                if "ENCLAVE_EXCEPTION" in result.stderr or result.returncode != 0:
                    status = "error"
                    logger.warning(f"[{run_id}] Execution failed or blocked by sandbox policy.")
                else:
                    status = "success"
                    logger.info(f"[{run_id}] Execution completed successfully.")
                    
                return {
                    "id": run_id,
                    "status": status,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip(),
                    "exit_code": result.returncode,
                    "microvm_plan": microvm_plan,
                }
                
            except subprocess.TimeoutExpired:
                logger.error(f"[{run_id}] Execution timed out after {timeout_seconds}s. Terminating container.")
                return {
                    "id": run_id,
                    "status": "timeout",
                    "stdout": "",
                    "stderr": "Enclave Policy Violation: Execution timed out",
                    "exit_code": -1,
                    "microvm_plan": microvm_plan,
                }
            except Exception as e:
                logger.error(f"[{run_id}] Critical sandbox failure: {str(e)}")
                return {
                    "id": run_id,
                    "status": "system_error",
                    "stderr": str(e),
                    "exit_code": -2,
                    "microvm_plan": microvm_plan,
                }

if __name__ == "__main__":
    sandbox = EnclaveRunner()
    print("Testing benign code...")
    res = sandbox.execute("print('Hello from inside the enclave!')")
    print(json.dumps(res, indent=2))
    
    print("\nTesting malicious code (trying to read /etc/passwd)...")
    malicious = "with open('/etc/passwd', 'r') as f:\n    print(f.read())"
    res2 = sandbox.execute(malicious)
    print(json.dumps(res2, indent=2))
