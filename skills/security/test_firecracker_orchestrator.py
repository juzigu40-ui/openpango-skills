import json
import tempfile
import unittest
from pathlib import Path

from firecracker_orchestrator import FirecrackerOrchestrator, TaskSpec


class TestFirecrackerOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.orch = FirecrackerOrchestrator(str(self.root / "workspace"))

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_simple_yaml_manifest(self):
        manifest_path = self.root / "caps.yaml"
        manifest_path.write_text("capabilities:\n  - allow_exec\n  - allow_raw_socket\n", encoding="utf-8")

        data = self.orch.load_manifest(str(manifest_path))
        self.assertEqual(data["capabilities"], ["allow_exec", "allow_raw_socket"])

    def test_seccomp_blocks_ptrace_by_default(self):
        profile = self.orch.build_seccomp_profile({"capabilities": ["allow_exec"]})
        names = profile["syscalls"][0]["names"]
        self.assertIn("ptrace", names)
        self.assertNotIn("execve", names)

    def test_plan_boot_writes_expected_files(self):
        manifest_path = self.root / "caps.yaml"
        manifest_path.write_text("capabilities:\n  - allow_exec\n", encoding="utf-8")

        spec = TaskSpec(
            task_id="t-001",
            kernel_image="/opt/vmlinux.bin",
            rootfs_image="/opt/rootfs.ext4",
            capability_manifest=str(manifest_path),
        )
        plan = self.orch.plan_boot(spec, use_snapshot=True, snapshot_path="/opt/snapshots/s0.snap")

        self.assertEqual(plan.strategy, "snapshot-restore")
        self.assertTrue(Path(plan.firecracker_cfg_path).exists())
        self.assertTrue(Path(plan.seccomp_cfg_path).exists())

        cfg = json.loads(Path(plan.firecracker_cfg_path).read_text(encoding="utf-8"))
        self.assertIn("snapshot", cfg)

    def test_benchmark_flags_target(self):
        healthy = self.orch.benchmark_readiness([42.0, 44.0, 41.5, 46.0, 43.2])
        self.assertTrue(healthy["target_under_50ms"])

        degraded = self.orch.benchmark_readiness([42.0, 90.0, 80.0, 70.0, 65.0])
        self.assertFalse(degraded["target_under_50ms"])


if __name__ == "__main__":
    unittest.main()
