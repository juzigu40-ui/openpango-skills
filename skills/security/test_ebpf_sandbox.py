import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capability_manifest import CapabilityManifest
from ebpf_sandbox import EBPFSandbox


class TestEBPFSandbox(unittest.TestCase):
    def setUp(self):
        self.sandbox = EBPFSandbox(manifest=CapabilityManifest.from_dict({"capabilities": ["allow_exec"]}))

    def test_execute_success(self):
        res = self.sandbox.execute("print('hello')")
        self.assertEqual(res.status, "success")
        self.assertIn("hello", res.stdout)

    def test_execute_policy_error(self):
        res = self.sandbox.execute("with open('/etc/passwd') as f:\n    print(f.read())")
        self.assertEqual(res.status, "error")
        self.assertIn("policy", res.stderr.lower())

    def test_timeout(self):
        res = self.sandbox.execute("while True:\n    pass", timeout_seconds=1)
        self.assertEqual(res.status, "timeout")

    def test_mode_selected(self):
        self.assertIn(self.sandbox.mode, {"namespace", "subprocess"})

    def test_benchmark_shape(self):
        bench = self.sandbox.benchmark_startup(iterations=3)
        self.assertEqual(bench["samples"], 3)
        self.assertIn("mean_ms", bench)
        self.assertIn("sub_50ms_compliant", bench)


if __name__ == "__main__":
    unittest.main()
