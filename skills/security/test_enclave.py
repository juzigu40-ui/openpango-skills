import unittest
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from enclave_runner import EnclaveRunner, SandboxPolicy

class TestEnclaveRunner(unittest.TestCase):
    def setUp(self):
        self.sandbox = EnclaveRunner()

    def test_benign_code(self):
        code = "print('I am a harmless calculation: 2 + 2 =', 2+2)"
        res = self.sandbox.execute(code)
        
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("4", res["stdout"])

    def test_environment_stripping(self):
        # The environment should be empty
        malicious = "import os; print(os.environ.get('SECRET_API_KEY', 'not-found'))"
        res = self.sandbox.execute(malicious)
        
        self.assertEqual(res["status"], "success")
        self.assertIn("not-found", res["stdout"])

    def test_file_system_jail(self):
        # Attempt to read outside the temporary sandbox directory
        malicious = "with open('/etc/passwd', 'r') as f:\n    print(f.read())"
        res = self.sandbox.execute(malicious)
        
        self.assertEqual(res["status"], "error")
        self.assertIn("sandbox", res["stderr"])
        self.assertIn("Policy Violation", res["stderr"])

    def test_timeout_policy(self):
        # A runaway infinite loop should be killed
        malicious = "while True:\n    pass"
        res = self.sandbox.execute(malicious, timeout_seconds=1)
        
        self.assertEqual(res["status"], "timeout")
        self.assertIn("timed out", res["stderr"])

    def test_firecracker_plan_attachment(self):
        os.environ["OPENPANGO_SECURE_ENCLAVE_FIRECRACKER"] = "1"
        os.environ["OPENPANGO_FIRECRACKER_KERNEL"] = "/opt/firecracker/vmlinux.bin"
        os.environ["OPENPANGO_FIRECRACKER_ROOTFS"] = "/opt/firecracker/rootfs.ext4"
        try:
            sandbox = EnclaveRunner()
            res = sandbox.execute("print('ok')")
            self.assertIsNotNone(res.get("microvm_plan"))
            self.assertIn("commands", res["microvm_plan"])
        finally:
            os.environ.pop("OPENPANGO_SECURE_ENCLAVE_FIRECRACKER", None)
            os.environ.pop("OPENPANGO_FIRECRACKER_KERNEL", None)
            os.environ.pop("OPENPANGO_FIRECRACKER_ROOTFS", None)

if __name__ == '__main__':
    unittest.main()
