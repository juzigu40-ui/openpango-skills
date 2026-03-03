import json
import tempfile
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capability_manifest import CapabilityManifest


class TestCapabilityManifest(unittest.TestCase):
    def test_from_dict_defaults(self):
        m = CapabilityManifest.from_dict({"capabilities": ["allow_exec"]})
        self.assertEqual(m.network_mode, "none")
        self.assertIn("allow_exec", m.capabilities)

    def test_from_file_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "caps.json"
            p.write_text(json.dumps({"capabilities": ["allow_exec", "allow_raw_socket"]}), encoding="utf-8")
            m = CapabilityManifest.from_file(str(p))
            self.assertEqual(len(m.capabilities), 2)

    def test_from_file_yaml_subset(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "caps.yaml"
            p.write_text("capabilities:\n  - allow_exec\n  - allow_ptrace\n", encoding="utf-8")
            m = CapabilityManifest.from_file(str(p))
            self.assertIn("allow_ptrace", m.capabilities)

    def test_blocked_caps(self):
        m = CapabilityManifest.from_dict({"capabilities": ["allow_exec", "allow_ptrace"]})
        self.assertEqual(m.blocked_capabilities(), {"allow_ptrace"})

    def test_allowed_syscalls(self):
        m = CapabilityManifest.from_dict({"capabilities": ["allow_exec"]})
        syscalls = m.allowed_syscalls()
        self.assertIn("execve", syscalls)
        self.assertNotIn("ptrace", syscalls)

    def test_seccomp_profile_shape(self):
        m = CapabilityManifest.from_dict({"capabilities": []})
        p = m.seccomp_profile()
        self.assertEqual(p["defaultAction"], "SCMP_ACT_ALLOW")
        self.assertTrue(len(p["syscalls"][0]["names"]) > 0)

    def test_policy_summary(self):
        m = CapabilityManifest.from_dict({"capabilities": ["allow_exec", "allow_bpf"]})
        s = m.to_policy_summary()
        self.assertIn("allow_bpf", s["blocked_caps"])
        self.assertIn("execve", s["allowed_syscalls"])


if __name__ == "__main__":
    unittest.main()
