# Security Skill Stack

This directory now contains two complementary execution models:

- `enclave_runner.py`: strict local subprocess sandbox for fallback execution.
- `firecracker_orchestrator.py`: policy-driven Firecracker planning path with deterministic replay hooks.

## Why both exist

`EnclaveRunner` is used when Firecracker/KVM is unavailable on the host.
`FirecrackerOrchestrator` is used for production-grade isolation and benchmarkable readiness targets.

## Capability policy flow

1. Author a capability manifest (`policies/default_caps.yaml`).
2. Compile it to seccomp deny rules.
3. Build MicroVM config + boot strategy (snapshot vs cold boot).
4. Capture deterministic traces with `rr` commands from plan output.
