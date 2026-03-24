---
description: "Add a new cryptographic algorithm capability to the security module, including API contract, provider abstraction, OpenSSL validation path, example updates, and documentation. 适用于给安全模块新增算法能力，并同步更新抽象接口、OpenSSL 验证路径、示例和文档。"
name: "Add Algorithm Capability"
argument-hint: "Describe the algorithm to add, expected operations, API constraints, and whether it should be generic or OpenSSL-only for now."
agent: "Embedded Security Module"
---
Add a new algorithm capability to this security module.

User request:

{{input}}

Requirements:
- Work within this repository's dependency-inversion architecture.
- Keep public APIs backend-agnostic and do not expose OpenSSL or other backend-specific types in public headers.
- Do not implement foundational cryptographic algorithms from scratch.
- Treat OpenSSL on Ubuntu 22.04 as the primary implementation and validation backend unless the request explicitly requires another backend.

Execution steps:
1. Inspect the current API, core abstractions, provider registry, and OpenSSL backend to determine the smallest coherent change.
2. Decide whether the requested algorithm capability belongs in shared enums, shared types, or provider interfaces.
3. Update the public API or core abstraction only as much as needed to represent the new capability generically.
4. Implement the OpenSSL-backed path under `src/providers/openssl/`.
5. Update the validation example if the new capability should be demonstrated there.
6. Update `README.md` if supported algorithms, extension points, or validation behavior changed.
7. Build and validate the affected targets when feasible.

Response requirements:
- State which layer changed: public API, core abstraction, provider factory, backend implementation, example validation, or documentation.
- Distinguish clearly between backend-agnostic capability and OpenSSL-validated behavior.
- Flag portability risks for future PKCS#11, TEE, or HSM backends.
- If the requested capability should not be added generically, explain why and isolate it to a backend-specific path instead.