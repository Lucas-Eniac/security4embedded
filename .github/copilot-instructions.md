# Project Guidelines

## Scope
- This repository builds a shared C++17 security module that validates its architecture on Ubuntu 22.04 with OpenSSL.
- The module exposes stable upper-layer APIs and core abstractions, while concrete crypto backends stay behind provider factories.
- Treat OpenSSL as the current validation backend. Keep PKCS#11, TEE, and HSM integration paths pluggable, but do not implement them unless the task explicitly requires it.

## Architecture
- Keep public API surface in `include/security/api/` and provider abstractions in `include/security/core/`.
- Do not expose OpenSSL headers, OpenSSL types, or backend-specific concepts in public headers.
- Place backend-specific code under `src/providers/<backend>/` and keep backend registration behind factories or module bootstrap.
- Preserve dependency inversion: upper-layer code should depend on `ICryptoModule`, `ICryptoProvider`, `ICryptoProviderFactory`, and `ProviderRegistry`, not concrete backend classes.
- When adding a new capability, prefer this order: update shared types or API contract, update provider abstraction if needed, implement OpenSSL path, then update validation example and documentation.

## Crypto Rules
- Do not implement foundational cryptographic algorithms from scratch in this repository.
- Use lower-layer providers such as OpenSSL for digest, key generation, signing, and verification behavior.
- Add new algorithm enums or capability types only when they represent backend-agnostic functionality that can also map to future PKCS#11, TEE, or HSM providers.
- If an API would only make sense for one backend, isolate it in that backend adapter instead of expanding the generic interface.

## Build And Test
- Use CMake for all build changes.
- Primary library target: `security_module`.
- Validation executable target: `security_validation`.
- Keep the project buildable with the existing OpenSSL dependency model in `CMakeLists.txt`.
- When changing CMake-based code, prefer building and testing the affected targets to verify the shared library and validation example still work.

## Code Style
- Follow the existing C++17 style and naming already used in `include/` and `src/`.
- Prefer small, focused changes that preserve current interfaces unless the task requires an API change.
- Keep backend-specific includes and helper code out of generic layers when possible.
- Update `README.md` when supported algorithms, backend behavior, build steps, or extension points change.

## Task Expectations
- For architecture or refactoring work, explain which layer changed: public API, core abstraction, provider factory, backend implementation, or example validation.
- For algorithm support changes, state what is available generically versus what is only validated through the OpenSSL backend.
- Flag portability risks whenever a change makes future PKCS#11, TEE, or HSM support harder.