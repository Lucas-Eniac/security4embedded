# Security Module (Linux, C++17, CMake)

This project provides a shared security module that follows dependency inversion:

- Upper applications depend only on abstract interfaces.
- Concrete crypto implementation is hidden behind provider factories.
- The module can adapt multiple backends (OpenSSL, PKCS#11, TEE, HSM).

The current implementation validates the architecture on Ubuntu 22.04 using OpenSSL.

## Architecture

- `include/security/core/crypto_provider.hpp`:
  - `ICryptoProvider` abstraction for digest/sign/verify/keygen and fixed-size user data storage access.
  - All operations return `Status` or `Result<T>` instead of exposing exceptions to upper layers.
  - `GenerateKeyPair(algorithm, bits, id)` returns PEM material and assigns a provider-managed key pair ID.
  - `Sign(...)` and `Verify(...)` use the provider-managed key pair ID instead of requiring PEM key material from the client.
  - `ICryptoProviderFactory` abstraction for backend creation.
- `include/security/core/crypto_types.hpp`:
  - Shared `ErrorCode` enumeration, default message mapping, `Status`, and `Result<T>`.
- `include/security/core/provider_factory.hpp`:
  - `ProviderRegistry` virtual-factory registry.
- `include/security/api/crypto_module.hpp`:
  - `ICryptoModule` public API for upper layer.
  - `GetProviderInfo("backend")` to query provider metadata (name/version/SN/userdata capability).
- `src/providers/openssl/*`:
  - OpenSSL adapter (backend implementation hidden from upper layer).
- `src/core/exclusive_provider.hpp`:
  - Core-layer exclusive wrapper that serializes provider calls through a Linux named semaphore.

## Supported algorithms (OpenSSL backend)

- Digest: SHA256, SM3
- Key generation: RSA, SM2
- Signature: RSA+SHA256, SM2+SM3

## User data storage (OpenSSL backend validation)

- `ICryptoProvider::ReadUserData(offset, length)` reads binary user data from a fixed-size storage area.
- `ICryptoProvider::WriteUserData(offset, length, data)` writes binary user data into that storage area.
- In the Ubuntu 22.04 OpenSSL validation environment, the storage area is simulated by `/tmp/openssl_userdata.bin`.
- The simulated storage size is fixed at 4KB.
- Reads and writes that exceed the 4KB range fail with bounds checking.

## Unified error model

- The module now reports failures through `security::core::Status` and `security::core::Result<T>`.
- `security::core::ErrorCode` centralizes common module failures such as invalid parameters, unsupported algorithms, provider lookup failures, semaphore timeout, storage I/O failures, missing key IDs, and backend crypto failures.
- `security::core::ErrorMessage(code)` returns the default message for each enum value.
- Operation-specific details are appended to the default message in the returned `status.message` field.

Common security-module errors typically include:

- Invalid input parameters, including wrong buffer sizes and empty or unknown key identifiers.
- Unsupported algorithms when a backend cannot map a requested digest, key, or signature mode.
- Provider registration or lookup failures when the requested backend is not available.
- Exclusive-access failures when the hardware lock cannot be opened, acquired, or is held past the timeout.
- Storage I/O failures while reading or writing fixed user data regions.
- Backend crypto failures returned from OpenSSL during digest, key generation, signing, verification, or PEM conversion.

## Exclusive access for embedded hardware

- To avoid concurrent hardware access, the core abstraction layer wraps each provider instance with a Linux named semaphore guard.
- All `ICryptoProvider` operations execute under the same process-shared semaphore: `/security_module_hw_lock`.
- Lock acquisition uses `sem_timedwait` with a 5-second timeout so callers fail fast instead of blocking indefinitely when the lock cannot be acquired.
- This keeps exclusion policy out of backend implementations while preserving the existing public API and provider abstraction boundaries.

## Build (Ubuntu 22.04)

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

The shared library is generated as `libsecurity_module.so` in the build directory.

## Extension points for PKCS#11 / TEE / HSM

1. Add a new provider implementation that inherits `ICryptoProvider`.
2. Add a new backend factory that inherits `ICryptoProviderFactory`.
3. Register it in module bootstrap (similar to OpenSSL factory registration).
4. Upper-layer code keeps using `ICryptoModule::CreateProvider("backend")` unchanged.

## Provider metadata API

Use `ICryptoModule::GetProviderInfo("backend")` to obtain provider metadata and check the returned `Result<ProviderInfo>::status`.

For OpenSSL backend:

- `name`: `openssl`
- `version`: runtime value from `OpenSSL_version(OPENSSL_VERSION)`
- `sn`: empty string, because the Ubuntu 22.04 OpenSSL validation backend does not represent a physical HSM chip
- `userdata_capability`: `4096`, representing the simulated 4KB user data storage at `/tmp/openssl_userdata.bin`
