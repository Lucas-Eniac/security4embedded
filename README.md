# Security Module (Linux, C++17, CMake)

This project provides a shared security module that follows dependency inversion:

- Upper applications depend only on abstract interfaces.
- Concrete crypto implementation is hidden behind provider factories.
- The module can adapt multiple backends (OpenSSL, PKCS#11, TEE, HSM).

The current implementation validates the architecture on Ubuntu 22.04 using OpenSSL.

## Architecture

- `include/security/core/crypto_provider.hpp`:
  - `ICryptoProvider` abstraction for digest/sign/verify/keygen.
  - `ICryptoProviderFactory` abstraction for backend creation.
- `include/security/core/provider_factory.hpp`:
  - `ProviderRegistry` virtual-factory registry.
- `include/security/api/crypto_module.hpp`:
  - `ICryptoModule` public API for upper layer.
  - `GetProviderInfo("backend")` to query provider metadata (name/version).
- `src/providers/openssl/*`:
  - OpenSSL adapter (backend implementation hidden from upper layer).

## Supported algorithms (OpenSSL backend)

- Digest: SHA256, SM3
- Key generation: RSA, SM2
- Signature: RSA+SHA256, SM2+SM3

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

Use `ICryptoModule::GetProviderInfo("backend")` to obtain provider metadata.

For OpenSSL backend:

- `name`: `openssl`
- `version`: runtime value from `OpenSSL_version(OPENSSL_VERSION)`
