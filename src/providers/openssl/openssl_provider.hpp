#pragma once

#include <memory>

#include "security/core/crypto_provider.hpp"

namespace security::providers::openssl_impl {

std::unique_ptr<security::core::ICryptoProvider> CreateOpenSslProvider();

} // namespace security::providers::openssl_impl
