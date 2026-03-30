#pragma once

#include "security/core/crypto_types.hpp"

namespace security::providers::openssl_impl {

security::core::Status RegisterOpenSslFactory();

} // namespace security::providers::openssl_impl
