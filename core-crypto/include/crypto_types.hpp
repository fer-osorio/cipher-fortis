/**
 * @file crypto_types.hpp
 * @brief Shared, stable type definitions used across CipherFortis modules.
 *
 * This header intentionally has no implementation dependencies. It may be
 * included by any module — including hsm-integration — without pulling in
 * the full core-crypto implementation classes.
 */
#ifndef CIPHFORTIS_CRYPTO_TYPES_HPP
#define CIPHFORTIS_CRYPTO_TYPES_HPP

#include <cstdint>

namespace CipherFortis {

/**
 * @brief AES key length in bits.
 *
 * The underlying integer value equals the bit count, so arithmetic such as
 * \`static_cast<size_t>(lb) / 8\` yields the byte length directly.
 */
enum class KeyLengthBits : unsigned {
    _128 = 128,
    _192 = 192,
    _256 = 256,
};

/**
 * @brief AES block cipher operation mode identifier.
 */
enum class OperationModeID {
    Unknown,
    ECB,  ///< Electronic Code Book (not recommended for most uses).
    CBC,  ///< Cipher Block Chaining.
    OFB,  ///< Output Feedback.
    CTR,  ///< Counter.
};

} // namespace CipherFortis

#endif // CIPHFORTIS_CRYPTO_TYPES_HPP
