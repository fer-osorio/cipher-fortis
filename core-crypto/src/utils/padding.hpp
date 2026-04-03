#ifndef PADDING_HPP
#define PADDING_HPP

#include <cstddef>
#include <stdexcept>

namespace CipherFortis::Padding {

// Returns the smallest multiple of block_size that is >= n.
constexpr size_t block_aligned_size(size_t n, size_t block_size) {
    if(n == 0) return block_size;
    return ((n + block_size - 1) / block_size) * block_size;
}

// Returns the number of padding bytes PKCS#7 would append to a message of length n.
// Always in range [1, block_size].
constexpr size_t pkcs7_pad_length(size_t n, size_t block_size) {
    return block_size - (n % block_size);
}

// Returns the number of zero bytes needed to align n to the nearest block_size boundary.
// Returns 0 when n is already a multiple of block_size.
constexpr size_t alignment_gap(size_t n, size_t block_size) {
    size_t rem = n % block_size;
    return rem == 0 ? 0 : block_size - rem;
}

} // namespace CipherFortis::Padding

#endif
