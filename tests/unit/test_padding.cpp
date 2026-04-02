#include <gtest/gtest.h>
#include <stdexcept>
#include "../../core-crypto/src/utils/padding.hpp"

using namespace CipherFortis::Padding;

static constexpr size_t BLOCK = 16;

// ---------------------------------------------------------------------------
// block_aligned_size
// ---------------------------------------------------------------------------

TEST(PaddingUtils, BlockAlignedSize) {
    EXPECT_EQ(block_aligned_size(0,  BLOCK), 16u);
    EXPECT_EQ(block_aligned_size(1,  BLOCK), 16u);
    EXPECT_EQ(block_aligned_size(15, BLOCK), 16u);
    EXPECT_EQ(block_aligned_size(16, BLOCK), 16u);
    EXPECT_EQ(block_aligned_size(17, BLOCK), 32u);
    EXPECT_EQ(block_aligned_size(31, BLOCK), 32u);
    EXPECT_EQ(block_aligned_size(32, BLOCK), 32u);
}

// ---------------------------------------------------------------------------
// pkcs7_pad_length
// ---------------------------------------------------------------------------

TEST(PaddingUtils, Pkcs7PadLength_NonAligned) {
    // Result must be in [1, BLOCK]
    for (size_t n : {1u, 15u, 17u, 31u}) {
        size_t pl = pkcs7_pad_length(n, BLOCK);
        EXPECT_GE(pl, 1u)    << "n=" << n;
        EXPECT_LE(pl, BLOCK) << "n=" << n;
        EXPECT_EQ((n + pl) % BLOCK, 0u) << "n=" << n;
    }
}

TEST(PaddingUtils, Pkcs7PadLength_Aligned) {
    // When n is already a multiple of BLOCK, a full padding block is added
    EXPECT_EQ(pkcs7_pad_length(0,  BLOCK), BLOCK);
    EXPECT_EQ(pkcs7_pad_length(16, BLOCK), BLOCK);
    EXPECT_EQ(pkcs7_pad_length(32, BLOCK), BLOCK);
}

// ---------------------------------------------------------------------------
// Local pad/unpad helpers (mirrors Cipher::pkcs7_pad / pkcs7_unpad logic)
// ---------------------------------------------------------------------------

static std::vector<uint8_t> local_pad(const std::vector<uint8_t>& input) {
    size_t pad_len = pkcs7_pad_length(input.size(), BLOCK);
    std::vector<uint8_t> out(input);
    out.insert(out.end(), pad_len, static_cast<uint8_t>(pad_len));
    return out;
}

static std::vector<uint8_t> local_unpad(const std::vector<uint8_t>& padded) {
    if (padded.empty() || padded.size() % BLOCK != 0)
        throw std::invalid_argument("pkcs7_unpad: size not a positive multiple of BLOCK");
    uint8_t pad_val = padded.back();
    if (pad_val == 0 || pad_val > BLOCK)
        throw std::invalid_argument("pkcs7_unpad: invalid padding byte value");
    for (size_t i = padded.size() - pad_val; i < padded.size(); ++i)
        if (padded[i] != pad_val)
            throw std::invalid_argument("pkcs7_unpad: inconsistent padding bytes");
    return std::vector<uint8_t>(padded.begin(), padded.end() - pad_val);
}

// ---------------------------------------------------------------------------
// Round-trip identity for lengths 0–32
// ---------------------------------------------------------------------------

TEST(PaddingUtils, RoundTrip) {
    for (size_t len = 0; len <= 32; ++len) {
        std::vector<uint8_t> original(len);
        for (size_t i = 0; i < len; ++i)
            original[i] = static_cast<uint8_t>(i & 0xFF);

        std::vector<uint8_t> padded   = local_pad(original);
        std::vector<uint8_t> recovered = local_unpad(padded);

        EXPECT_EQ(recovered, original) << "Round-trip failed for len=" << len;
        EXPECT_EQ(padded.size() % BLOCK, 0u) << "Padded size not aligned for len=" << len;
    }
}

// ---------------------------------------------------------------------------
// Corruption rejection
// ---------------------------------------------------------------------------

TEST(PaddingUtils, RejectLastByteZero) {
    std::vector<uint8_t> buf(16, 0x01);
    buf.back() = 0x00;  // invalid: pad value 0
    EXPECT_THROW(local_unpad(buf), std::invalid_argument);
}

TEST(PaddingUtils, RejectLastByteOverBlock) {
    std::vector<uint8_t> buf(16, 0x11);
    buf.back() = 17;  // invalid: pad value > BLOCK_SIZE
    EXPECT_THROW(local_unpad(buf), std::invalid_argument);
}

TEST(PaddingUtils, RejectInconsistentPaddingBytes) {
    // Claim 3 bytes of padding but corrupt one
    std::vector<uint8_t> buf(16, 0x00);
    buf[13] = 0x03;
    buf[14] = 0x02;  // inconsistent
    buf[15] = 0x03;
    EXPECT_THROW(local_unpad(buf), std::invalid_argument);
}
