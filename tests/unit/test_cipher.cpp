#include <gtest/gtest.h>
#include <cstring>
#include "../../testing/include/test-vectors/sp800_38a_modes.hpp"
#include "../../core-crypto/include/cipher.hpp"

namespace TV = TestVectors::AES;
namespace SP = TestVectors::AES::SP800_38A;

#define AESKEY CipherFortis::Key
#define AESKEY_LENBITS CipherFortis::Key::LengthBits

#define AESCIPHER CipherFortis::Cipher
#define AESCIPHER_OPTMODE CipherFortis::Cipher::OperationMode::Identifier

void test_successful_operations(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
void test_empty_vector_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
void test_invalid_size_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
void test_exception_safety(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm);
void test_cbc_mode_iv_handling(AESKEY_LENBITS ks);

void test_successful_operations(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    TV::KeySize ks_;
    switch(ks) {
        case AESKEY_LENBITS::_128: ks_ = TV::KeySize::AES128; break;
        case AESKEY_LENBITS::_192: ks_ = TV::KeySize::AES192; break;
        case AESKEY_LENBITS::_256: ks_ = TV::KeySize::AES256; break;
        default: GTEST_FAIL() << "Unknown key size"; return;
    }

    TV::CipherMode cm_;
    switch(cm) {
        case AESCIPHER_OPTMODE::ECB: cm_ = TV::CipherMode::ECB; break;
        case AESCIPHER_OPTMODE::CBC: cm_ = TV::CipherMode::CBC; break;
        case AESCIPHER_OPTMODE::OFB: cm_ = TV::CipherMode::OFB; break;
        case AESCIPHER_OPTMODE::CTR: cm_ = TV::CipherMode::CTR; break;
        default: GTEST_FAIL() << "Unknown cipher mode"; return;
    }

    std::unique_ptr<SP::ModeTestVectorBase> example = SP::create(ks_, cm_);
    ASSERT_NE(example, nullptr) << "Failed to create test vector";

    std::string optModeStr = TV::getCipherModeString(cm_);

    try {
        AESKEY key(example->getKey(), ks);
        AESCIPHER ciph(key, AESCIPHER::OperationMode(cm));
        const unsigned char* iv_data = (cm == AESCIPHER_OPTMODE::CTR)
            ? SP::kInitialCounter
            : SP::kInitializationVector;
        ciph.setInitialVectorForTesting(std::vector<uint8_t>(iv_data, iv_data + 16));

        EXPECT_TRUE(ciph.isKeyExpansionInitialized())
            << "Key expansion should be initialized after Cipher construction";

        std::vector<uint8_t> input = example->getInput();
        std::vector<uint8_t> encrypted(SP::kDataSize);
        std::vector<uint8_t> decrypted(SP::kDataSize);

        ciph.encryption(input, encrypted);
        EXPECT_EQ(0, memcmp(example->getExpectedOutput().data(), encrypted.data(), SP::kDataSize))
            << optModeStr + " encryption should match reference vector";

        ciph.decryption(encrypted, decrypted);
        EXPECT_EQ(0, memcmp(example->getInput().data(), decrypted.data(), SP::kDataSize))
            << optModeStr + " roundtrip should preserve data";
    } catch (const std::exception& e) {
        FAIL() << "Unexpected exception: " << e.what();
    }
}

void test_empty_vector_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    AESKEY key(ks);
    AESCIPHER cipher(key, AESCIPHER::OperationMode(cm));

    bool block_mode = (cm == AESCIPHER_OPTMODE::ECB || cm == AESCIPHER_OPTMODE::CBC);

    std::vector<uint8_t> input(SP::kDataSize);
    std::vector<uint8_t> output(SP::kDataSize);
    std::vector<uint8_t> empty(0);

    try {
        cipher.encryption(empty, output);
        FAIL() << "Should throw exception for empty input vector";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("Input data vector cannot be empty"), std::string::npos)
            << "Should mention empty input in error message";
    } catch (const std::exception& e) {
        FAIL() << "Wrong exception type: " << e.what();
    }

    // ECB/CBC manage output themselves (resize via PKCS#7); empty-output check only applies to OFB/CTR
    if (!block_mode) {
        try {
            cipher.decryption(input, empty);
            FAIL() << "Should throw exception for empty output vector";
        } catch (const std::invalid_argument& e) {
            EXPECT_NE(std::string(e.what()).find("Output data vector cannot be empty"), std::string::npos)
                << "Should mention empty output in error message";
        } catch (const std::exception& e) {
            FAIL() << "Wrong exception type: " << e.what();
        }
    }

    try {
        cipher.decryption(std::vector<uint8_t>(0), output);
        FAIL() << "Should throw exception for empty input vector";
    } catch (const std::invalid_argument& e) {
        EXPECT_NE(std::string(e.what()).find("Input data vector cannot be empty"), std::string::npos)
            << "Should mention empty input in error message";
    } catch (const std::exception& e) {
        FAIL() << "Wrong exception type: " << e.what();
    }

    if (!block_mode) {
        try {
            cipher.decryption(input, empty);
            FAIL() << "Should throw exception for empty output vector";
        } catch (const std::invalid_argument& e) {
            EXPECT_NE(std::string(e.what()).find("Output data vector cannot be empty"), std::string::npos)
                << "Should mention empty output in error message";
        } catch (const std::exception& e) {
            FAIL() << "Wrong exception type: " << e.what();
        }
    }
}

void test_invalid_size_exceptions(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    AESKEY key(ks);
    AESCIPHER cipher(key, AESCIPHER::OperationMode(cm));

    bool block_mode = (cm == AESCIPHER_OPTMODE::ECB || cm == AESCIPHER_OPTMODE::CBC);

    std::vector<uint8_t> small_input(15);
    std::vector<uint8_t> output(SP::kDataSize);

    if (block_mode) {
        // ECB/CBC accept non-aligned input via PKCS#7 — must NOT throw
        EXPECT_NO_THROW(cipher.encryption(small_input, output));
    } else {
        // OFB/CTR still reject sub-block input
        EXPECT_THROW(cipher.encryption(small_input, output), std::invalid_argument);
        EXPECT_THROW(cipher.decryption(small_input, output), std::invalid_argument);
    }
}

void test_exception_safety(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    AESKEY key(ks);
    AESCIPHER cipher(key, AESCIPHER::OperationMode(cm));

    uint8_t input[SP::kDataSize];
    uint8_t output[SP::kDataSize];

    EXPECT_TRUE(cipher.isKeyExpansionInitialized()) << "Cipher should be properly initialized";

    try {
        cipher.encrypt(nullptr, SP::kDataSize, output);
        FAIL() << "Should have thrown exception";
    } catch (const std::invalid_argument&) {
        EXPECT_TRUE(cipher.isKeyExpansionInitialized())
            << "Key expansion should still be initialized after exception";
        try {
            cipher.encrypt(input, SP::kDataSize, output);
        } catch (const std::exception& e) {
            FAIL() << "Cipher object corrupted after exception: " << e.what();
        }
    }
}

void test_cbc_mode_iv_handling(AESKEY_LENBITS ks) {
    try {
        CipherFortis::Key cbc_key(ks);
        AESCIPHER cbc_cipher(
            cbc_key, AESCIPHER::OperationMode(AESCIPHER_OPTMODE::CBC)
        );

        std::vector<uint8_t> input(SP::kDataSize);
        std::vector<uint8_t> output(SP::kDataSize);

        try {
            cbc_cipher.encryption(input, output);
        } catch (const std::exception& e) {
            std::string error_msg = e.what();
            if (error_msg.find("IV") == std::string::npos) {
                FAIL() << "Unexpected CBC error: " << e.what();
            }
        }
    } catch (const std::exception& e) {
        FAIL() << "CBC IV test failed: " << e.what();
    }
}

// ── 12 TEST cases (3 key sizes × 4 modes) ────────────────────────────────────

TEST(CipherTest, AES128_ECB) {
    test_successful_operations(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::ECB);
    test_empty_vector_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::ECB);
    test_invalid_size_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::ECB);
    test_exception_safety(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::ECB);
}
TEST(CipherTest, AES128_CBC) {
    test_successful_operations(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CBC);
    test_empty_vector_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CBC);
    test_invalid_size_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CBC);
    test_exception_safety(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CBC);
}
TEST(CipherTest, AES128_OFB) {
    test_successful_operations(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::OFB);
    test_empty_vector_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::OFB);
    test_invalid_size_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::OFB);
    test_exception_safety(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::OFB);
}
TEST(CipherTest, AES128_CTR) {
    test_successful_operations(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CTR);
    test_empty_vector_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CTR);
    test_invalid_size_exceptions(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CTR);
    test_exception_safety(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CTR);
}
TEST(CipherTest, AES192_ECB) {
    test_successful_operations(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::ECB);
    test_empty_vector_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::ECB);
    test_invalid_size_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::ECB);
    test_exception_safety(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::ECB);
}
TEST(CipherTest, AES192_CBC) {
    test_successful_operations(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CBC);
    test_empty_vector_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CBC);
    test_invalid_size_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CBC);
    test_exception_safety(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CBC);
}
TEST(CipherTest, AES192_OFB) {
    test_successful_operations(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::OFB);
    test_empty_vector_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::OFB);
    test_invalid_size_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::OFB);
    test_exception_safety(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::OFB);
}
TEST(CipherTest, AES192_CTR) {
    test_successful_operations(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CTR);
    test_empty_vector_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CTR);
    test_invalid_size_exceptions(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CTR);
    test_exception_safety(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CTR);
}
TEST(CipherTest, AES256_ECB) {
    test_successful_operations(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::ECB);
    test_empty_vector_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::ECB);
    test_invalid_size_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::ECB);
    test_exception_safety(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::ECB);
}
TEST(CipherTest, AES256_CBC) {
    test_successful_operations(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CBC);
    test_empty_vector_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CBC);
    test_invalid_size_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CBC);
    test_exception_safety(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CBC);
}
TEST(CipherTest, AES256_OFB) {
    test_successful_operations(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::OFB);
    test_empty_vector_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::OFB);
    test_invalid_size_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::OFB);
    test_exception_safety(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::OFB);
}
TEST(CipherTest, AES256_CTR) {
    test_successful_operations(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CTR);
    test_empty_vector_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CTR);
    test_invalid_size_exceptions(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CTR);
    test_exception_safety(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CTR);
}

// ── CBC IV handling (3 key sizes) ────────────────────────────────────────────

TEST(CipherCBCIVHandling, AES128) { test_cbc_mode_iv_handling(AESKEY_LENBITS::_128); }
TEST(CipherCBCIVHandling, AES192) { test_cbc_mode_iv_handling(AESKEY_LENBITS::_192); }
TEST(CipherCBCIVHandling, AES256) { test_cbc_mode_iv_handling(AESKEY_LENBITS::_256); }

// ── PKCS#7 round-trip tests (ECB/CBC × 3 key sizes) ─────────────────────────

void test_pkcs7_round_trip(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    TV::KeySize ks_;
    switch(ks) {
        case AESKEY_LENBITS::_128: ks_ = TV::KeySize::AES128; break;
        case AESKEY_LENBITS::_192: ks_ = TV::KeySize::AES192; break;
        case AESKEY_LENBITS::_256: ks_ = TV::KeySize::AES256; break;
        default: GTEST_FAIL() << "Unknown key size"; return;
    }

    TV::CipherMode cm_;
    switch(cm) {
        case AESCIPHER_OPTMODE::ECB: cm_ = TV::CipherMode::ECB; break;
        case AESCIPHER_OPTMODE::CBC: cm_ = TV::CipherMode::CBC; break;
        default: GTEST_FAIL() << "Unsupported mode for PKCS#7 round-trip"; return;
    }

    std::unique_ptr<SP::ModeTestVectorBase> example = SP::create(ks_, cm_);
    ASSERT_NE(example, nullptr);

    AESKEY key(example->getKey(), ks);
    AESCIPHER ciph(key, AESCIPHER::OperationMode(cm));
    if (cm == AESCIPHER_OPTMODE::CBC)
        ciph.setInitialVectorForTesting(
            std::vector<uint8_t>(SP::kInitializationVector, SP::kInitializationVector + 16));

    for (size_t len : {1u, 15u, 17u, 31u}) {
        std::vector<uint8_t> plaintext(len);
        for (size_t i = 0; i < len; ++i) plaintext[i] = static_cast<uint8_t>(i & 0xFF);

        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> recovered;

        ASSERT_NO_THROW(ciph.encryption(plaintext, ciphertext)) << "len=" << len;
        EXPECT_EQ(ciphertext.size() % 16, 0u) << "ciphertext not block-aligned, len=" << len;
        EXPECT_GT(ciphertext.size(), plaintext.size()) << "len=" << len;

        ASSERT_NO_THROW(ciph.decryption(ciphertext, recovered)) << "len=" << len;
        EXPECT_EQ(recovered, plaintext) << "round-trip failed for len=" << len;
    }
}

TEST(Cipher_PKCS7, AES128_ECB) { test_pkcs7_round_trip(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::ECB); }
TEST(Cipher_PKCS7, AES128_CBC) { test_pkcs7_round_trip(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CBC); }
TEST(Cipher_PKCS7, AES192_ECB) { test_pkcs7_round_trip(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::ECB); }
TEST(Cipher_PKCS7, AES192_CBC) { test_pkcs7_round_trip(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CBC); }
TEST(Cipher_PKCS7, AES256_ECB) { test_pkcs7_round_trip(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::ECB); }
TEST(Cipher_PKCS7, AES256_CBC) { test_pkcs7_round_trip(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CBC); }

// ── PaddingMode::None — rejects unaligned, accepts aligned ───────────────────

void test_padding_mode_none(AESKEY_LENBITS ks, AESCIPHER_OPTMODE cm) {
    AESKEY key(ks);
    AESCIPHER ciph(key, AESCIPHER::OperationMode(cm), AESCIPHER::PaddingMode::None);
    if (cm == AESCIPHER_OPTMODE::CBC)
        ciph.setInitialVectorForTesting(std::vector<uint8_t>(16, 0x00));

    // Non-aligned input must throw
    std::vector<uint8_t> unaligned(15);
    std::vector<uint8_t> out;
    EXPECT_THROW(ciph.encryption(unaligned, out), std::invalid_argument);
    EXPECT_THROW(ciph.decryption(unaligned, out), std::invalid_argument);

    // Aligned input must succeed and produce same-size output
    std::vector<uint8_t> aligned(32, 0xAB);
    ASSERT_NO_THROW(ciph.encryption(aligned, out));
    EXPECT_EQ(out.size(), aligned.size());

    std::vector<uint8_t> recovered;
    ASSERT_NO_THROW(ciph.decryption(out, recovered));
    EXPECT_EQ(recovered, aligned);
}

TEST(Cipher_PaddingNone, AES128_ECB) { test_padding_mode_none(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::ECB); }
TEST(Cipher_PaddingNone, AES128_CBC) { test_padding_mode_none(AESKEY_LENBITS::_128, AESCIPHER_OPTMODE::CBC); }
TEST(Cipher_PaddingNone, AES192_ECB) { test_padding_mode_none(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::ECB); }
TEST(Cipher_PaddingNone, AES192_CBC) { test_padding_mode_none(AESKEY_LENBITS::_192, AESCIPHER_OPTMODE::CBC); }
TEST(Cipher_PaddingNone, AES256_ECB) { test_padding_mode_none(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::ECB); }
TEST(Cipher_PaddingNone, AES256_CBC) { test_padding_mode_none(AESKEY_LENBITS::_256, AESCIPHER_OPTMODE::CBC); }
