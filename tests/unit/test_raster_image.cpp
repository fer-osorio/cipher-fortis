// Unit test suite for RasterImage contracts, exercised via File::PNG and File::JPEG
#include <gtest/gtest.h>
#include "../../file-handlers/include/png_image.hpp"
#include "../../file-handlers/include/jpeg_image.hpp"
#include "raster_image_fixture.hpp"
#include "../../core-crypto/include/encryptor.hpp"
#include "../../core-crypto/include/cipher.hpp"
#include <filesystem>

namespace fs = std::filesystem;

// Minimal mock: XOR every byte with 0xAB — self-inverse
class XorEncryptor : public Encryptor {
public:
    void encryption(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) const override {
        out.resize(in.size());
        for (size_t i = 0; i < in.size(); i++) out[i] = in[i] ^ 0xAB;
    }
    void decryption(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) const override {
        encryption(in, out);
    }
};

TEST_F(RasterImageFixture, LoadOperations) {
    // After load(), data holds exactly w*h*ch bytes — no alignment padding.
    // pixel_data_size_ equals data.size().
    {
        File::PNG png(validPngPath);
        png.load();
        EXPECT_EQ(static_cast<size_t>(300), png.get_pixel_data_size()) << "10x10 RGB: pixel_data_size_ == 300";
        EXPECT_EQ(static_cast<size_t>(300), png.get_size()) << "10x10 RGB: size == pixel_data_size_";
    }
    {
        File::PNG png(smallPngPath);
        png.load();
        EXPECT_EQ(static_cast<size_t>(12), png.get_pixel_data_size()) << "2x2 RGB: pixel_data_size_ == 12";
        EXPECT_EQ(static_cast<size_t>(12), png.get_size()) << "2x2 RGB: size == pixel_data_size_";
    }
    {
        File::PNG png(largePngPath);
        png.load();
        EXPECT_EQ(static_cast<size_t>(30000), png.get_pixel_data_size()) << "100x100 RGB: pixel_data_size_ == 30000";
        EXPECT_EQ(static_cast<size_t>(30000), png.get_size()) << "100x100 RGB: size == pixel_data_size_";
    }
    EXPECT_THROW({
        File::PNG png(nonexistentPath);
        png.load();
    }, std::runtime_error);
    EXPECT_THROW({
        File::PNG png(corruptPath);
        png.load();
    }, std::runtime_error);
    EXPECT_THROW({
        File::PNG png(emptyPath);
        png.load();
    }, std::runtime_error);
}

TEST_F(RasterImageFixture, SaveOperations) {
    // Save to explicit path — file exists and size matches after reload
    {
        File::PNG png(validPngPath);
        png.load();
        size_t original_size = png.get_size();

        fs::path outputPath = testDataDir / "output_save_test.png";
        png.save(outputPath);

        EXPECT_TRUE(fs::exists(outputPath)) << "Output file was created";

        File::PNG reloaded(outputPath);
        reloaded.load();
        EXPECT_EQ(original_size, reloaded.get_size())
            << "Reloaded file size matches original";

        fs::remove(outputPath);
    }

    // Save with empty path writes back to file_path
    {
        File::PNG png(validPngPath);
        png.load();
        std::vector<uint8_t> original = png.get_data();

        XorEncryptor xor_enc;
        png.apply_encryption(xor_enc);
        png.save();

        File::PNG reloaded(validPngPath);
        reloaded.load();
        EXPECT_NE(reloaded.get_data(), original)
            << "Save to original path persists the change";

        reloaded.apply_decryption(xor_enc);
        // apply_decryption resizes to pixel_data_size_ (== original.size() since
        // load() no longer pads), so the comparison covers the full original buffer.
        EXPECT_EQ(
            reloaded.get_data(),
            std::vector<uint8_t>(
                original.begin(),
                original.begin() + static_cast<std::ptrdiff_t>(reloaded.get_size())
            )
        ) << "Decryption returns original pixel data";
    }

    // Save to invalid directory throws
    EXPECT_THROW({
        File::PNG png(validPngPath);
        png.load();
        png.save("/invalid/nonexistent/directory/output.png");
    }, std::runtime_error);

    // Save without loading throws
    EXPECT_THROW({
        File::PNG png(validPngPath);
        png.save(testDataDir / "should_fail.png");
    }, std::logic_error);
}

TEST_F(RasterImageFixture, EdgeCases) {
    // Multiple loads on same object are consistent
    {
        File::PNG png(validPngPath);
        png.load();
        size_t firstLoad = png.get_size();
        png.load();
        size_t secondLoad = png.get_size();
        EXPECT_EQ(firstLoad, secondLoad) << "Multiple loads are consistent";
    }

    // Different image dimensions produce different byte counts
    {
        File::PNG small(smallPngPath);
        File::PNG large(largePngPath);
        small.load();
        large.load();
        EXPECT_TRUE(large.get_size() > small.get_size())
            << "100x100 PNG has more bytes than 2x2 PNG";
    }
}

TEST_F(RasterImageFixture, MemorySafety) {
    // Destructor after load does not crash
    {
        File::PNG png(validPngPath);
        png.load();
    }

    // Destructor without load does not crash
    {
        File::PNG png(validPngPath);
    }

    // Object remains valid after going out of scope in inner block
    {
        File::PNG outer(validPngPath);
        outer.load();
        size_t outerSize = outer.get_size();
        {
            File::PNG inner(smallPngPath);
            inner.load();
        }
        EXPECT_EQ(outerSize, outer.get_size())
            << "Outer PNG unaffected by inner scope destruction";
    }
}

TEST_F(RasterImageFixture, JpegLossyRoundTrip) {
    XorEncryptor xor_enc;

    // Encrypt → save JPEG → reload → JPEG altered the encrypted bytes
    {
        fs::path workPath = testDataDir / "jpeg_lossy_test1.jpg";
        fs::copy_file(validJpegPath, workPath, fs::copy_options::overwrite_existing);

        File::JPEG jpeg(workPath);
        jpeg.load();
        jpeg.apply_encryption(xor_enc);
        std::vector<uint8_t> encrypted = jpeg.get_data();

        jpeg.save();

        File::JPEG reloaded(workPath);
        reloaded.load();
        EXPECT_NE(reloaded.get_data(), encrypted)
            << "JPEG alters encrypted data during re-encoding (compression is lossy)";

        fs::remove(workPath);
    }

    // Encrypt → save JPEG → reload → decrypt ≠ original
    {
        fs::path workPath = testDataDir / "jpeg_lossy_test2.jpg";
        fs::copy_file(validJpegPath, workPath, fs::copy_options::overwrite_existing);

        File::JPEG jpeg(workPath);
        jpeg.load();
        std::vector<uint8_t> original = jpeg.get_data();

        jpeg.apply_encryption(xor_enc);
        jpeg.save();

        File::JPEG reloaded(workPath);
        reloaded.load();
        reloaded.apply_decryption(xor_enc);
        EXPECT_NE(reloaded.get_data(), original)
            << "decrypt(reload(encrypt(jpeg))) != original: JPEG is not a safe encrypted payload container";

        fs::remove(workPath);
    }
}

// ── Block-alignment and PKCS#7 round-trip ────────────────────────────────────

TEST_F(RasterImageFixture, BlockAlignmentAfterEncryption) {
    // After load(), data.size() == pixel_data_size_ (no padding).
    // After apply_encryption() with ECB/CBC, data.size() is a multiple of 16.
    CipherFortis::Key key(CipherFortis::Key::LengthBits::_128);
    CipherFortis::Cipher ecb(
        key,
        CipherFortis::Cipher::OperationMode(
            CipherFortis::Cipher::OperationMode::Identifier::ECB
        )
    );

    auto check = [&](
        File::RasterImage& img, size_t expected_pixels, const char* label
    ) {
        img.load();
        EXPECT_EQ(img.get_pixel_data_size(), expected_pixels)
            << label << ": pixel_data_size_ after load";
        EXPECT_EQ(img.get_size(), expected_pixels)
            << label << ": size == pixel_data_size_ after load (no padding)";

        img.apply_encryption(ecb);
        EXPECT_EQ(0u, img.get_size() % 16)
            << label << ": size is block-aligned after apply_encryption";
        EXPECT_GE(img.get_size(), expected_pixels)
            << label << ": size >= pixel_data_size_ after apply_encryption";
    };

    { File::PNG  img(validPngPath);  check(img, 300u,   "10x10 RGB PNG");   }
    { File::PNG  img(smallPngPath);  check(img, 12u,    "2x2 RGB PNG");     }
    { File::PNG  img(largePngPath);  check(img, 30000u, "100x100 RGB PNG"); }
    {
        File::JPEG img(validJpegPath);
        img.load();
        size_t pds = img.get_pixel_data_size();
        img.apply_encryption(ecb);
        EXPECT_EQ(0u, img.get_size() % 16) << "JPEG: block-aligned after apply_encryption";
        EXPECT_GE(img.get_size(), pds)     << "JPEG: size >= pixel_data_size_";
    }
}

TEST_F(RasterImageFixture, RoundTrip_ECB) {
    CipherFortis::Key key(CipherFortis::Key::LengthBits::_128);
    CipherFortis::Cipher cipher(
        key,
        CipherFortis::Cipher::OperationMode(
            CipherFortis::Cipher::OperationMode::Identifier::ECB
        ),
        CipherFortis::Cipher::PaddingMode::None
    );

    fs::path workPath = testDataDir / "ecb_roundtrip.png";
    fs::copy_file(largePngPath, workPath, fs::copy_options::overwrite_existing);

    File::PNG img(workPath);
    img.load();
    std::vector<uint8_t> original_pixels(
        img.get_data().begin(),
        img.get_data().begin() + static_cast<std::ptrdiff_t>(img.get_pixel_data_size())
    );

    img.apply_encryption(cipher);
    EXPECT_NE(img.get_data(), original_pixels) << "encrypted data should differ";
    EXPECT_EQ(0u, img.get_size() % 16)         << "encrypted buffer must be block-aligned";
    img.save(workPath);

    File::PNG reloaded(workPath);
    reloaded.load();
    reloaded.apply_decryption(cipher);
    EXPECT_EQ(reloaded.get_data(), original_pixels) << "ECB round-trip must recover original pixels";

    fs::remove(workPath);
}

TEST_F(RasterImageFixture, RoundTrip_GapNonZero_ECB) {
    // validPngPath is 10×10 RGB = 300 bytes (gap = 4)
    CipherFortis::Key key(CipherFortis::Key::LengthBits::_128);
    CipherFortis::Cipher cipher(
        key,
        CipherFortis::Cipher::OperationMode(
            CipherFortis::Cipher::OperationMode::Identifier::ECB
        ),
        CipherFortis::Cipher::PaddingMode::None
    );

    fs::path workPath = testDataDir / "gap_ecb_roundtrip.png";
    fs::copy_file(validPngPath, workPath, fs::copy_options::overwrite_existing);

    File::PNG img(workPath);
    img.load();
    ASSERT_EQ(img.get_pixel_data_size(), 300u);
    ASSERT_EQ(img.get_size(), 300u) << "load() stores exact pixel count, no padding";

    std::vector<uint8_t> original_pixels(
        img.get_data().begin(),
        img.get_data().begin() + static_cast<std::ptrdiff_t>(img.get_pixel_data_size())
    );

    img.apply_encryption(cipher);
    ASSERT_EQ(img.get_size(), 304u) << "zero-padded to 304 by apply_encryption";
    size_t pds = img.get_pixel_data_size();
    size_t gap = img.get_size() - pds;
    ASSERT_EQ(gap, 4u);
    std::vector<uint8_t> tail(
        img.get_data().end() - static_cast<std::ptrdiff_t>(gap),
        img.get_data().end()
    );

    img.save(workPath);   // tail bytes are dropped by stbi_write

    File::PNG reloaded(workPath);
    reloaded.load();
    EXPECT_EQ(reloaded.get_size(), 300u) << "loaded encrypted file has no tail";

    reloaded.append_data(tail);  // restore the dropped tail
    EXPECT_EQ(reloaded.get_size(), 304u) << "after tail restore, size matches ciphertext";

    reloaded.apply_decryption(cipher);
    EXPECT_EQ(reloaded.get_data(), original_pixels)
        << "gap>0 ECB round-trip must recover original pixels";

    fs::remove(workPath);
}

TEST_F(RasterImageFixture, RoundTrip_CBC) {
    CipherFortis::Key key(CipherFortis::Key::LengthBits::_128);
    CipherFortis::Cipher cipher(
        key,
        CipherFortis::Cipher::OperationMode(
            CipherFortis::Cipher::OperationMode::Identifier::CBC
        ),
        CipherFortis::Cipher::PaddingMode::None
    );
    cipher.setInitialVectorForTesting(std::vector<uint8_t>(16, 0x5A));

    fs::path workPath = testDataDir / "cbc_roundtrip.png";
    fs::copy_file(largePngPath, workPath, fs::copy_options::overwrite_existing);

    File::PNG img(workPath);
    img.load();
    std::vector<uint8_t> original_pixels(
        img.get_data().begin(),
        img.get_data().begin() + static_cast<std::ptrdiff_t>(img.get_pixel_data_size())
    );

    img.apply_encryption(cipher);
    EXPECT_NE(img.get_data(), original_pixels) << "encrypted data should differ";
    img.save(workPath);

    File::PNG reloaded(workPath);
    reloaded.load();
    reloaded.apply_decryption(cipher);
    EXPECT_EQ(reloaded.get_data(), original_pixels) << "CBC round-trip must recover original pixels";

    fs::remove(workPath);
}
