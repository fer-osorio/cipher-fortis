// System/E2E Testing Examples for AES File Encryption Tool
// File: system/test_file_encryption_workflows.cpp

#include "../include/raster_image_fixture.hpp"  // pulls in <gtest/gtest.h>
#include <gtest/gtest.h>
#include "../include/system_workflows.hpp"
#include "../include/file_write_utils.hpp"
#include "../../file-handlers/include/bitmap.hpp"
#include "../../file-handlers/include/png_image.hpp"
#include "../../file-handlers/include/jpeg_image.hpp"
#include "../../core-crypto/include/key.hpp"
#include <filesystem>
#include <cstdlib>
#include <string>

using namespace CommandLineToolsTest;

// Helper function to execute command line tool
int SystemUtils::execute_cli_command(const std::string& command) {
    return std::system(command.c_str());
}

// Helper to read file content
std::vector<uint8_t> SystemUtils::read_file(
    const std::string& filepath, bool isBinary
) {
    return TestUtils::IO::read_file(fs::path(filepath), isBinary);
}

void SystemTests::setupTestEnvironment() {
    this->originalValidPath          = factory_.make_valid(env_.path());
    this->originalLargePath          = factory_.make_large(env_.path());
    this->nonexistentPath            = env_.path() / (
        "does_not_exist." + factory_.extension()
    );
    this->encryptedOriginalValidPath = env_.path() / (
        "encrypted_original_valid." + factory_.extension()
    );
    this->decryptedOriginalValidPath = env_.path() / (
        "decrypted_original_valid." + factory_.extension()
    );
    this->encryptedOriginalLargePath = env_.path() / (
        "encrypted_original_large." + factory_.extension()
    );
    this->decryptedOriginalLargePath = env_.path() / (
        "decrypted_original_large." + factory_.extension()
    );
    this->keyPath = env_.path() / "key.bin";
}

SystemTests::SystemTests(
    const std::string& executable_path_, const AssetFactory& factory
) : executable_path(executable_path_), factory_(factory), env_("test_data") {
    this->setupTestEnvironment();
}

SystemTests::~SystemTests() {}

// SYSTEM TEST 1: Complete Text File Encryption Workflow
bool SystemTests::test_file_encryption_workflow() {
    bool success = true;

    // Step 2: Generate encryption key
    std::string gen_key_cmd =
        this->executable_path + " --generate-key --key-length 256 --output " +
        this->keyPath.string();
    int result1 = SystemUtils::execute_cli_command(
        gen_key_cmd
    );
    EXPECT_EQ(0, result1) << "Key generation should succeed";
    success &= (result1 == 0);

    bool keyCreated = std::filesystem::exists(this->keyPath);
    EXPECT_TRUE(keyCreated) << "Key file should be created";
    success &= keyCreated;

    // Step 3: Encrypt the file
    std::string encrypt_cmd =
        this->executable_path + " --mode CBC --key " +
        this->keyPath.string() + " --input " + this->originalValidPath.string()
        + " --output " + this->encryptedOriginalValidPath.string()
        + " --iv 00112233445566778899AABBCCDDEEFF";
    int result2 = SystemUtils::execute_cli_command(
        encrypt_cmd
    );

    EXPECT_EQ(0, result2) << "File encryption should succeed";
    success &= (result2 == 0);

    bool encryptedCreated = std::filesystem::exists(this->encryptedOriginalValidPath);
    EXPECT_TRUE(encryptedCreated) << "Encrypted file should be created";
    success &= encryptedCreated;

    // Step 4: Verify encrypted file is different from original
    std::vector<uint8_t> test_content = SystemUtils::read_file(
        this->originalValidPath, factory_.is_binary()
    );
    std::vector<uint8_t> encrypted_content = SystemUtils::read_file(
        this->encryptedOriginalValidPath, factory_.is_binary()
    );

    bool contentDiffers = (encrypted_content != test_content);
    EXPECT_TRUE(contentDiffers) << "Encrypted content should differ from original";
    success &= contentDiffers;

    // Step 5: Decrypt the file
    std::string decrypt_cmd =
        this->executable_path + " --decrypt --mode CBC --key " + this->keyPath.string() +
        " --input " + this->encryptedOriginalValidPath.string() +
        " --output " + this->decryptedOriginalValidPath.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";
    int result3 = SystemUtils::execute_cli_command(
        decrypt_cmd
    );

    EXPECT_EQ(0, result3) << "File decryption should succeed";
    success &= (result3 == 0);

    bool decryptedCreated = std::filesystem::exists(this->decryptedOriginalValidPath);
    EXPECT_TRUE(decryptedCreated) << "Decrypted file should be created";
    success &= decryptedCreated;

    // Step 6: Verify decrypted content matches original
    std::vector<uint8_t> decrypted_content = SystemUtils::read_file(
        this->decryptedOriginalValidPath, factory_.is_binary()
    );

    bool contentMatches = (decrypted_content == test_content);
    EXPECT_TRUE(contentMatches) << "Decrypted content should match original";
    success &= contentMatches;

    if (!contentMatches) {
        std::cout << "Original size: " << test_content.size() << std::endl;
        std::cout << "Decrypted size: " << decrypted_content.size() << std::endl;

        if (test_content.size() == decrypted_content.size()) {
            for (size_t i = 0; i < test_content.size(); i++) {
                if (test_content[i] != decrypted_content[i]) {
                    std::cout << "First mismatch at byte " <<
                        i << std::endl;
                    std::cout << "Original: " << std::hex <<
                        static_cast<int>(test_content[i]) << std::endl;
                    std::cout << "Decrypted: " << std::hex<<
                        static_cast<int>(decrypted_content[i]) << std::endl;
                    break;
                }
            }
        }
    }

    return success;
}

// SYSTEM TEST 2: Error Handling and Edge Cases
bool SystemTests::test_error_scenarios() {
    bool success = true;

    const fs::path second_key = this->env_.path() / "second_key.bin";

    // Generate two different keys
    SystemUtils::execute_cli_command(
        this->executable_path + " --generate-key --output " +
        this->keyPath.string()
    );
    SystemUtils::execute_cli_command(
        this->executable_path + " --generate-key --output " +
        second_key.string()
    );

    // Encrypt with key1
    std::string encrypt_cmd =
        this->executable_path + " --key " + this->keyPath.string() +
        " --input " + this->originalValidPath.string() +
        " --output " + this->encryptedOriginalValidPath.string();
    bool encryptSucceeded = (SystemUtils::execute_cli_command(encrypt_cmd) == 0);
    EXPECT_TRUE(encryptSucceeded) << "Encryption should succeed";
    success &= encryptSucceeded;

    // Try to decrypt with second_key (should fail or produce garbage)
    std::string decrypt_cmd = this->executable_path + " --decrypt --key "
        + second_key.string() + " --input " +
        this->encryptedOriginalValidPath.string() +
        " --output " + this->decryptedOriginalValidPath.string();
    int decrypt_result = SystemUtils::execute_cli_command(
        decrypt_cmd
    );
    // Either command should fail, or decrypted content should be garbage
    if (decrypt_result == 0 && std::filesystem::exists(this->decryptedOriginalValidPath)) {
        std::vector<uint8_t> original_content = SystemUtils::read_file(
            this->originalValidPath.string(), factory_.is_binary()
        );
        std::vector<uint8_t> decrypted_content = SystemUtils::read_file(
            this->decryptedOriginalValidPath.string(), factory_.is_binary()
        );
        bool wrongKeyProducesGarbage = (decrypted_content != original_content);
        EXPECT_TRUE(wrongKeyProducesGarbage) << "Wrong key should not produce correct plaintext";
        success &= wrongKeyProducesGarbage;
    } else {
        bool wrongKeyFails = (decrypt_result != 0);
        EXPECT_TRUE(wrongKeyFails) << "Decryption with wrong key should fail";
        success &= wrongKeyFails;
    }

    // Test 2: Non-existent file
    int nonexistent_result = SystemUtils::execute_cli_command(
        this->executable_path + " --input " +
        this->nonexistentPath.string() + " --output nonexistent_out.bin"
    );
    bool nonexistentFails = (nonexistent_result != 0);
    EXPECT_TRUE(nonexistentFails) << "Encrypting non-existent file should fail";
    success &= nonexistentFails;

    // Test 3: Invalid key file
    int invalid_key_result = SystemUtils::execute_cli_command(
        this->executable_path + " --key invalid.key --input " +
        this->originalValidPath.string() + " --output out.aes"
    );
    bool invalidKeyFails = (invalid_key_result != 0);
    EXPECT_TRUE(invalidKeyFails) << "Using invalid key file should fail";
    success &= invalidKeyFails;

    return success;
}

// SYSTEM TEST 4: JPEG encryption saves output as PNG
bool SystemTests::test_jpeg_encryption_saves_as_png() {
    bool success = true;

    // Generate key
    std::string gen_key_cmd =
        this->executable_path + " --generate-key --output " +
        this->keyPath.string();
    SystemUtils::execute_cli_command(gen_key_cmd);

    // Create a JPEG input
    const fs::path jpegInput  = this->env_.path() / "jpeg_input.jpg";
    const fs::path encJpg     = this->env_.path() / "enc.jpg";
    const fs::path encPng     = this->env_.path() / "enc.png";
    const fs::path decJpg     = this->env_.path() / "dec.jpg";

    RasterImageFixture::createValidJpeg(jpegInput, 32, 32);

    // Encrypt — tool should redirect output to enc.png
    std::string encrypt_cmd =
        this->executable_path + " --key " + this->keyPath.string() +
        " --input " + jpegInput.string() +
        " --output " + encJpg.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";
    int enc_result = SystemUtils::execute_cli_command(encrypt_cmd);
    EXPECT_EQ(0, enc_result) << "JPEG encryption should succeed";
    success &= (enc_result == 0);

    bool pngCreated = fs::exists(encPng);
    EXPECT_TRUE(pngCreated) << "Encrypted output should be saved as .png";
    success &= pngCreated;

    bool jpgNotCreated = !fs::exists(encJpg);
    EXPECT_TRUE(jpgNotCreated) << "No .jpg output should be created";
    success &= jpgNotCreated;

    // Decrypt the PNG back to JPEG
    std::string decrypt_cmd =
        this->executable_path + " --decrypt --key " + this->keyPath.string() +
        " --input " + encPng.string() +
        " --output " + decJpg.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";
    int dec_result = SystemUtils::execute_cli_command(decrypt_cmd);
    EXPECT_EQ(0, dec_result) << "Decryption of PNG to JPEG should succeed";
    success &= (dec_result == 0);

    bool decCreated = fs::exists(decJpg);
    EXPECT_TRUE(decCreated) << "Decrypted JPEG should be created";
    success &= decCreated;

    return success;
}

// SYSTEM TEST 5: Metadata round-trip
bool SystemTests::test_metadata_round_trip() {
    bool success = true;

    const fs::path metaPath      = this->env_.path() / "meta.json";
    const fs::path encryptedPath = env_.path() / (
        "meta_enc." + factory_.extension()
    );
    const fs::path decryptedPath = env_.path() / (
        "meta_dec." + factory_.extension()
    );

    // Generate key
    std::string gen_key_cmd =
        this->executable_path + " --generate-key --output " + this->keyPath.string();
    SystemUtils::execute_cli_command(gen_key_cmd);

    // Encrypt with --metadata (no --iv; random IV generated and saved to JSON)
    std::string encrypt_cmd =
        this->executable_path + " --key " + this->keyPath.string() +
        " --input " + this->originalValidPath.string() +
        " --output " + encryptedPath.string() +
        " --metadata " + metaPath.string();
    int enc_result = SystemUtils::execute_cli_command(encrypt_cmd);
    EXPECT_EQ(0, enc_result) << "Metadata encrypt should succeed";
    success &= (enc_result == 0);

    bool metaCreated = fs::exists(metaPath);
    EXPECT_TRUE(metaCreated) << "Metadata JSON file should be created";
    success &= metaCreated;

    bool encCreated = fs::exists(encryptedPath);
    EXPECT_TRUE(encCreated) << "Encrypted file should be created";
    success &= encCreated;

    // Decrypt with --metadata (no --iv; IV and mode loaded from JSON)
    std::string decrypt_cmd =
        this->executable_path + " --decrypt --key " + this->keyPath.string() +
        " --input " + encryptedPath.string() +
        " --output " + decryptedPath.string() +
        " --metadata " + metaPath.string();
    int dec_result = SystemUtils::execute_cli_command(decrypt_cmd);
    EXPECT_EQ(0, dec_result) << "Metadata decrypt should succeed";
    success &= (dec_result == 0);

    bool decCreated = fs::exists(decryptedPath);
    EXPECT_TRUE(decCreated) << "Decrypted file should be created";
    success &= decCreated;

    if (decCreated) {
        std::vector<uint8_t> original  = SystemUtils::read_file(
            this->originalValidPath, true
        );
        std::vector<uint8_t> decrypted = SystemUtils::read_file(decryptedPath, true);
        bool contentMatches = (original == decrypted);
        EXPECT_TRUE(contentMatches) << "Decrypted content should match original";
        success &= contentMatches;
    }

    return success;
}

// SYSTEM TEST 6: File validity after encrypt/decrypt
bool SystemTests::test_file_validity() {
    bool success = true;

    // Generate key
    SystemUtils::execute_cli_command(
        this->executable_path + " --generate-key --output " + this->keyPath.string()
    );

    const std::string iv = " --iv 00112233445566778899AABBCCDDEEFF";

    // ── BMP ──────────────────────────────────────────────────────────────────
    {
        const fs::path enc = env_.path() / "validity_enc.bmp";
        const fs::path dec = env_.path() / "validity_dec.bmp";

        SystemUtils::execute_cli_command(
            this->executable_path + " --key " + keyPath.string() +
            " --input "  + originalValidPath.string() +
            " --output " + enc.string() + iv
        );
        SystemUtils::execute_cli_command(
            this->executable_path + " --decrypt --key " + keyPath.string() +
            " --input "  + enc.string() +
            " --output " + dec.string() + iv
        );

        File::Bitmap ref(originalValidPath);
        ref.load();

        bool encValid = ref.verify_saved_file(enc);
        EXPECT_TRUE(encValid)
            << "BMP: encrypted file must be a valid loadable image";
        success &= encValid;

        bool decValid = ref.verify_saved_file(dec);
        EXPECT_TRUE(decValid)
            << "BMP: decrypted file must be a valid loadable image";
        success &= decValid;
    }

    // ── PNG ───────────────────────────────────────────────────────────────────
    {
        const fs::path pngOrig = env_.path() / "validity_orig.png";
        const fs::path enc     = env_.path() / "validity_enc.png";
        const fs::path dec     = env_.path() / "validity_dec.png";
        RasterImageFixture::createValidPng(pngOrig, 32, 32);

        SystemUtils::execute_cli_command(
            this->executable_path + " --key " + keyPath.string() +
            " --input "  + pngOrig.string() +
            " --output " + enc.string() + iv
        );
        SystemUtils::execute_cli_command(
            this->executable_path + " --decrypt --key " + keyPath.string() +
            " --input "  + enc.string() +
            " --output " + dec.string() + iv
        );

        File::PNG ref(pngOrig);
        ref.load();

        bool encValid = ref.verify_saved_file(enc);
        EXPECT_TRUE(encValid)
            << "PNG: encrypted file must be a valid loadable image";
        success &= encValid;

        bool decValid = ref.verify_saved_file(dec);
        EXPECT_TRUE(decValid)
            << "PNG: decrypted file must be a valid loadable image";
        success &= decValid;
    }

    // ── JPEG (saved as PNG on encrypt) ────────────────────────────────────────
    {
        const fs::path jpegOrig = env_.path() / "validity_orig.jpg";
        const fs::path encPng   = env_.path() / "validity_enc_jpeg.png";
        const fs::path dec      = env_.path() / "validity_dec_jpeg.jpg";
        RasterImageFixture::createValidJpeg(jpegOrig, 32, 32);

        SystemUtils::execute_cli_command(
            this->executable_path + " --key " + keyPath.string() +
            " --input "  + jpegOrig.string() +
            " --output " + encPng.string().substr(
                0, encPng.string().size() - 4
            ) + ".jpg" + iv
        );
        SystemUtils::execute_cli_command(
            this->executable_path + " --decrypt --key " + keyPath.string() +
            " --input "  + encPng.string() +
            " --output " + dec.string() + iv
        );

        File::JPEG ref(jpegOrig);
        ref.load();

        bool encValid = ref.verify_saved_file(encPng);
        EXPECT_TRUE(encValid)
            << "JPEG->PNG: encrypted file must be a valid loadable image";
        success &= encValid;

        bool decValid = ref.verify_saved_file(dec);
        EXPECT_TRUE(decValid)
            << "JPEG decrypted file must be a valid loadable image";
        success &= decValid;
    }

    return success;
}

// SYSTEM TEST 3: Performance and Large File Handling
bool SystemTests::test_large_file_performance() {
    bool success = true;

    // Generate key
    SystemUtils::execute_cli_command(
        this->executable_path + " --generate-key --output " + this->keyPath.string()
    );

    std::string encrypt_cmd =
        this->executable_path + " --mode CBC --key " + this->keyPath.string() +
        " --input " + this->originalLargePath.string() +
        " --output " + this->encryptedOriginalLargePath.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";

    // Time the encryption
    auto start_time = std::chrono::high_resolution_clock::now();
    int encrypt_result = SystemUtils::execute_cli_command(
        encrypt_cmd
    );
    auto encrypt_end = std::chrono::high_resolution_clock::now();
    auto encrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        encrypt_end - start_time
    );

    bool encryptSucceeded = (encrypt_result == 0);
    EXPECT_TRUE(encryptSucceeded) << "Large file encryption should succeed";
    success &= encryptSucceeded;

    if (encryptSucceeded) {
        bool encryptFast = (encrypt_duration.count() < 10000);
        EXPECT_TRUE(encryptFast)
            << "48MB encryption should complete within 10 seconds (lasted "
            << encrypt_duration.count() << " milliseconds)";
        success &= encryptFast;
    }

    std::string decrypt_cmd =
        this->executable_path +
        " --decrypt --mode CBC --key " + this->keyPath.string() +
        " --input " + this->encryptedOriginalLargePath.string() +
        " --output " + this->decryptedOriginalLargePath.string() +
        " --iv 00112233445566778899AABBCCDDEEFF";

    // Time the decryption
    auto decrypt_start = std::chrono::high_resolution_clock::now();
    int decrypt_result = SystemUtils::execute_cli_command(
        decrypt_cmd
    );
    auto decrypt_end = std::chrono::high_resolution_clock::now();
    auto decrypt_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        decrypt_end - decrypt_start
    );

    bool decryptSucceeded = (decrypt_result == 0);
    EXPECT_TRUE(decryptSucceeded) << "Large file decryption should succeed";
    success &= decryptSucceeded;

    if (decryptSucceeded) {
        bool decryptFast = (decrypt_duration.count() < 10000);
        EXPECT_TRUE(decryptFast)
            << "48MB decryption should complete within 10 seconds (lasted "
            << decrypt_duration.count() << " milliseconds)";
        success &= decryptFast;
    }

    // Verify integrity
    auto original_size  = std::filesystem::file_size(this->originalLargePath);
    auto decrypted_size = std::filesystem::file_size(this->decryptedOriginalLargePath);

    bool sizeMatches = (original_size == decrypted_size);
    EXPECT_TRUE(sizeMatches) << "Large file should maintain size after roundtrip";
    success &= sizeMatches;

    return success;
}
