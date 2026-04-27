#include <filesystem>
#include <string>
#include <vector>
#include "asset_factory.hpp"
#include "test_environment.hpp"

namespace CommandLineToolsTest{

namespace SystemUtils {
    // Helper function to execute command line tool
    int execute_cli_command(const std::string& command);

    // Helper to read file content
    std::vector<uint8_t> read_file(const std::string& filepath, bool isBinary);
} // namespace SystemUtils

namespace fs = std::filesystem;

class SystemTests {
public:
    SystemTests(const std::string& executable_path_, const AssetFactory& factory);
    ~SystemTests();

    // SYSTEM TEST 1: Complete Text File Encryption Workflow
    bool test_file_encryption_workflow();

    // SYSTEM TEST 2: Error Handling and Edge Cases
    bool test_error_scenarios();

    // SYSTEM TEST 3: Performance and Large File Handling
    bool test_large_file_performance();

    // SYSTEM TEST 5: Metadata round-trip (encrypt with --metadata, decrypt with --metadata)
    bool test_metadata_round_trip();

    // SYSTEM TEST 6: Encrypted and decrypted files are valid loadable images
    bool test_file_validity();

private:
    const std::string   executable_path;
    const AssetFactory& factory_;
    TestEnvironment     env_;

    fs::path originalValidPath;
    fs::path originalLargePath;
    fs::path nonexistentPath;
    fs::path encryptedOriginalValidPath;
    fs::path decryptedOriginalValidPath;
    fs::path encryptedOriginalLargePath;
    fs::path decryptedOriginalLargePath;
    fs::path keyPath;

    void setupTestEnvironment();
}; // class SystemTests

/**
 * @brief Verifies that the CLI redirects JPEG encryption output to PNG.
 *
 * This scenario is specific to JPEG and is not part of the generic
 * SystemTests workflow suite. It is a standalone test of the CLI's
 * lossy-format redirect behaviour.
 *
 * @param executable_path  Path to the image_encryptor binary under test.
 * @param working_dir      Writable directory for temporary test assets.
 *                         The caller is responsible for its lifecycle.
 */
bool test_jpeg_saves_as_png(
    const std::string& executable_path,
    const fs::path&    working_dir
);

} // namespace CommandLineToolsTest
