#include <filesystem>
#include <functional>
#include <string>
#include <vector>
#include "asset_factory.hpp"
#include "test_environment.hpp"

namespace CommandLineToolsTest{

namespace SystemUtils {
    // Helper function to execute command line tool
    int execute_cli_command(const std::string& command);

    // Helper to create text files
    void create_text_file(const std::string& filepath, const std::string& content);

    // Helper to create binary files
    void create_binary_file(
        const std::string& filepath, const std::vector<uint8_t>& content
    );

    // Helper to create binary files
    void create_binary_file(
        const std::string& filepath,
        std::function<uint8_t(size_t)> generator,
        size_t file_size
    );

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

    // SYSTEM TEST 4: JPEG encryption saves output as PNG
    bool test_jpeg_encryption_saves_as_png();

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

} // namespace CommandLineToolsTest
