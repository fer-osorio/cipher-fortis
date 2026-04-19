#include "../include/file_base_fixture.hpp"
#include "../include/file_write_utils.hpp"

void FileBaseFixture::SetUp()    { setupTestEnvironment(); }
void FileBaseFixture::TearDown() { cleanupTestEnvironment(); }

void FileBaseFixture::setupTestEnvironment() {
    fs::create_directories(testDataDir);
    createBinaryFile(validFilePath, FILE_BASE_FIXTURE_FILE_SIZE);
}

void FileBaseFixture::cleanupTestEnvironment() {
    if (fs::exists(testDataDir)) {
        for (auto& entry : fs::directory_iterator(testDataDir)) {
            if (entry.path().filename() != ".gitkeep")
                fs::remove_all(entry.path());
        }
    }
}

void FileBaseFixture::createBinaryFile(const fs::path& path, size_t size) {
    TestUtils::IO::write_binary_file(path, size);
}
