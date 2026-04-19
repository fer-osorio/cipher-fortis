#include "../include/file_base_fixture.hpp"
#include "../include/file_write_utils.hpp"

void FileBaseFixture::SetUp() {
    this->validFilePath   = env_.path() / "valid_64bytes.bin";
    this->nonexistentPath = env_.path() / "does_not_exist.bin";
    TestUtils::IO::write_binary_file(this->validFilePath, FILE_BASE_FIXTURE_FILE_SIZE);
}

void FileBaseFixture::TearDown() {}
