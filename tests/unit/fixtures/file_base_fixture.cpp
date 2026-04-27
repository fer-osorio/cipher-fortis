#include "file_base_fixture.hpp"
#include "file_write_utils.hpp"

void FileBaseFixture::SetUp() {
    this->validFilePath   = env_.path() / "valid.bin";
    TestUtils::IO::write_binary_file(
        this->validFilePath, FILE_BASE_FIXTURE_FILE_SIZE
    );
    this->nonexistentPath = env_.path() / "does_not_exist.bin";
}

void FileBaseFixture::TearDown() {}
