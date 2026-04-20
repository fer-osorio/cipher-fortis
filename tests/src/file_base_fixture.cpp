#include "../include/file_base_fixture.hpp"

void FileBaseFixture::SetUp() {
    this->validFilePath   = factory_.make_valid(env_.path());
    this->nonexistentPath = env_.path() / "does_not_exist.bin";
}

void FileBaseFixture::TearDown() {}
