#ifndef FILE_BASE_FIXTURE_HPP
#define FILE_BASE_FIXTURE_HPP

#include <gtest/gtest.h>
#include <filesystem>
#include <cstdint>
#include "test_environment.hpp"

namespace fs = std::filesystem;

// Number of bytes written by the fixture's binary test asset.
static constexpr size_t FILE_BASE_FIXTURE_FILE_SIZE = 1024;

class FileBaseFixture : public ::testing::Test {
protected:
    TestEnvironment      env_{"tests/data/file_base"};
    const fs::path&      testDataDir   = env_.path();
    fs::path             validFilePath;
    fs::path             nonexistentPath;

    void SetUp() override;
    void TearDown() override;
};

#endif // FILE_BASE_FIXTURE_HPP
