#pragma once
#include <filesystem>

namespace fs = std::filesystem;

class TestEnvironment {
public:
    explicit TestEnvironment(const fs::path& base_dir);
    ~TestEnvironment();

    const fs::path& path() const;

    TestEnvironment(const TestEnvironment&)            = delete;
    TestEnvironment& operator=(const TestEnvironment&) = delete;
    TestEnvironment(TestEnvironment&&)                 = delete;
    TestEnvironment& operator=(TestEnvironment&&)      = delete;

private:
    fs::path base_dir_;
};
