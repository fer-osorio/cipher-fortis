#pragma once
#include <filesystem>
#include <functional>
#include <string>
#include <vector>
#include <cstdint>

namespace fs = std::filesystem;

namespace TestUtils::IO {

    // Write exactly `size` bytes with value i % 256.
    void write_binary_file(const fs::path& path, size_t size);

    // Write bytes produced by a generator function.
    void write_binary_file(
        const fs::path& path,
        std::function<uint8_t(size_t)> gen,
        size_t size
    );

    // Write a UTF-8 text file.
    void write_text_file(const fs::path& path, const std::string& content);

    // Read a file into a byte vector.
    std::vector<uint8_t> read_file(const fs::path& path, bool binary = true);

}
