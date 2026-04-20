#include "../include/file_write_utils.hpp"
#include <fstream>
#include <stdexcept>

namespace TestUtils::IO {

void write_binary_file(const fs::path& path, size_t size) {
    write_binary_file(
        path,
        [](size_t i) noexcept -> uint8_t { return static_cast<uint8_t>(i & 0xFF); },
        size
    );
}

void write_binary_file(
    const fs::path& path,
    std::function<uint8_t(size_t)> gen,
    size_t size
) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to create file: " + path.string());
    }
    std::vector<uint8_t> content(size);
    for (size_t i = 0; i < size; i++) content[i] = gen(i);
    if (!file.write(reinterpret_cast<const char*>(content.data()), content.size())) {
        throw std::runtime_error("Failed to write file: " + path.string());
    }
}

void write_text_file(const fs::path& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) {
        throw std::runtime_error("Failed to create file: " + path.string());
    }
    file << content;
    if (!file) {
        throw std::runtime_error("Failed to write file: " + path.string());
    }
}

std::vector<uint8_t> read_file(const fs::path& path, bool binary) {
    std::ifstream file;
    if (binary) file.open(path, std::ios::binary);
    else        file.open(path);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }
    size_t size = fs::file_size(path);
    std::vector<uint8_t> content(size);
    if (!file.read(reinterpret_cast<char*>(content.data()), size)) {
        throw std::runtime_error("Failed to read file: " + path.string());
    }
    return content;
}

}
