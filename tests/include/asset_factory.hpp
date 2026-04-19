#pragma once
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

class AssetFactory {
public:
    virtual ~AssetFactory() = default;

    virtual fs::path    make_valid(const fs::path& dir) const = 0;
    virtual fs::path    make_large(const fs::path& dir) const = 0;
    virtual std::string extension()                     const = 0;

    // Non-virtual: format-independent implementations.
    fs::path make_corrupt(const fs::path& dir) const;
    fs::path make_empty  (const fs::path& dir) const;
};
