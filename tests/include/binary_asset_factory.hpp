#pragma once
#include "asset_factory.hpp"

class BinaryAssetFactory : public AssetFactory {
public:
    fs::path    make_valid(const fs::path& dir) const override; // 1 KB, i % 256
    fs::path    make_large(const fs::path& dir) const override; // 3 MB, i % 256
    std::string extension()                     const override; // "bin"
};
