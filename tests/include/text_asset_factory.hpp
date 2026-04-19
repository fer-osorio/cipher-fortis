#pragma once
#include "asset_factory.hpp"

class TextAssetFactory : public AssetFactory {
public:
    fs::path    make_valid(const fs::path& dir) const override; // Erwin speech
    fs::path    make_large(const fs::path& dir) const override; // 3 MB of 'z'
    std::string extension()                     const override; // "txt"
};
