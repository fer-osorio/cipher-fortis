#pragma once
#include "asset_factory.hpp"

class BitmapAssetFactory : public AssetFactory {
public:
    fs::path    make_valid(const fs::path& dir) const override; // 32x32 BMP
    fs::path    make_large(const fs::path& dir) const override; // 4096x4096 BMP
    std::string extension()                     const override; // "bmp"
};
