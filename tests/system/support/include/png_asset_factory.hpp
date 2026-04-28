#pragma once
#include "asset_factory.hpp"

class PngAssetFactory : public AssetFactory {
public:
    fs::path    make_valid(const fs::path& dir) const override; // 32x32 PNG
    fs::path    make_large(const fs::path& dir) const override; // 4096x4096 PNG
    std::string extension ()                    const override; // "png"

    bool verify_roundtrip(
        const fs::path& original,
        const fs::path& roundtripped
    ) const override;
};
