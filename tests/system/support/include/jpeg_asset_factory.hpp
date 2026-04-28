#pragma once
#include "asset_factory.hpp"

class JpegAssetFactory : public AssetFactory {
public:
    fs::path    make_valid(const fs::path& dir) const override; // 32x32 JPEG
    fs::path    make_large(const fs::path& dir) const override; // 4096x4096 JPEG
    std::string extension ()                    const override; // "jpg"
    // For JPEG it returns "png" because the CLI redirects lossy input to a
    // lossless container before encrypting.
    std::string encrypted_extension()           const override; // "png"
    bool        is_lossless()                   const override { return false; }

    bool verify_roundtrip(
        const fs::path& original,
        const fs::path& roundtripped
    ) const override;
};
