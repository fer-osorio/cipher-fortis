#include "../include/bitmap_asset_factory.hpp"
#include "raster_asset_utils.hpp"
#include "bitmap.hpp"

fs::path BitmapAssetFactory::make_valid(const fs::path& dir) const {
    fs::path p = dir / "valid.bmp";
    TestUtils::Raster::make_bmp(p, 32, 32);
    return p;
}

fs::path BitmapAssetFactory::make_large(const fs::path& dir) const {
    fs::path p = dir / "large.bmp";
    TestUtils::Raster::make_bmp(p, 4096, 4096);
    return p;
}

std::string BitmapAssetFactory::extension() const {
    return "bmp";
}

bool BitmapAssetFactory::verify_roundtrip(
    const fs::path& original,
    const fs::path& roundtripped
) const {
    File::Bitmap ref(original);
    ref.load();
    // Checks that stbi_info reports matching width, height, and channels.
    return ref.verify_saved_file(roundtripped);
}
