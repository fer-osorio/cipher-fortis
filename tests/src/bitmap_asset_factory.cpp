#include "../include/bitmap_asset_factory.hpp"
#include "../include/raster_asset_utils.hpp"

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
