#include "../include/png_asset_factory.hpp"
#include "../include/raster_asset_utils.hpp"
#include "../../file-handlers/include/png_image.hpp"

fs::path PngAssetFactory::make_valid(const fs::path& dir) const {
    fs::path p = dir / "valid.png";
    TestUtils::Raster::make_png(p, 32, 32);
    return p;
}

fs::path PngAssetFactory::make_large(const fs::path& dir) const {
    fs::path p = dir / "large.png";
    TestUtils::Raster::make_png(p, 4096, 3072);
    return p;
}

std::string PngAssetFactory::extension() const { return "png"; }

bool PngAssetFactory::verify_roundtrip(
    const fs::path& original,
    const fs::path& roundtripped
) const {
    File::PNG ref(original);
    ref.load();
    return ref.verify_saved_file(roundtripped);
}
