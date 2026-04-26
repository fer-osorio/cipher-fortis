#include "../include/jpeg_asset_factory.hpp"
#include "../include/raster_asset_utils.hpp"
#include "../../file-handlers/include/jpeg_image.hpp"

fs::path JpegAssetFactory::make_valid(const fs::path& dir) const {
    fs::path p = dir / "valid.jpg";
    TestUtils::Raster::make_jpeg(p, 32, 32);
    return p;
}

fs::path JpegAssetFactory::make_large(const fs::path& dir) const {
    fs::path p = dir / "large.jpg";
    TestUtils::Raster::make_jpeg(p, 2048, 2048);
    return p;
}

std::string JpegAssetFactory::extension() const { return "jpg"; }
std::string JpegAssetFactory::encrypted_extension() const { return "png"; }

bool JpegAssetFactory::verify_roundtrip(
    const fs::path& original,
    const fs::path& roundtripped
) const {
    File::JPEG ref(original);
    ref.load();
    // Byte comparison is intentionally skipped: lossy re-encoding after
    // decryption means the output will never be byte-identical to the
    // input even on a correct implementation. Dimension match is the
    // strongest assertion available for this format.
    return ref.verify_saved_file(roundtripped);
}
