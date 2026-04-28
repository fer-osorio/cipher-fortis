#include "raster_image_fixture.hpp"
#include "raster_asset_utils.hpp"
#include "file_write_utils.hpp"

void RasterImageFixture::SetUp() {
    this->validPngPath    = env_.path() / "valid_10x10.png";
    this->smallPngPath    = env_.path() / "small_2x2.png";
    this->largePngPath    = env_.path() / "large_100x100.png";
    this->corruptPath     = env_.path() / "corrupt.png";
    this->emptyPath       = env_.path() / "empty.png";
    this->nonexistentPath = env_.path() / "does_not_exist.png";
    this->validJpegPath   = env_.path() / "valid_10x10.jpg";

    TestUtils::Raster::make_png(this->validPngPath,   10, 10);
    TestUtils::Raster::make_png(this->smallPngPath,    2,  2);
    TestUtils::Raster::make_png(this->largePngPath,  100, 100);
    TestUtils::IO::write_binary_file(
        this->corruptPath,
        [](size_t i) noexcept -> uint8_t {
            constexpr uint8_t g[8] = {
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33
            };
            return g[i];
        },
        8
    );
    TestUtils::IO::write_binary_file(this->emptyPath, 0);
    TestUtils::Raster::make_jpeg(this->validJpegPath, 10, 10);
}

void RasterImageFixture::TearDown() {}
