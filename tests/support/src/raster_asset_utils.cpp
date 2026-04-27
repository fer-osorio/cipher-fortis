#include "../include/raster_asset_utils.hpp"
#include "stb_image_write.h"
#include <vector>
#include <cstdint>

namespace TestUtils::Raster {

// Shared pixel generator: pixel(x, y) = (x*25, y*25, 128) RGB.
static std::vector<uint8_t> make_pixels(int w, int h) {
    std::vector<uint8_t> pixels(w * h * 3);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            int idx = (y * w + x) * 3;
            pixels[idx]     = static_cast<uint8_t>(x * 25);
            pixels[idx + 1] = static_cast<uint8_t>(y * 25);
            pixels[idx + 2] = 128;
        }
    return pixels;
}

void make_png(const fs::path& path, int w, int h) {
    auto pixels = make_pixels(w, h);
    stbi_write_png(path.string().c_str(), w, h, 3, pixels.data(), w * 3);
}

void make_bmp(const fs::path& path, int w, int h) {
    auto pixels = make_pixels(w, h);
    stbi_write_bmp(path.string().c_str(), w, h, 3, pixels.data());
}

void make_jpeg(const fs::path& path, int w, int h, int quality) {
    auto pixels = make_pixels(w, h);
    stbi_write_jpg(path.string().c_str(), w, h, 3, pixels.data(), quality);
}

}
