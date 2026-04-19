#pragma once
#include <filesystem>

namespace fs = std::filesystem;

namespace TestUtils::Raster {
    void make_png (const fs::path& path, int w, int h);
    void make_bmp (const fs::path& path, int w, int h);
    void make_jpeg(const fs::path& path, int w, int h, int quality = 90);
}
