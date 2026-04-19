#ifndef RASTER_IMAGE_FIXTURE_HPP
#define RASTER_IMAGE_FIXTURE_HPP

#include <gtest/gtest.h>
#include <filesystem>
#include "test_environment.hpp"
#include "raster_asset_utils.hpp"

namespace fs = std::filesystem;

class RasterImageFixture : public ::testing::Test {
public:
    static void createValidPng (const fs::path& path, int width, int height);
    static void createValidBmp (const fs::path& path, int width, int height);
    static void createValidJpeg(const fs::path& path, int width, int height, int quality = 90);

protected:
    TestEnvironment  env_{"tests/data/raster_image"};
    const fs::path&  testDataDir   = env_.path();
    fs::path         validPngPath;
    fs::path         smallPngPath;
    fs::path         largePngPath;
    fs::path         corruptPath;
    fs::path         emptyPath;
    fs::path         nonexistentPath;
    fs::path         validJpegPath;

    void SetUp() override;
    void TearDown() override;
};

#endif // RASTER_IMAGE_FIXTURE_HPP
