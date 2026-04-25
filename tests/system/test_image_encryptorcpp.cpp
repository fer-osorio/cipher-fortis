// tests/system/test_image_encryptorcpp.cpp

#include <gtest/gtest.h>
#include "../include/system_workflows.hpp"
#include "../include/asset_factory.hpp"
#include "../include/bitmap_asset_factory.hpp"
#include "../include/png_asset_factory.hpp"
#include "../include/jpeg_asset_factory.hpp"
#include "../include/test_environment.hpp"

namespace cltt = CommandLineToolsTest;

// ── Parameterised suite ───────────────────────────────────────────────────────

class ImageEncryptorSystemTest
    : public ::testing::TestWithParam<const AssetFactory*> {
protected:
    const AssetFactory& factory() const { return *GetParam(); }
};

TEST_P(ImageEncryptorSystemTest, FileEncryptionWorkflow) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory());
    EXPECT_TRUE(st.test_file_encryption_workflow());
}

TEST_P(ImageEncryptorSystemTest, ErrorScenarios) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory());
    EXPECT_TRUE(st.test_error_scenarios());
}

TEST_P(ImageEncryptorSystemTest, LargeFilePerformance) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory());
    EXPECT_TRUE(st.test_large_file_performance());
}

TEST_P(ImageEncryptorSystemTest, MetadataRoundTrip) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory());
    EXPECT_TRUE(st.test_metadata_round_trip());
}

TEST_P(ImageEncryptorSystemTest, FileValidityAfterEncryptDecrypt) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory());
    EXPECT_TRUE(st.test_file_validity());
}

// Factory instances — stateless, safe to share across the suite.
static BitmapAssetFactory bitmapFactory;
static PngAssetFactory    pngFactory;
static JpegAssetFactory   jpegFactory;

INSTANTIATE_TEST_SUITE_P(
    ImageFormats,
    ImageEncryptorSystemTest,
    ::testing::Values(
        static_cast<const AssetFactory*>(&bitmapFactory),
        static_cast<const AssetFactory*>(&pngFactory),
        static_cast<const AssetFactory*>(&jpegFactory)
    ),
    [](const ::testing::TestParamInfo<const AssetFactory*>& info) {
        return info.param->extension();
    }
);

// ── JPEG standalone test ──────────────────────────────────────────────────────

TEST(SystemTest, JpegEncryptSavesAsPng) {
    TestEnvironment env("test_data/jpeg_saves_as_png");
    EXPECT_TRUE(cltt::test_jpeg_saves_as_png(IMAGE_ENCRYPTOR_PATH, env.path()));
}
