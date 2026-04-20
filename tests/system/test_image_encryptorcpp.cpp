// System/E2E Testing for AES Image Encryption Tool

#include <gtest/gtest.h>
#include "../include/system_workflows.hpp"
#include "../include/bitmap_asset_factory.hpp"

namespace cltt = CommandLineToolsTest;

TEST(SystemTest, FileEncryptionWorkflow) {
    BitmapAssetFactory factory;
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory);
    EXPECT_TRUE(st.test_file_encryption_workflow());
}

TEST(SystemTest, ErrorScenarios) {
    BitmapAssetFactory factory;
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory);
    EXPECT_TRUE(st.test_error_scenarios());
}

TEST(SystemTest, LargeFilePerformance) {
    BitmapAssetFactory factory;
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory);
    EXPECT_TRUE(st.test_large_file_performance());
}

TEST(SystemTest, JpegEncryptSavesAsPng) {
    BitmapAssetFactory factory;
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory);
    EXPECT_TRUE(st.test_jpeg_encryption_saves_as_png());
}

TEST(SystemTest, MetadataRoundTrip) {
    BitmapAssetFactory factory;
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory);
    EXPECT_TRUE(st.test_metadata_round_trip());
}

TEST(SystemTest, FileValidityAfterEncryptDecrypt) {
    BitmapAssetFactory factory;
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, factory);
    EXPECT_TRUE(st.test_file_validity());
}
