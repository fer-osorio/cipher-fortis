#ifndef RASTER_IMAGE_HPP
#define RASTER_IMAGE_HPP

#include "file_base.hpp"

namespace File {

class RasterImage : public FileBase {
public:
    explicit RasterImage(const std::filesystem::path& path);

    /**
     * @brief Loads pixel data via stbi_load into the data buffer.
     * @note Loads exactly width_ * height_ * channels_ bytes. No alignment padding
     *       is applied. pixel_data_size_ is set to data.size() here and is never
     *       modified afterwards. Padding is the responsibility of apply_encryption().
     */
    void load() override;

    /**
     * @note For ECB and CBC, zero-pads the pixel buffer to the nearest 16-byte
     *       boundary before encrypting, then sets PaddingMode::None so the cipher
     *       does not add a PKCS#7 block. pixel_data_size_ is not modified; the gap
     *       is recoverable as data.size() - pixel_data_size_ after this call and
     *       is also exposed via get_gap_bytes(). For OFB and CTR, no padding is
     *       applied. Restores PaddingMode::PKCS7 after the call. Has no effect on
     *       padding mode if the encryptor is not a CipherFortis::Cipher.
     */
    void apply_encryption(const Encryptor& algorithm) override;

    /**
     * @note Sets PaddingMode::None, decrypts, restores PaddingMode::PKCS7, then
     *       truncates data to pixel_data_size_ to remove the alignment tail.
     *       For OFB and CTR, no alignment tail is ever appended by
     *       apply_encryption(), so the truncation is a no-op.
     */
    void apply_decryption(const Encryptor& algorithm) override;

    size_t get_pixel_data_size() const;

    /**
     * @brief Checks that the file at path has the same dimensions as this image.
     * @return true if stbi_info reports width, height, and channels matching
     *         width_, height_, and channels_. Must be called after load().
     */
    bool verify_saved_file(const std::filesystem::path& path) const;

protected:
    int width_    = 0;
    int height_   = 0;
    int channels_ = 0;
    size_t pixel_data_size_ = 0; // w*h*ch before block-alignment zero-padding
};

} // namespace File

#endif // RASTER_IMAGE_HPP
