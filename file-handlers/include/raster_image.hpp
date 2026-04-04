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
     *       does not add a PKCS7 block. pixel_data_size_ is not modified; the gap
     *       is recoverable as data.size() - pixel_data_size_ after this call.
     *       For OFB and CTR, no padding is applied. Restores PaddingMode::PKCS7
     *       after the call. Has no effect on padding mode if the encryptor is not
     *       a CipherFortis::Cipher.
     */
    void apply_encryption(const Encryptor& algorithm) override;

    /**
     * @note Sets PaddingMode::None, decrypts, restores PaddingMode::PKCS7, then truncates
     *       data to pixel_data_size_ to remove the alignment tail.
     */
    void apply_decryption(const Encryptor& algorithm) override;

    size_t get_pixel_data_size() const;

protected:
    int width_    = 0;
    int height_   = 0;
    int channels_ = 0;
    size_t pixel_data_size_ = 0; // w*h*ch before block-alignment zero-padding
};

} // namespace File

#endif // RASTER_IMAGE_HPP
