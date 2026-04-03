#ifndef RASTER_IMAGE_HPP
#define RASTER_IMAGE_HPP

#include "file_base.hpp"

namespace File {

class RasterImage : public FileBase {
public:
    explicit RasterImage(const std::filesystem::path& path);

    /**
     * @brief Loads pixel data via stbi_load and zero-pads to the nearest 16-byte boundary.
     * @note The original unpadded byte count is stored in pixel_data_size_.
     *       Image dimensions (width_, height_, channels_) are never modified by padding.
     */
    void load() override;

    /**
     * @note Sets PaddingMode::None on the cipher before encrypting (the pixel buffer is
     *       already block-aligned after load()) and restores PaddingMode::PKCS7 afterwards.
     *       Has no effect on the padding mode if the encryptor is not a CipherFortis::Cipher.
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
