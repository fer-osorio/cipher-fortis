#include "../include/raster_image.hpp"
#include "../../core-crypto/include/cipher.hpp"
#include "../../core-crypto/src/utils/padding.hpp"
#include "../../third-party/stb/stb_image.h"
#include <stdexcept>
#include <string>

namespace File {

static constexpr size_t kAesBlockSize = 16;

RasterImage::RasterImage(const std::filesystem::path& path)
    : FileBase(path) {}

void RasterImage::load() {
    if (!this->data.empty()) return;
    int w, h, ch;
    uint8_t* pixels = stbi_load(
        this->file_path.string().c_str(), &w, &h, &ch, 0);
    if (!pixels)
        throw std::runtime_error(
            std::string("RasterImage::load(): ") + stbi_failure_reason());
    width_    = w;
    height_   = h;
    channels_ = ch;
    this->data.assign(pixels, pixels + w * h * ch);
    stbi_image_free(pixels);
    pixel_data_size_ = this->data.size();
    size_t gap = CipherFortis::Padding::alignment_gap(pixel_data_size_, kAesBlockSize);
    if (gap > 0)
        this->data.insert(this->data.end(), gap, static_cast<uint8_t>(0));
}

size_t RasterImage::get_pixel_data_size() const {
    return pixel_data_size_;
}

void RasterImage::apply_encryption(const Encryptor& algorithm) {
    // This does not feel right, it has to be revisited later
    auto* cipher = dynamic_cast<CipherFortis::Cipher*>(
        const_cast<Encryptor*>(&algorithm)
    );
    if (cipher) cipher->set_padding_mode(CipherFortis::Cipher::PaddingMode::None);
    FileBase::apply_encryption(algorithm);
    if (cipher) cipher->set_padding_mode(CipherFortis::Cipher::PaddingMode::PKCS7);
}

void RasterImage::apply_decryption(const Encryptor& algorithm) {
    // This does not feel right either, it has to be revisited later
    auto* cipher = dynamic_cast<CipherFortis::Cipher*>(
        const_cast<Encryptor*>(&algorithm)
    );
    if (cipher) cipher->set_padding_mode(CipherFortis::Cipher::PaddingMode::None);
    FileBase::apply_decryption(algorithm);
    if (cipher) cipher->set_padding_mode(CipherFortis::Cipher::PaddingMode::PKCS7);
    this->data.resize(pixel_data_size_);
}

} // namespace File
