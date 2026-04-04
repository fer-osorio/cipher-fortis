#include "../include/raster_image.hpp"
#include "../../core-crypto/include/encryptor.hpp"
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
}

size_t RasterImage::get_pixel_data_size() const {
    return pixel_data_size_;
}

bool RasterImage::verify_saved_file(const std::filesystem::path& path) const {
    int w, h, ch;
    if (!stbi_info(path.string().c_str(), &w, &h, &ch))
        return false;
    return w == width_ && h == height_ && ch == channels_;
}

void RasterImage::apply_encryption(const Encryptor& algorithm) {
    if (algorithm.requires_block_alignment()) {
        size_t gap = CipherFortis::Padding::alignment_gap(
            pixel_data_size_, kAesBlockSize
        );
        if (gap > 0)
            this->data.insert(this->data.end(), gap, static_cast<uint8_t>(0));
    }
    FileBase::apply_encryption(algorithm);
}

void RasterImage::apply_decryption(const Encryptor& algorithm) {
    FileBase::apply_decryption(algorithm);
    this->data.resize(pixel_data_size_);
}

} // namespace File
