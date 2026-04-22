#pragma once
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

class AssetFactory {
public:
    virtual ~AssetFactory() = default;

    virtual fs::path    make_valid(const fs::path& dir) const = 0;
    virtual fs::path    make_large(const fs::path& dir) const = 0;
    virtual std::string extension()                     const = 0;
    virtual bool        is_binary()   const { return true; }
    virtual bool        is_lossless() const { return true; }

    // Non-virtual: format-independent implementations.
    fs::path make_corrupt(const fs::path& dir) const;
    fs::path make_empty  (const fs::path& dir) const;

    /**
     * @brief Verifies that `roundtripped` is a valid asset of this format
     *        and faithfully represents the content of `original`.
     *
     * The default implementation performs a byte-for-byte comparison of the
     * two files, which is correct for lossless formats (binary, text).
     * Raster format subclasses should override this to verify that the file
     * is loadable and has the expected dimensions via
     * RasterImage::verify_saved_file.
     *
     * @return true if the roundtrip is considered successful for this format.
     */
    virtual bool verify_roundtrip(
        const fs::path& original,
        const fs::path& roundtripped
    ) const;
};
