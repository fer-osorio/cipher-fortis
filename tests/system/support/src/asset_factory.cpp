#include "../include/asset_factory.hpp"
#include "file_write_utils.hpp"

fs::path AssetFactory::make_corrupt(const fs::path& dir) const {
    fs::path p = dir / ("corrupt." + this->extension());
    static constexpr uint8_t kGarbage[8] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33
    };
    TestUtils::IO::write_binary_file(
        p,
        [](size_t i) noexcept -> uint8_t { return kGarbage[i]; },
        8
    );
    return p;
}

fs::path AssetFactory::make_empty(const fs::path& dir) const {
    fs::path p = dir / ("empty." + this->extension());
    TestUtils::IO::write_binary_file(p, 0);
    return p;
}

bool AssetFactory::verify_roundtrip(
    const fs::path& original,
    const fs::path& roundtripped
) const {
    // Default: byte-for-byte comparison. Correct for binary and text formats
    // that do not re-encode on save.
    return TestUtils::IO::read_file(original) == TestUtils::IO::read_file(roundtripped);
}
