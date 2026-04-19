#include "../include/binary_asset_factory.hpp"
#include "../include/file_write_utils.hpp"

fs::path BinaryAssetFactory::make_valid(const fs::path& dir) const {
    fs::path p = dir / "valid.bin";
    TestUtils::IO::write_binary_file(p, 1024);
    return p;
}

fs::path BinaryAssetFactory::make_large(const fs::path& dir) const {
    fs::path p = dir / "large.bin";
    TestUtils::IO::write_binary_file(p, 1024 * 1024 * 3);
    return p;
}

std::string BinaryAssetFactory::extension() const {
    return "bin";
}
