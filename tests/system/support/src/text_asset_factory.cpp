#include "../include/text_asset_factory.hpp"
#include "file_write_utils.hpp"

fs::path TextAssetFactory::make_valid(const fs::path& dir) const {
    fs::path p = dir / "valid.txt";
    TestUtils::IO::write_text_file(
        p,
        "Everything that you thought had meaning: every hope, dream, or moment of happiness. "
        "None of it matters as you lie bleeding out on the battlefield. None of it changes "
        "what a speeding rock does to a body, we all die. But does that mean our lives are "
        "meaningless? Does that mean that there was no point in our being born? Would you "
        "say that of our slain comrades? What about their lives? Were they meaningless?... "
        "They were not! Their memory serves as an example to us all! The courageous fallen! "
        "The anguished fallen! Their lives have meaning because we the living refuse to forget "
        "them! And as we ride to certain death, we trust our successors to do the same for us! "
        "Because my soldiers do not buckle or yield when faced with the cruelty of this world! "
        "My soldiers push forward! My soldiers scream out! My soldiers RAAAAAGE!\n"
        "\n\t~ Erwin's famous and final speech as he leads the Survey Corps on a suicide charge."
    );
    return p;
}

fs::path TextAssetFactory::make_large(const fs::path& dir) const {
    fs::path p = dir / "large.txt";
    TestUtils::IO::write_text_file(p, std::string(1024 * 1024 * 3, 'z'));
    return p;
}

std::string TextAssetFactory::extension() const {
    return "txt";
}
