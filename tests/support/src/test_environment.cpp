#include "../include/test_environment.hpp"

TestEnvironment::TestEnvironment(const fs::path& base_dir)
    : base_dir_(base_dir)
{
    fs::create_directories(this->base_dir_);
}

TestEnvironment::~TestEnvironment() {
    fs::remove_all(this->base_dir_);
}

const fs::path& TestEnvironment::path() const {
    return this->base_dir_;
}
