#include<fstream>
#include<string>
#include<cstring>
#include<random>
#include"../../aes/include/constants.h"
#include"../../include/key.hpp"
#include"../utils/print_bytes.hpp"

using namespace CipherFortis;

static size_t fromLenBitsToLenBytes(Key::LengthBits lenbits){
    return size_t(lenbits)/8;
}

Key::Key(): lenBits(LengthBits::_256), lenBytes(fromLenBitsToLenBytes(lenBits)) {
    this->data = new uint8_t[this->lenBytes];
    for(size_t i = 0; i < this->lenBytes; i++) this->data[i] = 0;
}

Key::Key(LengthBits lenbits): lenBits(lenbits), lenBytes(fromLenBitsToLenBytes(lenbits)){
    size_t i;
    union { int integer; char chars[4]; } buff;                                 // -Anonymous union. Casting from 32 bits integer to four chars
    std::random_device dev; std::mt19937 seed(dev());
    std::uniform_int_distribution<std::mt19937::result_type> distribution;      // -Random number with uniform distribution
    this->data = new uint8_t[this->lenBytes];
    for(i = 0; i < this->lenBytes; i += 4) {                                    // -I am supposing everything is fine and lenBytes is a multiple of four
        buff.integer = distribution(seed);                                      // -Taking a random 32 bits integer to divide it into four bytes
        memcpy(reinterpret_cast<char*>(this->data + i), buff.chars, 4);
    }
}

Key::Key(const std::vector<uint8_t>& key_, LengthBits lenbits)
    : lenBits(lenbits), lenBytes(fromLenBitsToLenBytes(lenbits)){
    if(key_.size() < this->lenBytes){
        throw std::invalid_argument(
            "In constructor Key::Key(const std::vector<uint8_t>& key_, LengthBits lenbits): "
            "Insufficient key size: provided " + std::to_string(key_.size()) + " bytes, expected " +
            std::to_string(lenBytes) + " bytes"
        );
    }
    this->data = new uint8_t[this->lenBytes];
    if(!key_.empty()) for(size_t i = 0; i < this->lenBytes; i++) this->data[i] = key_[i];
}

Key::Key(const Key& k): lenBits(k.lenBits), lenBytes(k.lenBytes) {
    size_t i;
    this->data = new uint8_t[k.lenBytes];
    for(i = 0; i < k.lenBytes; i++) this->data[i] = k.data[i];                  // -Supposing Cipher object is well constructed, this is, k.data != nullptr
}

Key::Key(const std::string& filepath): lenBits(LengthBits::_128), lenBytes(BLOCK_SIZE) {
    std::ifstream file;
    file.open(filepath, std::ios::binary | std::ios::ate);
    if(!file.is_open()) {
        throw std::runtime_error(
            "In file src/core/key.cpp, function Key::Key(const std::string& filepath):"
            " Failed to open " + filepath
        );
    }
    std::streamsize fileSize = file.tellg();
    if(fileSize == 16)
        this->lenBits = LengthBits::_128;
    else if(fileSize == 24)
        this->lenBits = LengthBits::_192;
    else if(fileSize == 32)
        this->lenBits = LengthBits::_256;
    else {
        throw std::invalid_argument(
            "In file src/core/key.cpp, function Key::Key(const std::string& filepath):"
            " File size " + std::to_string(fileSize) +
            " does not match any valid AES key length (16, 24, or 32 bytes)."
        );
    }
    this->lenBytes = fromLenBitsToLenBytes(this->lenBits);
    this->data = new uint8_t[this->lenBytes];
    file.seekg(0);
    file.read(reinterpret_cast<char*>(this->data), static_cast<std::streamsize>(this->lenBytes));
    if(!file || file.gcount() != static_cast<std::streamsize>(this->lenBytes)) {
        delete[] this->data;
        this->data = nullptr;
        throw std::runtime_error(
            "In file src/core/key.cpp, function Key::Key(const std::string& filepath):"
            " Failed to read key data from " + filepath
        );
    }
}

Key::~Key() {
    if(this->data != nullptr) delete[] this->data;
    this->data = nullptr;
}

Key& Key::operator = (const Key& k) {
    if(this != &k) {                                                            // -Guarding against self assignment
        unsigned i;
        if(this->lenBytes != k.lenBytes) {                                // -Modifying length and array containing key only if necessary
            this->lenBits = k.lenBits;
            this->lenBytes = k.lenBytes;
            if(this->data != nullptr) delete[] this->data;
            this->data = new uint8_t[k.lenBytes];
        }
        for(i = 0; i < k.lenBytes; i++) this->data[i] = k.data[i];
    }
    return *this;
}

bool Key::operator == (const Key& k) const{
    unsigned i;
    if(this->lenBytes != k.lenBytes) return false;
    for(i = 0; i < this->lenBytes; i++) if(this->data[i] != k.data[i]) return false;
    return true;
}

bool Key::compareWithRawData(const uint8_t* raw_data, size_t size) const{
    if (size != this->lenBytes) return false;
    return memcmp(this->data, raw_data, size) == 0;
}

Key::LengthBits Key::getLenBits() const{
    return this->lenBits;
}

size_t Key::getLenBytes() const{
    return this->lenBytes;
}

std::ostream& CipherFortis::operator<<(std::ostream& ost, const Key& k) {
    ost << "\tKey size: " << static_cast<int>(k.lenBits) << " bits, " << k.lenBytes << " bytes, Nk = " << (k.lenBytes >> 2) << " words\n";
    ost << "\tKey: ";
    print_bytes_as_hex(ost, k.data, k.lenBytes);
    ost << '\n';
    return ost;
}

void Key::save(const std::string& filepath) const {
    std::ofstream file;
    file.open(filepath, std::ios::binary);
    if(!file.is_open()) {
        throw std::runtime_error(
            "In function void Key::save(const std::string& filepath) const:"
            " Failed to open " + filepath + " for writing."
        );
    }
    file.write(
        reinterpret_cast<const char*>(this->data),
        static_cast<std::streamsize>(this->lenBytes)
    );
    if(!file) {
        throw std::runtime_error(
            "In function void Key::save(const std::string& filepath) const:"
            " Failed to write key data to file: " + filepath
        );
    }
}

const uint8_t* Key::getDataForTesting() const{
    return this->data;
}

void Key::write_Key(uint8_t*const destination) const {			// -Writes key in destination. Warning: We're supposing we have enough space in
	for(size_t i = 0; i < this->lenBytes; i++) destination[i] = this->data[i]; //  destination array.
}
