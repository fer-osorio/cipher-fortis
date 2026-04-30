#ifndef KEY_HPP
#define KEY_HPP

#include<iostream>
#include<stddef.h>
#include<stdint.h>
#include<vector>
#include "crypto_types.hpp"

namespace CipherFortis {

struct Key;									// -Declaring struct Key and class Cipher to use them as arguments in functions
std::ostream& operator << (std::ostream& ost, const Key& k);

class Cipher;									// Declare cipher class, so we can make it a friend of Key structure

struct Key {
public:
	// Preserve the existing nested name so all callsites compile unchanged.
	using LengthBits = CipherFortis::KeyLengthBits;
private:
	uint8_t* data = NULL;
	LengthBits lenBits;							// -Length in bits.
	size_t lenBytes;							// -Length in bytes.

	friend Cipher;
	// The following private constructor can only be acceced by Cipher class, the intention is to have well-constructed keys for the user.
	Key();
public:
	explicit Key(LengthBits);
	/*
	 * Consider: Throws exception when the size of the passed vector argument key_ is insuficient
	 * */
	Key(const std::vector<uint8_t>& key_, LengthBits);
	/*
	 * Consider: Throws exception when file does not exist, cannot be opened, or
	 * its size does not match a valid AES key length (16, 24, or 32 bytes).
	 * */
	explicit Key(const std::string& filepath);						// -Building from raw binary file.
	Key(const Key&);
	~Key();

	Key& operator =  (const Key&);
	bool operator == (const Key&) const;
	bool compareWithRawData(const uint8_t* raw_data, size_t len) const;
	friend std::ostream& operator << (std::ostream& ost, const Key& k);

	LengthBits getLenBits() const;
	size_t getLenBytes() const;

	const uint8_t* getDataForTesting() const;

	void save(const std::string& filepath) const;				// -Saving information in a binary file.
private:
	// -Writes key in destination. Warning: We're supposing we have enough space in
	//  destination array.
	void write_Key(uint8_t*const destination) const;
};
};
#endif
