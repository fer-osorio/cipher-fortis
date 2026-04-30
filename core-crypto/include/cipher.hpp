#ifndef CIPHER_HPP
#define CIPHER_HPP

#include"key.hpp"
#include"encryptor.hpp"
#include"crypto_types.hpp"

namespace CipherFortis {

// Forward declarations of custom exceptions
class AESException;
class KeyExpansionException;
class EncryptionException;
class DecryptionException;

struct InitVector;

std::ostream& operator << (std::ostream& st, const Cipher& c);			// -Declaration here so this function is inside the name space function.

class Cipher : public Encryptor {
public:
	struct OperationMode{
	public:
		// Preserve the existing nested name so all callsites compile unchanged.
		using Identifier = CipherFortis::OperationModeID;

	private:
		Identifier ID_ = Identifier::ECB;
		InitVector* IV_ = nullptr;						// -Initial vector in case of CBC operation mode

	public:
		OperationMode();
		explicit OperationMode(Identifier);
		OperationMode(const OperationMode&);
		OperationMode& operator=(const OperationMode&);
		~OperationMode();

		Identifier getOperationModeID() const;
		const uint8_t* getIVpointerData() const;
		bool setInitialVector(const std::vector<uint8_t>& source);

		static const char* identifier_to_string(Identifier);
		static Identifier string_to_identifier(const std::string&);

		void save(const std::string& filepath) const;
		static OperationMode loadFromFile(const std::string& filepath);
	};

	enum class PaddingMode {
		PKCS7,  // Default: ECB/CBC pad/unpad automatically; output size differs from input.
		None    // Caller guarantees block alignment; no padding is added or stripped.
	};

	struct Config{
	private:
		OperationMode operationMode;
		size_t Nk_;
		size_t Nr;
		size_t keyExpansionLengthBytes;
	public:
		Config();
		Config(OperationMode optMode, Key::LengthBits);
		OperationMode::Identifier getOperationModeID() const;
		size_t getNk() const;
		size_t getNr() const;
		size_t getKeyExpansionLengthBytes() const;
		const uint8_t* getIVpointerData() const;
		bool setInitialVector(const std::vector<uint8_t>& source);
		void saveOperationMode(const std::string& filepath) const;
	};

private:
	Key key = Key();
	uint8_t* keyExpansion = nullptr;
	struct Config config;

	Cipher();								// -The default constructor will set the key expansion as zero in every element.

public:
	/**
	 * @brief Builds a new Cipher session with a freshly generated key.
	 * @param padding_mode Padding policy applied by encryption()/decryption()
	 *        for ECB/CBC. Defaults to PaddingMode::PKCS7. Pass PaddingMode::None
	 *        when the caller guarantees block alignment (e.g. RasterImage).
	 */
	Cipher(
	    const Key::LengthBits,
	    const OperationMode::Identifier,
	    PaddingMode padding_mode = PaddingMode::PKCS7
	);

	/**
	 * @brief Builds a Cipher session with the given key and operation mode.
	 * @param padding_mode Padding policy applied by encryption()/decryption()
	 *        for ECB/CBC. Defaults to PaddingMode::PKCS7. Pass PaddingMode::None
	 *        when the caller guarantees block alignment (e.g. RasterImage).
	 */
	Cipher(
	    const Key&,
	    const OperationMode&,
	    PaddingMode padding_mode = PaddingMode::PKCS7
	);
	Cipher(const Cipher&);
	~Cipher();

	Cipher& operator = (const Cipher& a);
	friend std::ostream& operator << (std::ostream& st, const Cipher& c);

	/**
	 * @brief Returns true when this cipher requires the caller to supply a
	 *        block-aligned input (mode is ECB or CBC and PaddingMode::None).
	 */
	bool requires_block_alignment() const override;

	/**
	 * @brief Encrypts data contained in input vector and writes the result in output vector.
	 * @note Behaviour is determined by the PaddingMode set at construction time.
	 *       ECB/CBC with PaddingMode::PKCS7 (default): input is padded; output is resized
	 *       to the padded length (positive multiple of BLOCK_SIZE, > input.size()).
	 *       ECB/CBC with PaddingMode::None: input must be block-aligned; output is resized
	 *       to input.size(). Use requires_block_alignment() to query this at runtime.
	 *       OFB/CTR: no padding; output must be pre-allocated to at least input.size().
	 * @throws std::invalid_argument, EncryptionException, AESException
	 */
	void encryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const override;

	/**
	 * @brief Decrypts data contained in input vector and writes the result in output vector.
	 * @note Behaviour is determined by the PaddingMode set at construction time.
	 *       ECB/CBC with PaddingMode::PKCS7 (default): PKCS#7 padding is stripped; output
	 *       is resized to the unpadded length.
	 *       ECB/CBC with PaddingMode::None: no unpadding; output is resized to input.size().
	 *       OFB/CTR: no unpadding; output must be pre-allocated to at least input.size().
	 * @throws std::invalid_argument, EncryptionException, AESException
	 */
	void decryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const override;

		/*
	 * Encrypts using operation mode stored in Cipher object
	 * Consider: Comunicates with AES.h
	 * Consider: Rewrites bytes pointed by output
	 * Consider: Throws std::invalid_argument, EncryptionException, AESException
	 * */
	void encrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;

	/*
	 * Decrypts using operation mode stored in Cipher object
	 * Consider: Comunicates with AES.h
	 * Consider: Rewrites bytes pointed by output
	 * Consider: Throws std::invalid_argument, EncryptionException, AESException
	 * */
	void decrypt(const uint8_t*const data, size_t size, uint8_t*const output)const;


	void saveKey(const std::string& filepath) const;
	void saveOperationMode(const std::string& filepath) const;

	OperationMode::Identifier getOptModeID() const;

	// For testing purposes
	const uint8_t* getKeyExpansionForTesting() const;
	bool isKeyExpansionInitialized() const;
	const uint8_t* getInitialVectorForTesting() const;
	bool setInitialVectorForTesting(const std::vector<uint8_t>& source);

	private:
	PaddingMode padding_mode_ = PaddingMode::PKCS7;
	//OperationMode buildOperationMode(const OperationMode::Identifier);
	/*
	 * Creates key expansion
	 * Consider: Trows KeyExpansionException
	 * */
	void buildKeyExpansion();
	//void formInitialVector();						// -Creates initial vector and writes it on destination array
	static std::vector<uint8_t> pkcs7_pad(const std::vector<uint8_t>& input);
	static std::vector<uint8_t> pkcs7_unpad(const std::vector<uint8_t>& padded);
};
};
#endif
