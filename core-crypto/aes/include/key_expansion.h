#ifndef KEY_EXPANSION_H
#define KEY_EXPANSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "block.h"
#include "exception_code.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct KeyExpansion_ {
  enum Nk_t Nk;
  size_t Nr;
  size_t wordsSize;
  size_t blockSize;
  Block_t* dataBlocks;
#ifndef CF_NO_TTABLES
  /* Precomputed inv_mix_col of each forward round-key column.
   * Indexed as invRoundCols[r*4 + c] for round r, column c.
   * Valid for r in [1, Nr-1]; rounds 0 and Nr have no InvMixColumns
   * partner and are not stored here. */
  uint32_t *invRoundCols;
#endif
#ifdef CF_ENABLE_AESNI
  /* Round keys in FIPS 197 column-major byte order, ready for direct
   * _mm_loadu_si128. Size: (Nr+1)*16 bytes. */
  uint8_t *niRoundKeys;
  /* AESIMC-transformed round keys for AES-NI decryption.
   * Entries 1..Nr-1 are AESIMC(niRoundKeys[r]); entries 0 and Nr
   * are verbatim copies of niRoundKeys[0/Nr]. Size: (Nr+1)*16 bytes. */
  uint8_t *niDecRoundKeys;
#endif
} KeyExpansion_t;

/*
 * Initialises a caller-allocated KeyExpansion_t object.
 * */
enum ExceptionCode KeyExpansionInit(KeyExpansion_t*const output, const uint8_t* key, size_t keylenbits, bool debug);

/*
 * Builds a KeyExpansion_t object and returns a pointer to it.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_t* KeyExpansionCreate(const uint8_t* key, size_t keylenbits, bool debug);

/*
 * Builds a KeyExpansion_t object with zeros and returns a pointer to it.
 * Consider: Allocates memory using malloc.
 * */
KeyExpansion_t* KeyExpansionCreateZero(size_t keylenbits);

/*
 * Free the memory allocated for a KeyExpansion_t object pointed by *ke_pp.
 * */
void KeyExpansionDestroy(KeyExpansion_t** ke_pp);

/*
 * Writes the bytes that form the key expansion object to the location pointed by dest.
 * */
void KeyExpansionWriteToBytes(const KeyExpansion_t* source, uint8_t* dest);

/*
 * Initialises a KeyExpansion_t object using the bytes pointed by input.
 * */
enum ExceptionCode KeyExpansionReadFromBytes(KeyExpansion_t*const output, const uint8_t input[]);

/*
 * Builds key expansion and writes it on the bytes pointed by dest.
 * Consider: Supposes that dest points to a suitable memory location.
 * */
enum ExceptionCode KeyExpansionInitWrite(const uint8_t* key, size_t keylenbits, uint8_t* dest, bool debug);

/*
 * Compare key expansion with the bytes pointed by bytes.
 * */
bool compareKeyExpansionBytes(const KeyExpansion_t*const input, const uint8_t bytes[]);

#ifdef __cplusplus
}
#endif

#endif
