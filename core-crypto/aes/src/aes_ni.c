#ifdef CF_ENABLE_AESNI

/*
 * aes_ni.c — AES-NI hardware-accelerated block cipher implementation.
 *
 * This translation unit MUST be compiled with -maes -mssse3.
 * It is only linked when CF_ENABLE_AESNI is defined (see CMakeLists.txt).
 *
 * LAYOUT NOTE:
 * Block_t stores state[r][c] at uint08_[4*r + c] (row-major).
 * AES-NI intrinsics expect the FIPS 197 byte order (column-major):
 * state[r][c] at XMM byte c*4 + r.
 * Every Block_t <-> __m128i conversion applies the CF_TRANSPOSE shuffle,
 * which is its own inverse (transpose of a 4x4 byte matrix).
 */

#include "aes_ni.h"
#include "../include/block.h"
#include "../include/key_expansion.h"
#include "../include/compiler_attrs.h"
#include <wmmintrin.h>  /* AESENC / AESDEC family              */
#include <tmmintrin.h>  /* _mm_shuffle_epi8 (PSHUFB, SSSE3)   */
#include <emmintrin.h>  /* _mm_loadu_si128 / _mm_storeu_si128  */
#include <string.h>

/* Transpose mask: converts row-major Block_t bytes to FIPS 197
 * column-major XMM bytes and back.  _mm_set_epi8 takes args high->low.
 * Stored as a byte array and loaded at first use to stay portable
 * across C standards and compilers. */
static const uint8_t CF_TRANSPOSE_BYTES[16] = {
  0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
};
static CF_TARGET_AESNI inline __m128i cf_transpose_mask(void) {
  return _mm_loadu_si128((const __m128i *)CF_TRANSPOSE_BYTES);
}

static CF_TARGET_AESNI inline __m128i block_to_m128i(const Block_t *b) {
  __m128i v = _mm_loadu_si128((const __m128i *)b->uint08_);
  return _mm_shuffle_epi8(v, cf_transpose_mask());
}

static CF_TARGET_AESNI inline void m128i_to_block(__m128i v, Block_t *b) {
  v = _mm_shuffle_epi8(v, cf_transpose_mask());
  _mm_storeu_si128((__m128i *)b->uint08_, v);
}

/* Load a precomputed NI round key from the flat byte array. */
static CF_TARGET_AESNI inline __m128i load_ni_rk(
  const uint8_t *base, size_t r
) {
  return _mm_loadu_si128((const __m128i *)(base + r * 16));
}

CF_TARGET_AESNI
enum ExceptionCode encryptBlock_ni(
  const Block_t *input,
  const KeyExpansion_t *ke_p,
  Block_t *output,
  bool debug
) {
  (void)debug; /* NI path does not support debug output */
  if (input  == NULL) return NullInput;
  if (output == NULL) return NullOutput;
  if (ke_p   == NULL) return NullKeyExpansion;

  __m128i state = block_to_m128i(input);

  /* AddRoundKey — round 0 */
  state = _mm_xor_si128(state, load_ni_rk(ke_p->niRoundKeys, 0));

  /* Rounds 1 .. Nr-1 */
  for (size_t r = 1; r < ke_p->Nr; r++) {
    state = _mm_aesenc_si128(state, load_ni_rk(ke_p->niRoundKeys, r));
  }

  /* Final round — no MixColumns */
  state = _mm_aesenclast_si128(
    state, load_ni_rk(ke_p->niRoundKeys, ke_p->Nr)
  );

  m128i_to_block(state, output);
  return NoException;
}

CF_TARGET_AESNI
enum ExceptionCode decryptBlock_ni(
  const Block_t *input,
  const KeyExpansion_t *ke_p,
  Block_t *output,
  bool debug
) {
  (void)debug;
  if (input  == NULL) return NullInput;
  if (output == NULL) return NullOutput;
  if (ke_p   == NULL) return NullKeyExpansion;

  __m128i state = block_to_m128i(input);

  /* AddRoundKey — round Nr */
  state = _mm_xor_si128(state, load_ni_rk(ke_p->niRoundKeys, ke_p->Nr));

  /* Rounds Nr-1 .. 1 — uses AESIMC-transformed keys */
  for (size_t r = ke_p->Nr - 1; r > 0; r--) {
    state = _mm_aesdec_si128(state, load_ni_rk(ke_p->niDecRoundKeys, r));
  }

  /* Final round — round key 0, no InvMixColumns */
  state = _mm_aesdeclast_si128(
    state, load_ni_rk(ke_p->niRoundKeys, 0)
  );

  m128i_to_block(state, output);
  return NoException;
}

CF_TARGET_AESNI
void aes_ni_populate_keys(KeyExpansion_t *ke) {
  /* Build niRoundKeys: transpose each Block_t round key to FIPS
   * column-major XMM byte order. */
  for (size_t r = 0; r <= ke->Nr; r++) {
    __m128i rk = block_to_m128i(&ke->dataBlocks[r]);
    _mm_storeu_si128((__m128i *)(ke->niRoundKeys + r * 16), rk);
  }

  /* Build niDecRoundKeys:
   * - rounds 0 and Nr are copied verbatim (used in first/last
   *   AddRoundKey which has no InvMixColumns partner)
   * - rounds 1 .. Nr-1 get AESIMC applied */
  memcpy(ke->niDecRoundKeys, ke->niRoundKeys, 16);
  memcpy(
    ke->niDecRoundKeys + ke->Nr * 16,
    ke->niRoundKeys    + ke->Nr * 16,
    16
  );
  for (size_t r = 1; r < ke->Nr; r++) {
    __m128i rk = load_ni_rk(ke->niRoundKeys, r);
    rk = _mm_aesimc_si128(rk);
    _mm_storeu_si128((__m128i *)(ke->niDecRoundKeys + r * 16), rk);
  }
}

#endif /* CF_ENABLE_AESNI */
