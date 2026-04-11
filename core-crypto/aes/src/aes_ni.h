#ifndef CF_AES_NI_H
#define CF_AES_NI_H

#ifdef CF_ENABLE_AESNI

#include "../include/AES.h"
#include "../include/key_expansion.h"
#include "../include/compiler_attrs.h"

/*
 * AES-NI accelerated block cipher functions.
 * These are drop-in replacements for encryptBlock / decryptBlock and
 * share the same signature. They are compiled with -maes -mssse3 and
 * must only be called after confirming cf_cpu_has_aesni() == true.
 *
 * CF_TARGET_AESNI is applied to every declaration so that LTO cannot
 * inline these functions into TUs compiled without -maes.
 */
CF_TARGET_AESNI
enum ExceptionCode encryptBlock_ni(
  const Block_t *input,
  const KeyExpansion_t *ke_p,
  Block_t *output,
  bool debug
);

CF_TARGET_AESNI
enum ExceptionCode decryptBlock_ni(
  const Block_t *input,
  const KeyExpansion_t *ke_p,
  Block_t *output,
  bool debug
);

/*
 * Populates ke->niRoundKeys and ke->niDecRoundKeys from ke->dataBlocks.
 * Must be called after dataBlocks is fully initialised (by KeyExpansionInit,
 * KeyExpansionReadFromBytes, or KeyExpansionCreateZero).
 * Compiled with -maes so that _mm_aesimc_si128 is available.
 */
CF_TARGET_AESNI
void aes_ni_populate_keys(KeyExpansion_t *ke);

#endif /* CF_ENABLE_AESNI */
#endif /* CF_AES_NI_H */
