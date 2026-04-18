#ifndef CF_CPU_FEATURES_H
#define CF_CPU_FEATURES_H

#include <stdbool.h>

/*
 * Returns true when the current CPU supports the AES-NI instruction set
 * (AESENC, AESENCLAST, AESDEC, AESDECLAST, AESIMC, AESKEYGENASSIST).
 *
 * Uses GCC/Clang's __builtin_cpu_supports, which reads a cached CPUID
 * result at process start and requires no special compiler flags in the
 * calling translation unit.
 */
static inline bool cf_cpu_has_aesni(void) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_cpu_supports("aes");
#else
  return false;
#endif
}

#endif /* CF_CPU_FEATURES_H */
