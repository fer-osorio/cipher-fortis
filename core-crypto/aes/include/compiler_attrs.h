#ifndef CF_COMPILER_ATTRS_H
#define CF_COMPILER_ATTRS_H

/* CF_HOT — hints to the compiler that this function is on the critical path */
#if defined(__GNUC__) || defined(__clang__)
#  define CF_HOT __attribute__((hot))
#else
#  define CF_HOT
#endif

/* CF_RESTRICT — standard restrict qualifier with portability guard */
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) \
    || defined(__GNUC__) || defined(__clang__)
#  define CF_RESTRICT restrict
#else
#  define CF_RESTRICT
#endif

/* CF_TARGET_AESNI — documents that a function body requires AES-NI and
 * SSSE3 ISA support.  Applied to functions in aes_ni.c as a readability
 * and documentation aid.
 *
 * NOTE: cross-TU inlining of these functions is prevented at the build
 * level by compiling aes_ni.c with -fno-lto (see CMakeLists.txt), which
 * produces real machine code rather than GIMPLE IR.  This attribute does
 * not replace that build-level guard. */
#ifdef CF_ENABLE_AESNI
#  if defined(__GNUC__) || defined(__clang__)
#    define CF_TARGET_AESNI __attribute__((target("aes,ssse3")))
#  else
#    define CF_TARGET_AESNI
#  endif
#endif

#endif /* CF_COMPILER_ATTRS_H */
