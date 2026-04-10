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

#endif /* CF_COMPILER_ATTRS_H */
