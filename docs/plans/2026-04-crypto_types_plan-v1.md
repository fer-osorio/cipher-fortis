# Shared `crypto_types.hpp` Header — Implementation Plan

**Status:** completed  
**Scope:** `core-crypto`, `hsm-integration`, affected test files  
**Motivation:** `hsm-integration` currently depends on `key.hpp` solely to
reuse `Key::LengthBits`. That pulls in a concrete implementation class as a
dependency of what is otherwise a thin interface module. Extracting the stable,
behaviorally-inert type definitions into a dedicated header makes the dependency
explicit, minimal, and correct.

---

## Objectives

1. Create `core-crypto/include/crypto_types.hpp` containing the type
   definitions that are consumed by more than one module.
2. Migrate `Key::LengthBits` and `Cipher::OperationMode::Identifier` into that
   header.
3. Update `key.hpp` and `cipher.hpp` to import from `crypto_types.hpp` so all
   existing callsites continue to compile without modification.
4. Update `hsm_key_handle.hpp` to include `crypto_types.hpp` directly instead
   of `key.hpp`.
5. Verify the full test suite passes without modification.

---

## Types to migrate

| Type | Current location | Reason to migrate |
|---|---|---|
| `Key::LengthBits` | `core-crypto/include/key.hpp` | Used by `hsm_key_handle.hpp`, `hsm_cipher.hpp`, test vectors, and CLI configs; pulling in the full `Key` class for an enum is excess baggage |
| `Cipher::OperationMode::Identifier` | `core-crypto/include/cipher.hpp` | Used by `hsm_cipher.hpp`, `cli_config.hpp`, and both CLI tools; same rationale |

`ExceptionCode` (the C enum in `core-crypto/aes/include/exception_code.h`) is
intentionally excluded. It belongs to the C AES layer and wraps C-level error
codes; mixing it into a C++ shared-types header would blur the C/C++ boundary
that the current design maintains deliberately.

---

## Entry conditions

- All tests pass on the `test` preset before work begins.
- Run `cmake --build build/test` and `ctest --test-dir build/test` and confirm
  zero failures.

---

## Phase 1 — Create `crypto_types.hpp`

### 1.1 New file

Create `core-crypto/include/crypto_types.hpp`:

```cpp
/**
 * @file crypto_types.hpp
 * @brief Shared, stable type definitions used across CipherFortis modules.
 *
 * This header intentionally has no implementation dependencies. It may be
 * included by any module — including hsm-integration — without pulling in
 * the full core-crypto implementation classes.
 */
#ifndef CIPHFORTIS_CRYPTO_TYPES_HPP
#define CIPHFORTIS_CRYPTO_TYPES_HPP

#include <cstdint>

namespace CipherFortis {

/**
 * @brief AES key length in bits.
 *
 * The underlying integer value equals the bit count, so arithmetic such as
 * `static_cast<size_t>(lb) / 8` yields the byte length directly.
 */
enum class KeyLengthBits : unsigned {
    _128 = 128,
    _192 = 192,
    _256 = 256,
};

/**
 * @brief AES block cipher operation mode identifier.
 */
enum class OperationModeID {
    Unknown,
    ECB,  ///< Electronic Code Book (not recommended for most uses).
    CBC,  ///< Cipher Block Chaining.
    OFB,  ///< Output Feedback.
    CTR,  ///< Counter.
};

} // namespace CipherFortis

#endif // CIPHFORTIS_CRYPTO_TYPES_HPP
```

**Design notes:**

- Both enums are defined at namespace scope rather than as nested types. This
  is intentional: the header must have no knowledge of `Key` or `Cipher`, so
  nesting inside those classes is not possible. The names `KeyLengthBits` and
  `OperationModeID` are sufficiently self-describing at namespace scope.
- The `Key::LengthBits` and `Cipher::OperationMode::Identifier` names that
  currently appear throughout the codebase are preserved as type aliases in
  Phase 2, so no call site needs to change.

### 1.2 Exit condition for Phase 1

`crypto_types.hpp` compiles in isolation:

```bash
echo '#include "core-crypto/include/crypto_types.hpp"' | \
  g++ -std=c++17 -Icore-crypto/include -x c++ - -fsyntax-only
```

---

## Phase 2 — Introduce aliases in `key.hpp` and `cipher.hpp`

### 2.1 `key.hpp`

Inside `struct Key`, replace the current nested enum definition with a type
alias and a `static_assert` to confirm the values match:

```cpp
#include "crypto_types.hpp"

struct Key {
    // Preserve the existing nested name so all callsites compile unchanged.
    using LengthBits = CipherFortis::KeyLengthBits;
    // ...rest of Key unchanged...
};
```

The underlying enum definition moves to `crypto_types.hpp`; `Key::LengthBits`
becomes a transparent alias.

### 2.2 `cipher.hpp`

Inside `Cipher::OperationMode`, replace the nested `Identifier` enum definition
with a type alias:

```cpp
#include "crypto_types.hpp"

class Cipher {
public:
    struct OperationMode {
        using Identifier = CipherFortis::OperationModeID;
        // ...rest of OperationMode unchanged...
    };
    // ...
};
```

### 2.3 Exit condition for Phase 2

Full build with zero errors or warnings:

```bash
cmake --build build/test 2>&1 | grep -E "error:|warning:" | wc -l
# Expected: 0
```

---

## Phase 3 — Update `hsm-integration`

### 3.1 `hsm_key_handle.hpp`

Replace the current include of `key.hpp`:

```cpp
// Before
#include "../../core-crypto/include/key.hpp"

// After
#include "../../core-crypto/include/crypto_types.hpp"
```

Update the member type declaration and constructor signature to use
`CipherFortis::KeyLengthBits` directly. Because `Key::LengthBits` is now an
alias for `CipherFortis::KeyLengthBits`, callers that pass `Key::LengthBits`
values remain valid without any change.

### 3.2 `hsm_cipher.hpp` and `hsm_cipher.cpp`

`hsm_cipher.hpp` currently includes `cipher.hpp` to use
`Cipher::OperationMode::Identifier`. After Phase 2 this include can be narrowed:

```cpp
// hsm_cipher.hpp — replace
#include "../../core-crypto/include/cipher.hpp"
// with
#include "../../core-crypto/include/crypto_types.hpp"
```

All references to `Cipher::OperationMode::Identifier` in `hsm_cipher.hpp` and
`hsm_cipher.cpp` become `CipherFortis::OperationModeID`. The alias in
`cipher.hpp` means that any callsite passing a `Cipher::OperationMode::Identifier`
value still compiles correctly because the types are identical.

> **Note:** `hsm_cipher.hpp` will still need to include `encryptor.hpp` for the
> `Encryptor` base class. That dependency is correct and should be kept.

### 3.3 Exit condition for Phase 3

```bash
cmake --build build/test 2>&1 | grep -E "error:|warning:" | wc -l
# Expected: 0
```

---

## Phase 4 — Verify no test changes are required

Run the full suite:

```bash
ctest --test-dir build/test --output-on-failure
```

Because `Key::LengthBits` and `Cipher::OperationMode::Identifier` are preserved
as aliases, no test file should require modification. If any test fails, the
failure indicates a callsite that was relying on something beyond the type
identity (e.g. a forward declaration of the nested enum) and must be corrected
in that test file.

### Master verification checklist

| Check | Command | Expected result |
|---|---|---|
| `crypto_types.hpp` compiles in isolation | see Phase 1.2 | no errors |
| Full build, zero diagnostics | `cmake --build build/test` | exit 0, 0 errors/warnings |
| `test_AES` passes | `ctest -R test_AES` | PASSED |
| `test_cipher` passes | `ctest -R test_cipher` | PASSED |
| `test_key` passes | `ctest -R test_key` | PASSED |
| `test_operation_modes` passes | `ctest -R test_operation_modes` | PASSED |
| `test_padding` passes | `ctest -R test_padding` | PASSED |
| `test_hsmcipher` passes | `ctest -R test_hsmcipher` | PASSED (or SKIPPED if SoftHSM absent) |
| `test_cpp_c_interface` passes | `ctest -R test_cpp_c_interface` | PASSED |
| `test_cli_crypto_config` passes | `ctest -R test_cli_crypto_config` | PASSED |
| `test_image_encryptorcpp` passes | `ctest -R test_image_encryptorcpp` | PASSED |
| `hsm-integration` includes `key.hpp` nowhere | `grep -r "key.hpp" hsm-integration/` | no output |

---

## Deferred / out of scope

- Migrating `ExceptionCode` — remains in the C AES layer deliberately.
- Updating the `testing/` library test vectors, which reference
  `TV::KeySize` and `TV::CipherMode` — these are independent enums in the
  test infrastructure and do not need to alias `crypto_types.hpp`.
- Any CLI-level session-factory pattern — deferred per project decision.

---

## Correction log

_Append entries here if design decisions change during implementation._

| Date | Change | Rationale |
|---|---|---|
| — | — | — |
