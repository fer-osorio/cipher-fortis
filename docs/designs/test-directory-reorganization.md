# Test Directory Reorganization — Design Document

**Project:** CipherFortis
**Scope:** `tests/` directory structure
**Status:** Implemented

---

## 1. Current Structure

```
tests/
├── include/                        ← flat, mixed-concern header pool
│   ├── asset_factory.hpp           #   system-test scaffolding
│   ├── binary_asset_factory.hpp    #   system-test scaffolding
│   ├── bitmap_asset_factory.hpp    #   system-test scaffolding
│   ├── jpeg_asset_factory.hpp      #   system-test scaffolding
│   ├── png_asset_factory.hpp       #   system-test scaffolding
│   ├── text_asset_factory.hpp      #   system-test scaffolding
│   ├── system_workflows.hpp        #   system-test scaffolding
│   ├── file_base_fixture.hpp       #   unit-tier fixture
│   ├── raster_image_fixture.hpp    #   unit-tier fixture (+ misused static helper)
│   ├── file_write_utils.hpp        #   shared infrastructure
│   ├── raster_asset_utils.hpp      #   shared infrastructure
│   └── test_environment.hpp        #   shared infrastructure
├── src/                            ← flat mirror of include/
│   ├── asset_factory.cpp
│   ├── binary_asset_factory.cpp
│   ├── bitmap_asset_factory.cpp
│   ├── jpeg_asset_factory.cpp
│   ├── png_asset_factory.cpp
│   ├── text_asset_factory.cpp
│   ├── system_workflows.cpp
│   ├── file_base_fixture.cpp
│   ├── raster_asset_utils.cpp
│   ├── raster_image_fixture.cpp
│   ├── file_write_utils.cpp
│   └── test_environment.cpp
├── unit/
│   ├── test_AES.cpp
│   ├── test_cipher.cpp
│   ├── test_file_base.cpp
│   ├── test_hsmcipher.cpp
│   ├── test_key.cpp
│   ├── test_operation_modes.cpp
│   ├── test_padding.cpp
│   └── test_raster_image.cpp
├── integration/
│   ├── test_cli_crypto_config.cpp
│   └── test_cpp_c_interface.cpp
├── system/
│   └── test_image_encryptorcpp.cpp
├── benchmark/
│   └── bench_aes.c
├── test-files/
├── data/
└── CMakeLists.txt
```

---

## 2. Target Structure

```
tests/
├── support/                        ← infrastructure shared across two or more tiers
│   ├── include/
│   │   ├── test_environment.hpp
│   │   ├── file_write_utils.hpp
│   │   └── raster_asset_utils.hpp
│   └── src/
│       ├── test_environment.cpp
│       ├── file_write_utils.cpp
│       └── raster_asset_utils.cpp
├── unit/
│   ├── fixtures/                   ← fixtures co-located with the tier that owns them
│   │   ├── file_base_fixture.hpp
│   │   ├── file_base_fixture.cpp
│   │   ├── raster_image_fixture.hpp
│   │   └── raster_image_fixture.cpp
│   ├── test_AES.cpp
│   ├── test_cipher.cpp
│   ├── test_file_base.cpp
│   ├── test_hsmcipher.cpp
│   ├── test_key.cpp
│   ├── test_operation_modes.cpp
│   ├── test_padding.cpp
│   └── test_raster_image.cpp
├── integration/
│   ├── test_cli_crypto_config.cpp
│   └── test_cpp_c_interface.cpp
├── system/
│   ├── support/                    ← system-test scaffolding, not shared elsewhere
│   │   ├── include/
│   │   │   ├── asset_factory.hpp
│   │   │   ├── binary_asset_factory.hpp
│   │   │   ├── bitmap_asset_factory.hpp
│   │   │   ├── jpeg_asset_factory.hpp
│   │   │   ├── png_asset_factory.hpp
│   │   │   ├── text_asset_factory.hpp
│   │   │   └── system_workflows.hpp
│   │   └── src/
│   │       ├── asset_factory.cpp
│   │       ├── binary_asset_factory.cpp
│   │       ├── bitmap_asset_factory.cpp
│   │       ├── jpeg_asset_factory.cpp
│   │       ├── png_asset_factory.cpp
│   │       ├── text_asset_factory.cpp
│   │       └── system_workflows.cpp
│   └── test_image_encryptorcpp.cpp
├── benchmark/
│   └── bench_aes.c
├── test-files/
├── data/
└── CMakeLists.txt
```

---

## 3. Motivation

### 3.1 Problem: flat `include/src` conflates three distinct roles

All support files currently share a single flat `include/src` pool regardless of their
actual scope of use. Inspection reveals three categories with very different ownership:

| Category | Files | Actual consumers |
|---|---|---|
| Shared infrastructure | `TestEnvironment`, `file_write_utils`, `raster_asset_utils` | unit fixtures + system scaffolding |
| Unit-tier fixtures | `FileBaseFixture`, `RasterImageFixture` | `unit/` only |
| System-test scaffolding | `AssetFactory` hierarchy, `SystemTests` | `system/` only |

Placing all three in the same directory implies a symmetry of scope that does not exist,
making the structure misleading to anyone navigating the repository.

### 3.2 Design principle violated: proximity rule

Infrastructure should live as close as possible to the tier that owns it and be promoted
upward only when a second tier genuinely requires it. The current layout promotes
everything unconditionally.

### 3.3 Secondary smell: fixture misused as utility

`RasterImageFixture::createValidJpeg()` is a `static` method called from
`system_workflows.cpp` — a gtest fixture acting as a general-purpose factory outside
its own test tier. The responsibility already belongs in `raster_asset_utils`, which
exists for exactly that purpose.

---

## 4. Migration Path

The migration is low-risk: it is purely a file-move and include-path update with no
logic changes.

### Step 1 — Resolve the fixture/utility coupling (prerequisite)

Move `RasterImageFixture::createValidJpeg/Bmp/Png` static methods into
`TestUtils::Raster` (`raster_asset_utils`), where equivalent helpers already exist.
Update the single call site in `system_workflows.cpp`. Remove the static methods from
the fixture class. This eliminates the only cross-tier coupling before files are moved.

### Step 2 — Create the new directory skeleton

```
tests/support/include/
tests/support/src/
tests/unit/fixtures/
tests/system/support/include/
tests/system/support/src/
```

### Step 3 — Relocate files

| From | To |
|---|---|
| `include/test_environment.hpp` + `src/test_environment.cpp` | `support/` |
| `include/file_write_utils.hpp` + `src/file_write_utils.cpp` | `support/` |
| `include/raster_asset_utils.hpp` + `src/raster_asset_utils.cpp` | `support/` |
| `include/file_base_fixture.hpp` + `src/file_base_fixture.cpp` | `unit/fixtures/` |
| `include/raster_image_fixture.hpp` + `src/raster_image_fixture.cpp` | `unit/fixtures/` |
| `include/asset_factory.hpp` + `src/asset_factory.cpp` (+ all concrete subclasses) | `system/support/` |
| `include/system_workflows.hpp` + `src/system_workflows.cpp` | `system/support/` |

### Step 4 — Update `#include` paths

Adjust include directives in all affected translation units to reflect the new relative
paths. No API changes are required.

### Step 5 — Update `CMakeLists.txt`

Replace the single `ciphfortis_test_fixtures` library with three scoped targets:

| Target | Sources | Links |
|---|---|---|
| `ciphfortis_test_support` | `support/src/*.cpp` | `ciphfortis_files`, `GTest::gtest`, `third_party_stb` |
| `ciphfortis_unit_fixtures` | `unit/fixtures/*.cpp` | `ciphfortis_test_support` |
| `ciphfortis_system_support` | `system/support/src/*.cpp` | `ciphfortis_test_support` |

### Step 6 — Remove vacated directories

Delete the now-empty `tests/include/` and `tests/src/` trees.

### Step 7 — Verify

Full test suite green. No changes to test names, test logic, or production code.
