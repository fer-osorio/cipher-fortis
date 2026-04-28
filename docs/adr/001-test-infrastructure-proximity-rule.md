# ADR 001 — Test infrastructure organized by proximity rule

## Status

Accepted

## Context

The `tests/` directory previously used a single flat `include/src` pair for all test
support code, regardless of which test tier actually consumed it. This caused three
distinct categories of code to share one bucket:

- **Shared infrastructure** (`TestEnvironment`, `file_write_utils`, `raster_asset_utils`)
  — used by both unit fixtures and system scaffolding.
- **Unit-tier fixtures** (`FileBaseFixture`, `RasterImageFixture`) — consumed exclusively
  by `tests/unit/`.
- **System-test scaffolding** (`AssetFactory` hierarchy, `SystemTests`,
  `system_workflows`) — consumed exclusively by `tests/system/`.

The flat layout implied that all three categories were equally broad in scope, which was
misleading. It also produced a concrete design smell: `system_workflows.cpp` called
`RasterImageFixture::createValidJpeg()` — a `public static` method on a gtest fixture —
as a general-purpose image factory, creating a cross-tier dependency from system code
into a unit-tier fixture class.

## Decision

Apply the **proximity rule**: each piece of test infrastructure lives as close as possible
to the tier that owns it, and is promoted to a higher-level directory only when a second
tier genuinely requires it.

The resulting layout is:

```
tests/
├── support/            ← promoted: used by unit fixtures AND system scaffolding
├── unit/
│   └── fixtures/       ← owned by unit tier only
└── system/
    └── support/        ← owned by system tier only
```

This is mirrored in CMake by three scoped static libraries:
`ciphfortis_test_support`, `ciphfortis_unit_fixtures`, `ciphfortis_system_support`.

The design smell is resolved by replacing the call to `RasterImageFixture::createValidJpeg()`
with a direct call to `TestUtils::Raster::make_jpeg()`, which already existed in
`raster_asset_utils` for exactly this purpose. The three `public static` helper methods
are removed from `RasterImageFixture`.

## Consequences

- New test support code must be placed at the lowest tier that needs it; promotion to
  `support/` requires a concrete second consumer, not speculation.
- The monolithic `ciphfortis_test_fixtures` CMake target no longer exists; consumers
  link against the appropriately scoped target instead.
- Unit tests have no transitive dependency on system-tier scaffolding.
- The gtest fixture classes (`FileBaseFixture`, `RasterImageFixture`) no longer expose
  public static factory methods; callers outside the unit tier use `TestUtils::Raster`
  and `TestUtils::IO` directly.
