option(CF_BUILD_BENCHMARKS "Build AES throughput benchmark (off by default)" OFF)

# ── Shared test infrastructure ────────────────────────────────────────────────
add_library(ciphfortis_test_support STATIC
    support/src/test_environment.cpp
    support/src/file_write_utils.cpp
    support/src/raster_asset_utils.cpp
)
target_include_directories(ciphfortis_test_support PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/support/include
)
target_link_libraries(ciphfortis_test_support
    PUBLIC  ciphfortis_files ciphfortis_core ciphfortis_aes
            ciphfortis_analysis ciphfortis_testing GTest::gtest
    PRIVATE ciphfortis::compile_options third_party_stb
)

# ── Unit test fixtures ────────────────────────────────────────────────────────
add_library(ciphfortis_unit_fixtures STATIC
    unit/fixtures/file_base_fixture.cpp
    unit/fixtures/raster_image_fixture.cpp
)
target_include_directories(ciphfortis_unit_fixtures PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/unit/fixtures
)
target_link_libraries(ciphfortis_unit_fixtures
    PUBLIC  ciphfortis_test_support
    PRIVATE ciphfortis::compile_options
)

# ── System test scaffolding ───────────────────────────────────────────────────
add_library(ciphfortis_system_support STATIC
    system/support/src/asset_factory.cpp
    system/support/src/binary_asset_factory.cpp
    system/support/src/bitmap_asset_factory.cpp
    system/support/src/jpeg_asset_factory.cpp
    system/support/src/png_asset_factory.cpp
    system/support/src/text_asset_factory.cpp
    system/support/src/system_workflows.cpp
)
target_include_directories(ciphfortis_system_support PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/system/support/include
)
target_link_libraries(ciphfortis_system_support
    PUBLIC  ciphfortis_test_support
    PRIVATE ciphfortis::compile_options
)

# ── Helper function ───────────────────────────────────────────────────────────
function(add_ciphfortis_test)
    cmake_parse_arguments(ARG "" "NAME;LABEL" "SOURCES;EXTRA_LIBS" ${ARGN})

    add_executable(${ARG_NAME} ${ARG_SOURCES})
    target_link_libraries(${ARG_NAME} PRIVATE
        ciphfortis_testing GTest::gtest_main
        ciphfortis::compile_options
        ${ARG_EXTRA_LIBS}
    )
    set_target_properties(${ARG_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY
            ${CMAKE_BINARY_DIR}/tests/bin/${ARG_LABEL}
    )
    gtest_discover_tests(${ARG_NAME}
        PROPERTIES
            LABELS            ${ARG_LABEL}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tests
    )
endfunction()

# ── Unit tests ────────────────────────────────────────────────────────────────
add_ciphfortis_test(NAME test_AES              SOURCES unit/test_AES.cpp
    LABEL unit EXTRA_LIBS ciphfortis_aes)
add_ciphfortis_test(NAME test_cipher           SOURCES unit/test_cipher.cpp
    LABEL unit EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_key              SOURCES unit/test_key.cpp
    LABEL unit EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_operation_modes  SOURCES unit/test_operation_modes.cpp
    LABEL unit EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_file_base        SOURCES unit/test_file_base.cpp
    LABEL unit
    EXTRA_LIBS ciphfortis_files ciphfortis_core ciphfortis_aes
               ciphfortis_analysis ciphfortis_unit_fixtures)
add_ciphfortis_test(NAME test_raster_image     SOURCES unit/test_raster_image.cpp
    LABEL unit
    EXTRA_LIBS ciphfortis_files ciphfortis_core ciphfortis_aes
               ciphfortis_analysis ciphfortis_unit_fixtures)
add_ciphfortis_test(NAME test_padding          SOURCES unit/test_padding.cpp
    LABEL unit EXTRA_LIBS ciphfortis_core ciphfortis_aes)

if(TARGET ciphfortis_hsm)
    add_ciphfortis_test(NAME test_hsmcipher    SOURCES unit/test_hsmcipher.cpp
        LABEL unit
        EXTRA_LIBS ciphfortis_hsm ciphfortis_core ciphfortis_aes ${CMAKE_DL_LIBS})
endif()

# ── Integration tests ─────────────────────────────────────────────────────────
add_ciphfortis_test(NAME test_cpp_c_interface    SOURCES integration/test_cpp_c_interface.cpp
    LABEL integration EXTRA_LIBS ciphfortis_core ciphfortis_aes)
add_ciphfortis_test(NAME test_cli_crypto_config  SOURCES integration/test_cli_crypto_config.cpp
    LABEL integration EXTRA_LIBS ciphfortis_cli ciphfortis_core ciphfortis_aes)

# ── System tests ──────────────────────────────────────────────────────────────
add_ciphfortis_test(NAME test_image_encryptorcpp SOURCES system/test_image_encryptorcpp.cpp
    LABEL system
    EXTRA_LIBS ciphfortis_files ciphfortis_core ciphfortis_aes
               ciphfortis_analysis ciphfortis_system_support)
target_compile_definitions(test_image_encryptorcpp PRIVATE
    IMAGE_ENCRYPTOR_PATH="$<TARGET_FILE:image-encryptor>"
)

# ── Convenience targets ───────────────────────────────────────────────────────
add_custom_target(run-unit
    COMMAND ${CMAKE_CTEST_COMMAND} -L unit --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_target(run-integration
    COMMAND ${CMAKE_CTEST_COMMAND} -L integration --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_custom_target(run-system
    COMMAND ${CMAKE_CTEST_COMMAND} -L system --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

# ── Benchmark harness ─────────────────────────────────────────────────────────
if(CF_BUILD_BENCHMARKS)
    add_executable(bench_aes benchmark/bench_aes.c)
    target_include_directories(bench_aes PRIVATE
        ${CMAKE_SOURCE_DIR}/core-crypto/aes/include
    )
    target_link_libraries(bench_aes PRIVATE
        ciphfortis_aes
        ciphfortis::compile_options_c
    )
    set_target_properties(bench_aes PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY
            ${CMAKE_BINARY_DIR}/tests/bin/benchmark
    )
endif()
