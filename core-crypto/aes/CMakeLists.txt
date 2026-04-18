add_library(ciphfortis_aes STATIC
    src/AES.c
    src/block.c
    src/constants.c
    src/key_expansion.c
    src/operation_modes.c
)
target_include_directories(ciphfortis_aes
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(ciphfortis_aes
    PRIVATE ciphfortis::compile_options_c
)

# AES-NI hardware acceleration (x86 only)
include(CheckCCompilerFlag)
check_c_compiler_flag("-maes" CF_COMPILER_SUPPORTS_AES)
option(CF_ENABLE_AESNI
    "Enable AES-NI hardware-accelerated block cipher path"
    ${CF_COMPILER_SUPPORTS_AES}
)
if(CF_ENABLE_AESNI)
    target_sources(ciphfortis_aes PRIVATE src/aes_ni.c)
    set_source_files_properties(src/aes_ni.c PROPERTIES
        COMPILE_FLAGS "-maes -mssse3 -fno-lto"
    )
    target_compile_definitions(ciphfortis_aes PRIVATE CF_ENABLE_AESNI)
    message(STATUS "AES-NI acceleration: enabled")
else()
    message(STATUS "AES-NI acceleration: disabled")
endif()

set_source_files_properties(src/key_expansion.c PROPERTIES
    COMPILE_FLAGS "-fno-lto"
)
