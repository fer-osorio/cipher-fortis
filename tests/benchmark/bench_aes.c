#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "operation_modes.h"
#include "key_expansion.h"
#include "constants.h"

#define BENCH_BUFFER_MB   64
#define BENCH_ITERATIONS  5
#define BENCH_BUFFER_SIZE (BENCH_BUFFER_MB * 1024 * 1024)

static double elapsed_seconds(
    struct timespec start,
    struct timespec end
) {
    return (double)(end.tv_sec - start.tv_sec)
         + (double)(end.tv_nsec - start.tv_nsec) * 1e-9;
}

typedef enum ExceptionCode (*bench_fn)(
    const uint8_t *const input,
    size_t size,
    const uint8_t *keyexpansion,
    size_t keylenbits,
    uint8_t *const output
);

typedef enum ExceptionCode (*bench_fn_iv)(
    const uint8_t *const input,
    size_t size,
    const uint8_t *keyexpansion,
    size_t keylenbits,
    const uint8_t *iv,
    uint8_t *const output
);

static void bench_no_iv(
    const char *mode,
    int keybits,
    const char *dir,
    bench_fn fn,
    const uint8_t *input,
    uint8_t *output,
    const uint8_t *ke
) {
    double times[BENCH_ITERATIONS];
    struct timespec t0, t1;

    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        fn(input, BENCH_BUFFER_SIZE, ke, (size_t)keybits, output);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        times[i] = elapsed_seconds(t0, t1);
    }

    double min = times[0], max = times[0], sum = 0.0;
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        if (times[i] < min) min = times[i];
        if (times[i] > max) max = times[i];
        sum += times[i];
    }
    double mean = sum / BENCH_ITERATIONS;

    printf(
        "%-10s %-4d %-6s %10.2f  %10.2f  %10.2f\n",
        mode, keybits, dir,
        (double)BENCH_BUFFER_MB / max,
        (double)BENCH_BUFFER_MB / mean,
        (double)BENCH_BUFFER_MB / min
    );
}

static void bench_with_iv(
    const char *mode,
    int keybits,
    const char *dir,
    bench_fn_iv fn,
    const uint8_t *input,
    uint8_t *output,
    const uint8_t *ke,
    const uint8_t *iv
) {
    double times[BENCH_ITERATIONS];
    struct timespec t0, t1;

    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        fn(input, BENCH_BUFFER_SIZE, ke, (size_t)keybits, iv, output);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        times[i] = elapsed_seconds(t0, t1);
    }

    double min = times[0], max = times[0], sum = 0.0;
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        if (times[i] < min) min = times[i];
        if (times[i] > max) max = times[i];
        sum += times[i];
    }
    double mean = sum / BENCH_ITERATIONS;

    printf(
        "%-10s %-4d %-6s %10.2f  %10.2f  %10.2f\n",
        mode, keybits, dir,
        (double)BENCH_BUFFER_MB / max,
        (double)BENCH_BUFFER_MB / mean,
        (double)BENCH_BUFFER_MB / min
    );
}

int main(void) {
    uint8_t *input  = malloc(BENCH_BUFFER_SIZE);
    uint8_t *output = malloc(BENCH_BUFFER_SIZE);
    if (!input || !output) {
        fprintf(stderr, "Failed to allocate buffers\n");
        free(input);
        free(output);
        return 1;
    }

    srand((unsigned)time(NULL));
    for (size_t i = 0; i < BENCH_BUFFER_SIZE; i++) {
        input[i] = (uint8_t)(rand() & 0xFF);
    }

    static const uint8_t iv[BLOCK_SIZE] = {0};

    printf(
        "%-10s %-4s %-6s %10s  %10s  %10s\n",
        "Mode", "Key", "Dir", "Min(MB/s)", "Mean(MB/s)", "Max(MB/s)"
    );
    printf(
        "---------- ---- ------ ----------  ----------  ----------\n"
    );

    static const int key_lengths[] = {128, 192, 256};
    static const size_t ke_sizes[] = {
        KEY_EXPANSION_LENGTH_128_BYTES,
        KEY_EXPANSION_LENGTH_192_BYTES,
        KEY_EXPANSION_LENGTH_256_BYTES
    };
    static const size_t key_byte_lengths[] = {16, 24, 32};

    uint8_t ke[KEY_EXPANSION_LENGTH_256_BYTES];

    for (int ki = 0; ki < 3; ki++) {
        int keybits          = key_lengths[ki];
        size_t ke_size       = ke_sizes[ki];
        size_t key_bytes_len = key_byte_lengths[ki];

        uint8_t key[32];
        for (size_t b = 0; b < key_bytes_len; b++) {
            key[b] = (uint8_t)b;
        }

        memset(ke, 0, sizeof(ke));
        KeyExpansionInitWrite(key, (size_t)keybits, ke, false);
        (void)ke_size;

        bench_no_iv(
            "ECB", keybits, "enc",
            encryptECB, input, output, ke
        );
        bench_no_iv(
            "ECB", keybits, "dec",
            decryptECB, input, output, ke
        );
        bench_with_iv(
            "CBC", keybits, "enc",
            encryptCBC, input, output, ke, iv
        );
        bench_with_iv(
            "CBC", keybits, "dec",
            decryptCBC, input, output, ke, iv
        );
        bench_with_iv(
            "OFB", keybits, "enc",
            encryptOFB, input, output, ke, iv
        );
        bench_with_iv(
            "OFB", keybits, "dec",
            decryptOFB, input, output, ke, iv
        );
        bench_with_iv(
            "CTR", keybits, "enc",
            encryptCTR, input, output, ke, iv
        );
        bench_with_iv(
            "CTR", keybits, "dec",
            decryptCTR, input, output, ke, iv
        );
    }

    free(input);
    free(output);
    return 0;
}
