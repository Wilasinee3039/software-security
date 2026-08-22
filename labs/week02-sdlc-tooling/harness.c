/* Week 2 — Fuzzing intro (10-min mini-lab). Sandbox/teaching only.
 *
 * A minimal libFuzzer target with ONE planted memory-safety bug so you can see a
 * coverage-guided fuzzer *discover* a crash that SAST/linters miss. The bug is a
 * classic missing bound check: when the input is exactly "FUZ" (size == 3), the
 * data[3] read runs one byte past the buffer -> AddressSanitizer reports a
 * heap-buffer-overflow. libFuzzer mutates inputs toward the magic bytes on its own.
 *
 * Build + run in the labs/toolbox container (Apple clang has no libFuzzer):
 *   clang -g -fsanitize=address,fuzzer harness.c -o fuzz && ./fuzz
 * Expect: within a second, "ERROR: AddressSanitizer: heap-buffer-overflow" and a
 * crash- reproducer file. That crash is the deliverable for worksheet Task 4.
 *
 * The deeper, exploit-focused fuzzing lab is Week 11 (labs/week11-memory-safety-exploitation).
 */
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'F')
        if (size > 1 && data[1] == 'U')
            if (size > 2 && data[2] == 'Z')
                if (data[3] == 'Z')   /* BUG: no `size > 3` check -> reads data[3] out of bounds */
                    __builtin_trap();  /* and aborts once the full magic "FUZZ" is reached */
    return 0;
}
