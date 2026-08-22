/*
 * fuzz_harness.c — libFuzzer harness for the Week 11 vulnerable routine
 * ====================================================================
 * Sandbox/teaching only; for authorized lab use.
 *
 * Coverage-guided fuzzers (libFuzzer/AFL++) repeatedly call one entry point
 * with mutated input and watch for crashes. We feed the fuzzer's bytes into the
 * SAME vulnerable parsing routine that vuln.c exploits (CWE-121 strcpy overflow),
 * so a crash here == the bug the exploit targets.
 *
 * Why is the routine copied below instead of #included from vuln.c?
 *   vuln.c defines its own main()/win(); libFuzzer supplies its own main().
 *   Linking both would clash. So we keep an EXACT copy of parse_input() here.
 *   If you change the bug in vuln.c, change it here too (they must stay identical).
 *
 * Build + run (AddressSanitizer pinpoints the overflow; libFuzzer drives it):
 *   clang -g -fsanitize=address,fuzzer fuzz_harness.c -o fuzz
 *   ./fuzz                 # fuzz until it finds a crashing input
 *   ./fuzz -runs=100000    # bounded run
 *   ./fuzz crash-<hash>    # replay a saved crashing input
 *
 * Expected result: ASan reports a stack-buffer-overflow inside parse_input()
 * within seconds, and writes the offending input to a crash-* file.
 */

#include <stdint.h>   /* uint8_t            */
#include <stddef.h>   /* size_t             */
#include <string.h>   /* strcpy, memcpy     */

/* ---- EXACT COPY of the vulnerable routine from vuln.c (CWE-121) ---------- */
static int parse_input(const char *src) {
    char buf[64];          /* small fixed-size stack buffer            */
    strcpy(buf, src);      /* CWE-121: no bounds check -> overflow     */
    return (int)strlen(buf);
}

/*
 * libFuzzer calls this once per generated input. We must turn the raw,
 * NOT-necessarily-NUL-terminated byte buffer into a C string before handing it
 * to the strcpy-based routine, so we copy into a local, oversized, terminated
 * buffer first. (The oversized copy is safe; the BUG lives inside parse_input.)
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char tmp[4096];

    /* Bound the copy to our scratch buffer and always NUL-terminate. */
    size_t n = size < sizeof(tmp) - 1 ? size : sizeof(tmp) - 1;
    memcpy(tmp, data, n);
    tmp[n] = '\0';

    parse_input(tmp);   /* overflows buf[64] when n >= 64 -> ASan fires */
    return 0;           /* libFuzzer requires 0 */
}
