/*
 * LZX decompressor harness - AFL++ persistent mode.
 *
 * One source targets two implementations that share API names:
 *   - CHMLib      src/lzx.c
 *   - ConvertLIT  lib/lzx/lzx.c   (legacy; NOT built by the upstream Makefile)
 *
 * Calling the decompressor directly avoids having to satisfy a CHM or LIT
 * container, so the Huffman trees, position-slot tables and window handling
 * are covered immediately.
 *
 * Input layout (first 4 bytes are parameters):
 *   [0]    window: mapped to 15..21 (LZX window size 2^window)
 *   [1..2] outlen: LE u16, clamped
 *   [3]    unused (alignment)
 *   [4..]  compressed data
 *
 * Point of interest in lzx.c:
 *     match_offset = position_base[match_offset] - 2 + verbatim_bits;
 *     ...
 *     runsrc = rundest - match_offset;
 *     while ((runsrc < window) && (match_length-- > 0))
 *         *rundest++ = *(runsrc + window_size);
 *   If match_offset exceeds window_size, "runsrc + window_size" reads ahead
 *   of the window.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lzx.h"

#define MAX_OUT (1 << 20)

static void run_one(const uint8_t *data, size_t len)
{
    struct LZXstate *st;
    unsigned char *out;
    int window, outlen, inlen;

    if (len < 8 || len > (1u << 20))
        return;

    /* window size: LZX uses 15..21 bits */
    window = 15 + (data[0] % 7);
    outlen = (int)(data[1] | (data[2] << 8));
    if (outlen <= 0)
        outlen = 4096;
    if (outlen > MAX_OUT)
        outlen = MAX_OUT;

    inlen = (int)(len - 4);

    st = LZXinit(window);
    if (!st)
        return;

    out = (unsigned char *)malloc((size_t)outlen);
    if (!out) {
        LZXteardown(st);
        return;
    }

    /* call twice on the same state to cover reset and continuation paths */
    LZXdecompress(st, (unsigned char *)(data + 4), out, inlen, outlen);
    LZXreset(st);
    LZXdecompress(st, (unsigned char *)(data + 4), out, inlen, outlen);

    free(out);
    LZXteardown(st);
}

#ifdef FUZZ_STANDALONE
int main(int argc, char **argv)
{
    FILE *f;
    long sz;
    uint8_t *buf;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <lzx_blob>\n", argv[0]);
        return 1;
    }
    f = fopen(argv[1], "rb");
    if (!f)
        return 1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (1L << 20)) {
        fclose(f);
        return 1;
    }
    buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);
    run_one(buf, (size_t)sz);
    free(buf);
    return 0;
}
#else
__AFL_FUZZ_INIT();

int main(void)
{
    unsigned char *buf;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        run_one(buf, (size_t)len);
    }
    return 0;
}
#endif
