/*
 * ConvertLIT lit_read_manifest() harness - AFL++ persistent mode.
 *
 * litmanifest.c and litutil.c are not modified. The whole manifest buffer
 * comes from lit_get_file(), so that single function is stubbed. It allocates
 * exactly the input length, which makes pEnd coincide with the allocation end
 * so a one-byte overread hits the ASan redzone immediately.
 *
 * Target (lib/litutil.c:117-139, lit_i_utf8_len_to_bytes):
 *     while (nchars < lenSrc) {
 *         if ((*(src + nbytes) & 0xC0) != 0x80) nchars++;   -- read first
 *         nbytes++;
 *         if (nbytes > sizeSrc) { return -1; }               -- check after
 *     }
 *     while (( *(src + nbytes) & 0xC0) == 0x80) {           -- read first
 *         nbytes++;
 *         if (nbytes > sizeSrc) { return -1; }
 *     }
 *
 * The caller passes src = p+1 and sizeSrc = (pEnd-p)-1, so src[sizeSrc] is
 * exactly *pEnd - one byte past the end of the manifest buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "litlib.h"

void lit_error(int what, char *fmt, ...) { (void)what; (void)fmt; }

static const uint8_t *g_data;
static size_t         g_len;

int lit_get_file(lit_file *litfile, const char *name, U8 **ptr, int *psize)
{
    (void)litfile; (void)name;
    if (!ptr || !psize) return 0;
    /* allocate exactly the input length so pEnd lands on the allocation end */
    *ptr = (U8 *)malloc(g_len);
    if (!*ptr) return -1;
    memcpy(*ptr, g_data, g_len);
    *psize = (int)g_len;
    return 0;
}

static void run_one(const uint8_t *data, size_t len)
{
    lit_file lit;
    manifest_type manifest;

    if (len < 8 || len > (1u << 20))
        return;

    g_data = data;
    g_len  = len;

    memset(&lit, 0, sizeof(lit));
    memset(&manifest, 0, sizeof(manifest));
    lit_read_manifest(&lit, &manifest);
    lit_free_manifest(&manifest);
}

#ifdef FUZZ_STANDALONE
int main(int argc, char **argv)
{
    FILE *f; long sz; uint8_t *b;
    if (argc < 2) { fprintf(stderr, "usage: %s <blob>\n", argv[0]); return 1; }
    f = fopen(argv[1], "rb"); if (!f) return 1;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (1L << 20)) { fclose(f); return 1; }
    b = (uint8_t *)malloc((size_t)sz); if (!b) { fclose(f); return 1; }
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); fclose(f); return 1; }
    fclose(f);
    run_one(b, (size_t)sz);
    free(b);
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
