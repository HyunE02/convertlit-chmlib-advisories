/*
 * ConvertLIT HTML reconstitution harness - AFL++ persistent mode.
 *
 * Why a direct call: driving the container path (lit_read_from_file) never
 * reached litembiggen.c (770 lines) or littags.c (1030 lines), because AFL
 * cannot synthesise a valid directory and section layout - 270 million
 * executions produced zero new coverage there. The public API takes a raw
 * buffer, so calling it directly covers those ~1800 lines immediately.
 *
 * Target (lib/litlib.h):
 *   int lit_reconstitute_html(U8 *pHtml, int base, int nBytes, int html_type,
 *                             manifest_type *pManifest, lit_atom_list *pCustomTags,
 *                             HTMLWRITEFCN htmlwrite, void *writedata);
 *
 * Called the same way the real consumer does (clit18/explode.c:517,524).
 * pAtoms stays NULL - litembiggen.c:314 checks it. pManifest must not be NULL
 * because it is passed on to lit_lookup_mapping(), so a zeroed struct is used.
 *
 * Input layout:
 *   [0]    html_type (0 = XHTML, 1 = HTML)
 *   [1..]  the blob to reconstitute
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "litlib.h"

/* called by the library (clit.c: "Must not be static, linked into litlib") */
void lit_error(int what, char *fmt, ...)
{
    (void)what;
    (void)fmt;
}

/* HTMLWRITEFCN: int (*)(void *, U8 *, int) - output is discarded */
static int sink(void *data, U8 *p, int n)
{
    (void)data;
    (void)p;
    return n;
}

static void run_one(const uint8_t *data, size_t len)
{
    manifest_type manifest;
    U8 *buf;
    int html_type, nbytes;

    if (len < 4 || len > (1u << 20))
        return;

    html_type = data[0] & 1;
    nbytes    = (int)(len - 1);

    /* the function walks the buffer in place, so hand it a copy */
    buf = (U8 *)malloc((size_t)nbytes);
    if (!buf)
        return;
    memcpy(buf, data + 1, (size_t)nbytes);

    memset(&manifest, 0, sizeof(manifest));

    lit_reconstitute_html(buf, 0, nbytes, html_type,
                          &manifest, NULL, sink, NULL);

    free(buf);
}

#ifdef FUZZ_STANDALONE
int main(int argc, char **argv)
{
    FILE *f;
    long sz;
    uint8_t *b;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <blob>\n", argv[0]);
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
    b = (uint8_t *)malloc((size_t)sz);
    if (!b) {
        fclose(f);
        return 1;
    }
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) {
        free(b);
        fclose(f);
        return 1;
    }
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
