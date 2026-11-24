/*
 * ConvertLIT container-path fuzzing harness - AFL++ persistent mode.
 *
 * Drives lit_read_from_file() through a stubbed readat(). The stub mirrors
 * clit.c's own readat() semantics exactly: malloc + zero fill, and a short
 * read at EOF is NOT treated as an error. That fidelity matters - a stricter
 * stub would reject inputs the real tool accepts.
 *
 * Build:
 *   afl-clang-fast -g -O1 -fsanitize=address -funsigned-char -Wno-everything \
 *     -I lib -I lib/des -I lib/sha -I lib/newlzx \
 *     -o fuzz_lit harness/fuzz_lit.c lib/openclit.a
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>

#include "litlib.h"

/* called by the library. clit.c comment: "Must not be static, linked into litlib" */
void lit_error(int what, char *fmt, ...)
{
    (void)what;
    (void)fmt;
    /* silent while fuzzing; stderr output only costs throughput */
}

typedef struct {
    const uint8_t *data;
    uint32_t       len;
} membuf;

/*
 * Same ownership and boundary semantics as clit.c's readat:
 *   - malloc here, caller frees
 *   - zero the whole buffer, then copy as much as is available
 *   - reading past EOF is NOT an error (a zero-padded buffer is returned)
 */
static U8 *mem_readat(void *v, U32 offset, int size)
{
    membuf *b = (membuf *)v;
    U8 *mem;

    if (size <= 0)
        return NULL;

    mem = (U8 *)malloc((size_t)size);
    if (!mem)
        return NULL;
    memset(mem, 0, (size_t)size);

    if (offset < b->len) {
        uint32_t avail = b->len - offset;
        size_t   n = ((uint32_t)size < avail) ? (size_t)size : (size_t)avail;
        memcpy(mem, b->data + offset, n);
    }
    return mem;
}

static void run_one(const uint8_t *data, size_t len)
{
    lit_file lit;
    membuf   b;

    if (len < 8 || len > (8u << 20))
        return;

    memset(&lit, 0, sizeof(lit));
    b.data = data;
    b.len  = (uint32_t)len;

    lit.file_pointer  = &b;
    lit.readat        = mem_readat;
    lit.writeat       = NULL;
    lit.drm5_callback = NULL;      /* DRM5 path needs libtommath; disabled here */
    lit.drm5_data     = NULL;
    lit.filesize      = (uint32_t)len;

    /* exercises headers -> directory -> sections -> LZX decompression */
    if (lit_read_from_file(&lit) == 0) {
        manifest_type manifest;
        memset(&manifest, 0, sizeof(manifest));
        if (lit_read_manifest(&lit, &manifest) == 0)
            lit_free_manifest(&manifest);
    }

    lit_close(&lit);
}

#ifdef FUZZ_STANDALONE
/* single-shot mode for crash reproduction and triage */
int main(int argc, char **argv)
{
    FILE *f;
    long  sz;
    uint8_t *buf;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <lit_file>\n", argv[0]);
        return 1;
    }
    f = fopen(argv[1], "rb");
    if (!f)
        return 1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (8L << 20)) {
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
/* AFL++ persistent mode: loops without forking, which raises throughput a lot */
__AFL_FUZZ_INIT();

int main(void)
{
    unsigned char *buf;
    int len;

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        len = __AFL_FUZZ_TESTCASE_LEN;
        run_one(buf, (size_t)len);
    }
    return 0;
}
#endif
