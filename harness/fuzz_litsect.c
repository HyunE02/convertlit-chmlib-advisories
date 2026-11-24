/*
 * ConvertLIT decompress_section() harness - AFL++ persistent mode.
 *
 * litsections.c is not modified. decompress_section() receives the control
 * block and the content directly as arguments, so only lit_get_file() - which
 * supplies the reset table - needs stubbing to reach this code without a
 * container.
 *
 *   int decompress_section(lit_file *litfile, char *section_name,
 *       U8 *pControl, int sizeControl, U8 *pContent, int sizeContent,
 *       U8 **ppUncompressed, int *psizeUncompressed);
 *
 * Target (lib/litsections.c:364-376):
 *     uclength = READ_INT32(pRT + RESET_UCLENGTH);   -- signed int, unbounded
 *     ptr = malloc(uclength+1);
 *     ptr[uclength] = 0xCC;                           -- dereference BEFORE the
 *     if (!ptr) { ... }                               -- NULL check
 *
 * READ_INT32 masks the sign bit, so uclength lands in [0, INT_MAX]. At INT_MAX
 * the expression uclength+1 overflows to INT_MIN, sign-extends to
 * 0xFFFFFFFF80000000 as the size_t argument, the allocation fails, and the
 * store targets address uclength.
 *
 * Preconditions to satisfy:
 *   sizeControl >= 32, READ_U32(pControl+4) == 'LZXC',
 *   READ_U32(pControl+12) must map to a window of 15..21,
 *   sizeRT >= 40, READ_U32(pRT+20) == 0 (high half of UCLENGTH)
 *
 * Input layout:
 *   [0]      window selector (mapped to 1..127)
 *   [1..2]   reset-table length (LE u16, clamped to [40, remaining])
 *   [3]      unused
 *   [4..]    reset table, then the rest is content
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "litlib.h"
#include "litinternal.h"

/*
 * decompress_section() has internal linkage: the forward declaration at
 * litsections.c:36 is static. It therefore cannot be linked externally, so the
 * UNMODIFIED source is included here to call it from the same translation unit.
 */
#include "../pristine/lib/litsections.c"

/* ---- stubs: only the external symbols litsections.c references ---- */
void lit_error(int what, char *fmt, ...) { (void)what; (void)fmt; }

char *lit_i_strmerge(const char *first, ...)
{
    char *p = (char *)malloc(16);
    if (p) strcpy(p, "/ResetTable");
    return p;
}

int lit_i_encrypt(U8 *p, int n, U8 *k) { (void)p; (void)n; (void)k; return 0; }
int lit_i_decrypt(lit_file *l, U8 *p, int n) { (void)l; (void)p; (void)n; return 0; }
int lit_put_file(lit_file *l, const char *n, U8 *p, int s, int c)
{ (void)l; (void)n; (void)p; (void)s; (void)c; return 0; }

/* the reset table carved out of the fuzz input, returned by lit_get_file */
static const uint8_t *g_rt;
static int            g_rt_len;

int lit_get_file(lit_file *litfile, const char *name, U8 **ptr, int *psize)
{
    (void)litfile; (void)name;
    if (!ptr || !psize) return 0;
    *ptr = (U8 *)malloc((size_t)g_rt_len);
    if (!*ptr) return -1;
    memcpy(*ptr, g_rt, (size_t)g_rt_len);
    *psize = g_rt_len;
    return 0;
}

static void run_one(const uint8_t *data, size_t len)
{
    lit_file lit;
    U8 control[32];
    U8 *pUC = NULL;
    int sizeUC = 0, rt_len, content_len;
    unsigned win;

    if (len < 4 + 40 + 1 || len > (1u << 20))
        return;

    /* synthesise a control block that passes the preconditions */
    memset(control, 0, sizeof(control));
    control[4] = (U8)(LZXC_TAG & 0xFF);
    control[5] = (U8)((LZXC_TAG >> 8) & 0xFF);
    control[6] = (U8)((LZXC_TAG >> 16) & 0xFF);
    control[7] = (U8)((LZXC_TAG >> 24) & 0xFF);
    win = (unsigned)(data[0] & 0x7F);
    if (!win) win = 1;                      /* window_size 15..21 */
    control[12] = (U8)win;

    rt_len = (int)(data[1] | (data[2] << 8));
    if (rt_len < 40) rt_len = 40;
    if (rt_len > (int)(len - 4)) rt_len = (int)(len - 4);
    if (rt_len < 40) return;

    g_rt     = data + 4;
    g_rt_len = rt_len;

    content_len = (int)(len - 4 - (size_t)rt_len);
    if (content_len < 0) content_len = 0;

    memset(&lit, 0, sizeof(lit));
    decompress_section(&lit, "fuzz", control, (int)sizeof(control),
                       (U8 *)(data + 4 + rt_len), content_len, &pUC, &sizeUC);
    if (pUC) free(pUC);
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
