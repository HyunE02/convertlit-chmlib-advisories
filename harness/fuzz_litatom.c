/*
 * ConvertLIT lit_read_atoms() harness - AFL++ persistent mode.
 *
 * litatom.c is not modified. Only the I/O layer (lit_get_file) is stubbed to
 * return the fuzz buffer - the same approach fuzz_lit.c uses for clit.c's
 * readat(). The stub allocates exactly the input length, so the buffer end
 * coincides with the allocation end and a one-byte overread lands in the
 * ASan redzone. That also matches how the real caller allocates.
 *
 * Target (lib/litatom.c):
 *     int nEntries, len, idx;                                  -- both int
 *     nEntries = READ_U32(p);                                   -- unchecked
 *     len = nEntries * sizeof(char *) + sizeof(lit_atom_list);  -- 64-bit product
 *     list = (lit_atom_list *)malloc(len);                      -- stored into int
 *     ...
 *     while (idx < nEntries) { ... list->atom_names[idx++] = s; }
 *
 * With nEntries = 0x20000000 the product 0x20000000*8 + 32 truncates to 32,
 * so malloc(32) is followed by writes of heap pointers past the allocation.
 * The attribute-map path at line 156 has the same defect.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#include "litlib.h"

/* ---- stubs: external symbols the library expects ---- */

void lit_error(int what, char *fmt, ...) { (void)what; (void)fmt; }

char *lit_i_strmerge(const char *s1, ...)
{
    /* the stubbed lit_get_file ignores the path, so the contents do not matter */
    char *p = (char *)malloc(8);
    if (p) strcpy(p, "/atom");
    return p;
}

/* holds the fuzz input so the stubbed lit_get_file can hand it back */
static const uint8_t *g_data;
static size_t         g_len;

int lit_get_file(lit_file *litfile, const char *name, U8 **ptr, int *psize)
{
    (void)litfile; (void)name;
    /* existence probe (ptr == NULL): just report success */
    if (!ptr || !psize) return 0;
    *ptr = (U8 *)malloc(g_len);
    if (!*ptr) return -1;
    memcpy(*ptr, g_data, g_len);
    *psize = (int)g_len;
    return 0;
}

static void run_one(const uint8_t *data, size_t len)
{
    lit_file lit;
    lit_atom_list *atoms;

    if (len < 8 || len > (1u << 20))
        return;

    g_data = data;
    g_len  = len;

    memset(&lit, 0, sizeof(lit));
    atoms = lit_read_atoms(&lit, "fuzz");
    if (atoms)
        lit_free_atoms(atoms);
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
