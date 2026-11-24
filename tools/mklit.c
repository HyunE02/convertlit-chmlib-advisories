/*
 * Valid .lit container builder - uses ConvertLIT's own writer API.
 *
 * Why this exists: findings A-05 through A-11 were originally located by calling
 * internal APIs directly or by stubbing lit_get_file(), which leaves open the
 * objection that the harness, not a real file, caused the crash. This tool removes
 * that objection. It builds a structurally valid container with the library's own
 * public writer:
 *
 *     lit_put_file(&out, "/manifest", payload, size, section);   // lib/litlib.c:387
 *     lit_write_to_file(&out);                                    // lib/litlib.c:166
 *
 * The primary header, piece table, secondary header and directory chunks are
 * therefore produced by ConvertLIT itself; only the inner part under test carries
 * the malicious bytes. No library source is modified - this file supplies the same
 * writeat() callback that clit18/transmute.c:84 does, plus the root "/" entry that
 * lit_put_file() requires (lib/litlib.c:395).
 *
 * Usage: mklit <out.lit> <internal/path[@section]> <payload-file> [...]
 *   Section defaults to 0 (Uncompressed). Append "@1" to place a file in the
 *   compressed section, which is what reaches decompress_section().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "litlib.h"

void lit_error(int what, char *fmt, ...)
{
    va_list a;
    (void)what;
    fprintf(stderr, "[lit_error] ");
    va_start(a, fmt);
    vfprintf(stderr, fmt, a);
    va_end(a);
    fprintf(stderr, "\n");
}

/* identical to clit18/transmute.c:84 */
static int my_writeat(void *v, U32 offset, U8 *ptr, int size)
{
    FILE *f = (FILE *)v;
    if (!f) return -1;
    if (fseek(f, (long)offset, SEEK_SET) != 0) return -1;
    return (int)fwrite(ptr, 1, (size_t)size, f);
}

/* lit_put_file needs the root "/" entry to exist already (lib/litlib.c:395) */
static entry_type *make_root(void)
{
    entry_type *e = (entry_type *)malloc(sizeof(entry_type) + 2);
    if (!e) return NULL;
    memset(e, 0, sizeof(entry_type) + 2);
    e->next        = NULL;
    e->data_source = ENTRY_SOURCE_POINTER;
    e->data_pointer= NULL;
    e->section     = 0;
    e->offset      = 0;
    e->size        = 0;
    e->namelen     = 1;
    e->name        = '/';
    return e;
}

static U8 *slurp(const char *path, int *psize)
{
    FILE *f = fopen(path, "rb");
    long sz;
    U8 *b;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    b = (U8 *)malloc((size_t)sz ? (size_t)sz : 1);
    if (!b) { fclose(f); return NULL; }
    if (sz && fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); fclose(f); return NULL; }
    fclose(f);
    *psize = (int)sz;
    return b;
}

int main(int argc, char **argv)
{
    lit_file out;
    FILE *fOut;
    int i, status;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr,
            "usage: %s <out.lit> <internal/path[@section]> <payload-file> [...]\n",
            argv[0]);
        return 1;
    }

    memset(&out, 0, sizeof(out));

    out.entry = make_root();
    if (!out.entry) return 1;
    out.num_file_entries = 1;

    /* header fields that are "mostly fixed" - typical values per litlib.h */
    out.entry_chunklen = 0x2000;
    out.count_chunklen = 0x200;
    out.drmlevel       = 1;
    out.creator_id     = 1;
    out.language_id    = 0x409;
    out.timestamp      = 0;
    out.entry_unknown  = 0;
    out.count_unknown  = 0;
    out.content_offset = 0;

    for (i = 2; i < argc; i += 2) {
        int sz = 0, sect = 0;
        char namebuf[512], *at;
        U8 *data = slurp(argv[i + 1], &sz);
        if (!data) {
            fprintf(stderr, "cannot read payload: %s\n", argv[i + 1]);
            return 1;
        }
        /* support the "path@section" syntax */
        snprintf(namebuf, sizeof(namebuf), "%s", argv[i]);
        at = strrchr(namebuf, '@');
        if (at) { *at = '\0'; sect = atoi(at + 1); }

        status = lit_put_file(&out, namebuf, data, sz, sect);
        if (status) {
            fprintf(stderr, "lit_put_file(\"%s\") failed: %d\n", namebuf, status);
            return 1;
        }
        printf("  added: %-62s section=%d  %d bytes\n", namebuf, sect, sz);
    }

    fOut = fopen(argv[1], "wb");
    if (!fOut) { fprintf(stderr, "cannot open output file\n"); return 1; }
    out.file_pointer = (void *)fOut;
    out.writeat      = my_writeat;

    status = lit_write_to_file(&out);
    fclose(fOut);

    if (status) {
        fprintf(stderr, "lit_write_to_file failed: %d\n", status);
        return 1;
    }
    printf("  written: %s\n", argv[1]);
    return 0;
}
