/*
 * Link-time replacement for clit18/drm5.c.
 *
 * The upstream Makefile builds drm5.c against libtommath-0.30 (-I ../libtommath-0.30/).
 * Where that distribution is unavailable, this file substitutes at link time only.
 * drm5_callback() is the sole symbol other translation units reference; it is the
 * decryption callback for DRM5-protected .lit files.
 *
 * None of the proofs of concept in this repository are DRM-protected, and every crash
 * occurs inside lit_i_read_headers(), lit_read_atoms(), decompress_section() or
 * lit_reconstitute_html() - all reached long before any DRM5 code would run. No file
 * under clit18/ or lib/ is modified.
 */
#include <stdio.h>
int drm5_callback(void *pv, unsigned char *p, int size)
{
    (void)pv; (void)p; (void)size;
    fprintf(stderr, "[drm5_stub] DRM5 path is disabled in this build.\n");
    return -1;
}
