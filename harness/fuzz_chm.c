/*
 * CHMLib (jedwing) harness - AFL++ persistent mode.
 *
 * CHMLib's last upstream commit is 2009-07-02 and there has been no release
 * since, so "latest" and "old" are the same thing: a crash found here cannot
 * already be fixed in a later version.
 *
 * chm_open() takes a file path, so each iteration writes the input to a
 * per-PID file under /dev/shm (tmpfs, so no disk I/O) and opens that.
 *
 * Coverage: ITSF/ITSP headers -> directory chunks (PMGL/PMGI) -> LZX reset
 * table -> chm_retrieve_object() and LZX decompression (src/lzx.c).
 *
 * Build:
 *   afl-clang-fast -g -O1 -fsanitize=address -I src \
 *     -o fuzz_chm harness/fuzz_chm.c src/chm_lib.c src/lzx.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "chm_lib.h"

/* per-PID path so parallel instances do not collide */
static char tmp_path[64];
#define MAX_OBJ  (64)          /* reading every object is too slow */
#define MAX_READ (256 * 1024)

struct ctx {
    int count;
    unsigned char *buf;
};

static int enum_cb(struct chmFile *h, struct chmUnitInfo *ui, void *context)
{
    struct ctx *c = (struct ctx *)context;

    if (c->count++ >= MAX_OBJ)
        return CHM_ENUMERATOR_SUCCESS;

    if (ui->length > 0 && ui->length <= MAX_READ) {
        /* this is where LZX decompression happens */
        chm_retrieve_object(h, ui, c->buf, 0, (LONGINT64)ui->length);
    }

    /* also exercise the path-string resolution route */
    {
        struct chmUnitInfo ui2;
        chm_resolve_object(h, ui->path, &ui2);
    }
    return CHM_ENUMERATOR_CONTINUE;
}

static void run_one(const uint8_t *data, size_t len)
{
    struct chmFile *h;
    struct ctx c;
    int fd;

    /* the ITSF header alone needs several dozen bytes */
    if (len < 56 || len > (4u << 20))
        return;

    if (!tmp_path[0])
        snprintf(tmp_path, sizeof(tmp_path), "/dev/shm/.fuzz_chm_%d", (int)getpid());

    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return;
    if (write(fd, data, len) != (ssize_t)len) {
        close(fd);
        return;
    }
    close(fd);

    h = chm_open(tmp_path);
    if (!h)
        return;

    c.count = 0;
    c.buf = (unsigned char *)malloc(MAX_READ);
    if (c.buf) {
        chm_enumerate(h, CHM_ENUMERATE_ALL, enum_cb, &c);
        chm_enumerate_dir(h, "/", CHM_ENUMERATE_ALL, enum_cb, &c);
        free(c.buf);
    }
    chm_close(h);
}

#ifdef FUZZ_STANDALONE
int main(int argc, char **argv)
{
    FILE *f;
    long sz;
    uint8_t *buf;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <chm_file>\n", argv[0]);
        return 1;
    }
    f = fopen(argv[1], "rb");
    if (!f)
        return 1;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (4L << 20)) {
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

    while (__AFL_LOOP(5000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        run_one(buf, (size_t)len);
    }
    return 0;
}
#endif
