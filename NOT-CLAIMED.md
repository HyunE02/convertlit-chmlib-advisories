# Findings that were investigated and then dropped

Two defects were found, fully reproduced, and then **removed from this report**. They are
documented here because omitting them silently would misrepresent the work, and because
the reasoning is useful to anyone auditing the same code.

---

## 1. Signed overflow in `lit_i_read_headers()` — duplicate of CVE-2026-107730

```c
total_hdr_size = hdr_len + num_pieces*PIECE_SIZE + sec_hdr_len;   /* PIECE_SIZE = 16 */
if ((size_t)total_hdr_size >= litfile->filesize) {                /* the only check */
    return E_LIT_FORMAT_ERROR;
}
header = litfile->readat(litfile->file_pointer, 0, total_hdr_size);
r = lit_i_read_secondary_header(litfile,
    header + hdr_len + num_pieces*PIECE_SIZE,    /* different expression from the check */
    sec_hdr_len);
```

A 64-byte file sets `num_pieces = 0x08000000`, making the sub-expression −2,147,483,608
while the checked total stays at 39, so the pointer lands about 2 GiB before the
allocation. It is deterministic, needs no sanitizer, and reproduces on vendor binaries.

**It is nonetheless the same defect as CVE-2026-107730** (SumatraPDF, published
2026-10-08), which describes `hdrLen + nPieces * 16` computed in signed 32-bit without
validating the aggregate.

### How that was established, rather than assumed

Comparing advisory prose is weak evidence. Instead, the **official fix commit**
(SumatraPDF `10a83278`) was ported into ConvertLIT and the proof of concept re-run:

| build | result |
|---|---|
| unmodified upstream | SIGSEGV at `lib/litheaders.c:629` |
| with the upstream fix ported in | **no crash** |

There is a trap in that experiment. The ported fix also gates `nPieces` to `5..16`, so a
proof of concept with an out-of-range `num_pieces` would be rejected by the *gate* rather
than fixed by the *check* — and one would wrongly conclude "duplicate". This is not
hypothetical: two other findings were briefly misjudged that way before being
rehabilitated.

So the test was repeated with `num_pieces` kept inside the gate, driving the overflow
through `hdr_len` instead (ConvertLIT places no upper bound on it):

| `num_pieces` | `hdr_len` | displacement | unmodified | with fix |
|---|---|---|---|---|
| 5 | `0x7fffffff` | −2,147,483,569 | SIGSEGV | blocked |
| 6 … 15 | `0x7fffffff` | … | SIGSEGV | blocked |
| 16 | `0x7fffffff` | −2,147,483,393 | SIGSEGV | blocked |

**12 of 12 blocked, with zero gate rejections** — every one passed the `5..16` gate and
was then stopped by the real predicate the fix adds. Repeated five times, fully
convergent. The fix addresses the defect itself, so the defect is the same one.
**Not claimed.**

---

## 2. Unbounded `ENSURE_BITS` in `lib/lzx/lzx.c` — dead code, and not attacker-controlled

```c
#define ENSURE_BITS(n)                                                   \
  while (bitsleft < (n)) {                                               \
    bitbuf |= ((inpos[1]<<8)|inpos[0]) << (ULONG_BITS-16 - bitsleft);    \
    bitsleft += 16; inpos+=2;                                            \
  }
```

`inpos` advances with no check against the end of the input, and the only guard
(`if (inpos > (endinp+2) ...)`) explicitly tolerates reading two bytes past the end.
That looks like a clean out-of-bounds read, and it reproduces — but it is not shipped.

**Nobody builds this file.** The upstream `lib/Makefile` links
`newlzx/lzxglue.o` + `newlzx/lzxd.o`, not `lzx/lzx.o`, and `newlzx/lzxd.c`'s own
`ENSURE_BITS` does check (`if (i_ptr >= i_end)`). Arch, Gentoo and NetBSD all use the
upstream Makefile.

An initial reading of a vendor binary suggested otherwise, because it exports
`LZXwindow` — which looked like the legacy implementation. That was wrong: `LZXwindow` is
defined in `newlzx/lzxglue.c:127`, and `lzx/lzx.c` does not contain the name at all.
Disassembling the vendor's `LZXdecompress` settled it:

```asm
mov    r9d, 0x1000     ; 4096
mov    r8d, 0x7fff     ; 32767
```

Those are the literal arguments at `lzxglue.c:163-165`. The vendor uses the safe path too.

### And the crash in the configuration that *is* shipped is not a vulnerability

Rebuilding against `newlzx` changes the signature entirely:

```
global-buffer-overflow, WRITE of size 1
  #0 lzxd_static_init   newlzx/lzxd.c:362
  #1 lzxd_init          newlzx/lzxd.c:409
0 bytes after global variable 'extra_bits' (size 51)
```

```c
static unsigned char extra_bits[51];
for (i = 0, j = 0; i < 51; i += 2) {
    extra_bits[i]   = j;
    extra_bits[i+1] = j;     /* i = 50 → extra_bits[51] */
}
```

A plain off-by-one — but **input-independent**. Benign seed files produce the identical
write at the identical address; it fires on every `lzxd_init()` call and has done so for
twenty years. An attacker influences nothing about it. It is a genuine undefined-behaviour
bug worth reporting upstream, but it is **not a vulnerability** and is **not claimed**.

---

## Also excluded

* **A bug introduced by our own fuzzing patch.** A modified guard
  (`while (offset + 12 <= len)`) created an integer overflow that the original
  (`offset < len`) does not have. Found, recognised, discarded.
* **`poc/chm/c_freespace.chm`, `c_freespace2.chm`, `d_strlen.chm`** — these do not
  reproduce against an unmodified 0.40 build (exit 0) and were removed from the PoC set.
* **`litmanifest.c:146`**, `malloc(sizeof(name_mapping)*num_files)` — the product never
  passes through an `int`, so there is no truncation, and the NULL check is correct.
  Clean.
* **`clit.c:242-248`** off-by-one — driven by the user's own `argv`, not by file content.
* A LibRaw crash reproduced during the same work is **CVE-2026-20889**, already public.
