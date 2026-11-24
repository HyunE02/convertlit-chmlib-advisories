# ConvertLIT 1.8 and CHMLib 0.40 — memory-safety advisories

Fifteen memory-safety defects in two unmaintained e-book parsing libraries, with
file-level proofs of concept that reproduce through the shipped command-line tools.

CVE IDs were requested from the MITRE CNA of Last Resort on 2026-11-24 and are pending.
Neither project has a CNA or a contactable maintainer.

Reported by **C_Rang**.

---

## Why these libraries

| Project | Version audited | Upstream status | OSS-Fuzz |
|---|---|---|---|
| ConvertLIT (clit18) | **1.8** | No release since **2003**; site still serves the source; no contactable maintainer | not enrolled |
| CHMLib (jedwing) | **0.40** | Last commit **2009-07-02**; 0.40 is the final release | not enrolled |

Both are still shipped today:

* ConvertLIT — Arch Linux `extra/convertlit 1.8-13`, Gentoo `app-text/convertlit-1.8-r4`,
  NetBSD pkgsrc `convertlit-1.8nb1`
* CHMLib — used by CHM viewers and bundled by appliance vendors

Because upstream is effectively dead, "latest" and "old" are the same thing: a defect
found here cannot already have been fixed in a later release.

### The audited source is byte-identical to what distributions ship

| Check | Value | Source of truth | Match |
|---|---|---|---|
| Size | 135,120 bytes | NetBSD pkgsrc `distinfo` | yes |
| SHA-256 | `d70a85f5b945104340d56f48ec17bcf544e3bb3c35b1b3d58d230be699e557ba` | Arch `PKGBUILD` | yes |
| SHA-512 | `0d4b7d525f5164a73a47a00e1c4e93ff50e738a4e6c541ded283c4779e6a6713…` | NetBSD `distinfo` | yes |
| BLAKE2s | `4f753b9612793c47bb5120a521f075483c0a89ed9bc8e4293fca4a6bd923e15b` | NetBSD `distinfo` | yes |

No distribution carries a security patch for either library. Arch does carry an unrelated
OOB fix in `clit18/clit.c` (`dir_program[MAX_PATH]`), which shows that known issues do get
patched there — the defects below are simply not known.

---

## Advisories

### ConvertLIT (clit18) 1.8

| ID | Weakness | Routine | File |
|---|---|---|---|
| [A-01](advisories/A-01.md) | CWE-835 Infinite Loop | `lit_i_read_secondary_header` | `lib/litheaders.c` |
| [A-02](advisories/A-02.md) | CWE-125 Out-of-bounds Read | `lit_i_read_secondary_header` | `lib/litheaders.c` |
| [A-03](advisories/A-03.md) | CWE-125 Out-of-bounds Read | `lit_i_read_headers` | `lib/litheaders.c` |
| [A-04](advisories/A-04.md) | CWE-190 Integer Overflow | `lit_i_read_directory` | `lib/litdirectory.c` |
| [A-05](advisories/A-05.md) | CWE-129 Improper Array Index Validation | `lit_reconstitute_html` | `lib/litembiggen.c` |
| [A-06](advisories/A-06.md) | CWE-590 Free of Memory not on the Heap | `lit_reconstitute_html` | `lib/litembiggen.c` |
| [A-07](advisories/A-07.md) | CWE-190 → **out-of-bounds write** | `lit_read_atoms` | `lib/litatom.c` |
| [A-08](advisories/A-08.md) | CWE-195 → **out-of-bounds write** | `lit_read_atoms` | `lib/litatom.c` |
| [A-09](advisories/A-09.md) | CWE-476 NULL Pointer Dereference | `decompress_section` | `lib/litsections.c` |
| [A-10](advisories/A-10.md) | CWE-125 Out-of-bounds Read | `lit_i_utf8_len_to_bytes` | `lib/litutil.c` |
| [A-11](advisories/A-11.md) | CWE-125 Out-of-bounds Read | `decompress_section` | `lib/litsections.c` |

### CHMLib 0.40

| ID | Weakness | Routine | File |
|---|---|---|---|
| [A-12](advisories/A-12.md) | CWE-125 Out-of-bounds Read | `_chm_parse_cword` | `src/chm_lib.c` |
| [A-13](advisories/A-13.md) | CWE-835 Infinite Loop | directory page chain | `src/chm_lib.c` |
| [A-14](advisories/A-14.md) | CWE-125 Out-of-bounds Read | ITSP `block_len` handling | `src/chm_lib.c` |
| [A-15](advisories/A-15.md) | CWE-125 Out-of-bounds Read | `_chm_parse_UTF8` | `src/chm_lib.c` |

**A-07 and A-08 are the only write primitives** (CVSS 4.0 6.8, `VI:L`); everything else
is a read or an availability issue (6.7, `VI:N`). No code execution has been
demonstrated for any of them.

---

## Prior art — please read before triage

On 2026-10-08 a batch of SumatraPDF advisories was published (reporter `sigure21`),
including **CVE-2026-107730** and **CVE-2026-107731**, both covering LIT parsing in
SumatraPDF's own `src/LitDoc.cpp`. That file is an *independent reimplementation*, not a
port of ConvertLIT, but it handles the same file format, so the areas overlap.

Every finding here was checked against `src/LitDoc.cpp` at commit `5d43b8cf` (1,624 lines)
and against both fix commits. **Two findings were dropped as a result** — see
[NOT-CLAIMED.md](NOT-CLAIMED.md).

For the findings that remain, the distinguishing facts are:

| | SumatraPDF | ConvertLIT |
|---|---|---|
| secondary-header walk (A-02) | reads 8 bytes under an 8-byte-aware guard, plus a `pos >= 0` lower bound | reads **12 bytes** under a **1-byte** guard |
| directory chunk check (A-04) | `32 + (i64)nChunks * chunkSize` — 64-bit product | `32 + nChunks*sizeChunk` — **int product** |
| piece cross-check (A-03) | bounds-checked accessors (`LitU32`/`LitU64` return 0 out of range) | raw `READ_U32` at a fixed offset into a variable-size buffer, no size check |
| A-01, A-05 … A-10 | **no counterpart exists** in `src/LitDoc.cpp` | — |

**A-11 is a partial claim.** The integer-overflow half of that code
(`ofsEntry = READ_INT32(pRT+12) + 8`) *is* covered by CVE-2026-107731, whose fix changed
the same expression in SumatraPDF. Only the guard-granularity half is claimed here.

CHMLib has its own CVE history in two of the functions below — CVE-2005-2930
(`_chm_parse_cword`, fixed in 0.36/0.37) and CVE-2007-0619 (page block length, fixed
before 0.39). **A-12 and A-14 are offered explicitly as incomplete-fix claims** against
the final release 0.40.

---

## Reproduction

```sh
# Upstream source
#   http://www.convertlit.com/clit18src.zip
#   SHA-256 d70a85f5b945104340d56f48ec17bcf544e3bb3c35b1b3d58d230be699e557ba
unzip clit18src.zip && cd clit18src

I="-I lib -I lib/des -I lib/sha -I lib/newlzx"
F="-g -fsanitize=address -fno-omit-frame-pointer -funsigned-char -Wno-everything"

# library — same object list as the upstream Makefile (newlzx, not lib/lzx)
for s in litatom litdrm litlib litembiggen littags litmetatags litmanifest \
         litdirectory litsections litheaders litutil ; do
    clang $F -O1 $I -c lib/$s.c -o $s.o ; done
clang $F -O1 $I -c lib/sha/mssha1.c      -o mssha1.o
clang $F -O1 $I -c lib/des/des.c         -o des.o
clang $F -O1 $I -c lib/newlzx/lzxglue.c  -o lzxglue.o
clang $F -O1 $I -c lib/newlzx/lzxd.c     -o lzxd.o
ar rcs openclit_asan.a *.o

# the shipped CLI, matching a distribution build
#   (1) Arch extra 1.8-13 applies this; without it a *known* OOB in clit.c:122
#       fires before any LIT parsing happens
sed -i -e 's|\(dir_program\[MAX_PATH\)\(\] = \)|\1-1\2|' clit18/clit.c
#   (2) clit18/drm5.c needs libtommath-0.30. If unavailable, link tools/drm5_stub.c
#       instead; the DRM path is unrelated to every finding here and no source
#       file is modified.
for s in clit hexdump explode transmute display utils manifest ; do
    clang $F -O1 -I lib -I lib/des -I clit18 -c clit18/$s.c -o c_$s.o ; done
clang $F -O1 -c tools/drm5_stub.c -o drm5_stub.o
clang $F -O1 -o clit_asan c_*.o drm5_stub.o openclit_asan.a

mkdir -p out/            # NOTE: the trailing slash matters, see Caveats
ASAN_OPTIONS=detect_leaks=0 ./clit_asan poc/container/f15.lit out/
```

`poc/container/*.lit` are complete, structurally valid LIT containers: the primary
header, piece table, secondary header and directory chunks were produced by ConvertLIT's
own writer API (`lit_put_file` + `lit_write_to_file`, see `tools/mklit.c`), and only the
inner part under test carries the malicious bytes. They reach the parser through
`readat()` and `lit_get_file()` exactly as a downloaded file would — no harness-supplied
buffer is involved.

CHMLib needs no container work: `chm_open()` takes a path, so each `poc/chm/*.chm` is
already a file-level proof of concept.

### Caveats that will otherwise waste your time

* **Output directory must end in `/`.** Otherwise `clit.c:242-248`
  (`malloc(strlen+1)` + `strcpy` + `strcat("/")`) overflows first. That is an argv-driven
  off-by-one unrelated to file content.
* **A-09 needs `-O0`.** At `-O1` and above clang infers `ptr != NULL` from the
  dereference that precedes the NULL check and removes the branch. The store is present
  in optimised vendor builds; it is the sanitizer build that hides it.
* **Do not build `lib/lzx/lzx.c`.** The upstream Makefile does not; it builds
  `newlzx/lzxglue.o` + `newlzx/lzxd.o`. See [NOT-CLAIMED.md](NOT-CLAIMED.md).

---

## Verification

Every proof of concept was run **five times in independent runs**, each with a freshly
created working directory. **28 / 28 produced identical results; zero were unstable.**
Full data and the re-run script are in [VERIFICATION.md](VERIFICATION.md) and
`tools/verify5.sh`.

All logs in `logs/` were produced from **unmodified upstream sources**. Patches used
during fuzzing were applied only to a separate working copy and are not part of this
repository.

---

## Scope and limitations, stated plainly

* **No code execution is demonstrated** for any finding, including the two write
  primitives. The CVSS vectors reflect that (`VC:N`, and `VI:N` except for A-07/A-08).
* **No information disclosure is demonstrated.** The out-of-bounds reads crash or feed
  values into further parsing; none was shown to reach an attacker-visible output.
* Versions older than ConvertLIT 1.8 / CHMLib 0.40 were **not tested**; `defaultStatus`
  is `unknown` rather than `unaffected` for that reason.
* Appliance vendors that bundle these libraries often run parsers in a short-lived forked
  child and discard the exit status, which contains crashes but not the two infinite
  loops (A-01, A-13), since those children never exit.

## Layout

```
advisories/   one file per finding
poc/lit/      ConvertLIT PoC inputs (raw parts and standalone .lit)
poc/chm/      CHMLib PoC inputs
poc/container/ complete valid .lit containers built with tools/mklit.c
logs/         AddressSanitizer output, all from unmodified upstream sources
harness/      fuzzing and reproduction harnesses
tools/        mklit.c (container builder), gen_poc.py, drm5_stub.c, verify5.sh
```

## Disclosure

Neither project has a maintainer who can issue a fix. CVE IDs were requested from the
MITRE CNA of Last Resort on 2026-11-24. This repository is published so that
distributions carrying these packages can act on concrete, reproducible information.
