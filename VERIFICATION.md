# Verification

## Method

Each proof of concept was executed **five times in independent runs**. Every run created
a fresh working directory (`mktemp -d`) and removed it afterwards, so no state carried
between rounds. The purpose was to eliminate results that reproduce only once, depend on
environment, or are otherwise non-deterministic.

Binaries used match a distribution build: Arch `extra/convertlit 1.8-13` patch applied,
`drm5_stub.c` linked in place of `drm5.c` (libtommath-0.30 unavailable; the DRM path is
unrelated to every finding). A-09 uses an `-O0` build — see the note in the README.

Re-run it yourself with `tools/verify5.sh`.

## Results — 28 / 28 stable, 0 unstable

| Advisory | PoC | Signature | Location | 5 runs |
|---|---|---|---|---|
| A-01 | `sec_infloop_min.lit` | hang | — | **5/5** |
| A-01 | `m_0_16.lit` | hang | — | **5/5** |
| A-01 | `c1.lit` | hang | — | **5/5** |
| A-02 | `sec_oob_np5.lit` | heap-buffer-overflow | `litheaders.c:633` | **5/5** |
| A-02 | `m_0_8.lit` | heap-buffer-overflow | `litheaders.c:634` | **5/5** |
| A-02 | `c0.lit` | heap-buffer-overflow | `litheaders.c:634` | **5/5** |
| A-03 | `piece_oob.lit` | heap-buffer-overflow | `litheaders.c:329` | **5/5** |
| A-04 | `d_ovf_2x.lit` | heap-buffer-overflow | `litdirectory.c:304` | **5/5** |
| A-04 | `d_ovf_16x.lit` | heap-buffer-overflow | `litdirectory.c:304` | **5/5** |
| A-04 | `d_ovf_big.lit` | heap-buffer-overflow | `litdirectory.c:304` | **5/5** |
| A-05 | `f10.lit` | SIGSEGV | `litembiggen.c:338` | **5/5** |
| A-06 | `f11.lit` | SIGSEGV | `litembiggen.c:437` | **5/5** |
| A-07 | `f12a.lit` | heap-buffer-overflow **WRITE** | `litatom.c:126` | **5/5** |
| A-07 | `f12b.lit` | heap-buffer-overflow **WRITE** | `litatom.c:99` | **5/5** |
| A-07 | `f12c.lit` | heap-buffer-overflow **WRITE** | `litatom.c:189` | **5/5** |
| A-08 | `f13.lit` | negative-size-param | `litatom.c:186` | **5/5** |
| A-09 | `f14.lit` | SIGSEGV | `litsections.c:369` | **5/5** |
| A-10 | `f15.lit` | heap-buffer-overflow | `litutil.c:132` | **5/5** |
| A-11 | `f16a.lit` | SIGSEGV | `litsections.c:388` | **5/5** |
| A-11 | `f16b.lit` | heap-buffer-overflow | `litsections.c:388` | **5/5** |
| A-11 | `f16c.lit` | heap-buffer-overflow | `litsections.c:389` | **5/5** |
| A-12 | `a_encint.chm` | heap-buffer-overflow | `chm_lib.c:1109` | **5/5** |
| A-13 | `b_pmgiloop.chm` | hang | — | **5/5** |
| A-14 | `e_blocklen1.chm` | heap-buffer-overflow | `chm_lib.c:1280` | **5/5** |
| A-14 | `e_blocklen4.chm` | heap-buffer-overflow | `chm_lib.c:272` | **5/5** |
| A-14 | `e_blocklen19.chm` | heap-buffer-overflow | `chm_lib.c:260` | **5/5** |
| A-14 | `e_blocklen20.chm` | hang | — | **5/5** |
| A-15 | `d_utf8oob.chm` | heap-buffer-overflow | `chm_lib.c:1129` | **5/5** |

## One reported mismatch, resolved as a reporting artefact

A-05 was initially flagged as not matching its expected location. The cause was the
summarising script's regular expression `(lit[a-z]*|chm_lib)\.c:[0-9]+`, which matched
the substring `lit.c:261` inside `clit.c:261`; at `-O1` the `litembiggen.c` frame carries
no line number, so the next match won. Re-checking the actual frame five times:

```
runs 1-5:  #0 lit_reconstitute_html   lib/litembiggen.c
```

and at `-O0`, with line numbers:

```
#0 lit_reconstitute_html   lib/litembiggen.c:338
#1 write_htmlish_file      clit18/explode.c:524
#2 explode_lit             clit18/explode.c:109
#3 main                    clit18/clit.c:261
```

The defect location was correct; only the summary table was wrong.

## The infinite loops burn CPU — they do not block

A-01 was measured directly to rule out a blocking wait:

```
+1s  %CPU 101   state R
+4s  %CPU  98.8 state R
/proc/<pid>/stat :  utime 707 jiffies   stime 0   state R
/proc/<pid>/wchan:  0
```

`stime 0` and `wchan 0` mean no syscall wait. It is a pure user-space loop holding one
core at 100%.

## Compiler and optimisation matrix

A-01 and the dropped `lit_i_read_headers` finding were additionally run across
**clang 18.1.3 and gcc 13.3.0 × -O0 -O1 -O2 -O3 × {ASan, plain}** — 16 combinations each.
All 16 reproduced in every case, ruling out an artefact of one compiler or optimisation
level.
