#!/bin/bash
# Repeat the same verification N times independently and check that the results
# converge. The point is to filter out anything that reproduces only once,
# depends on the environment, or is otherwise non-deterministic.
cd /home/hyun/synology-bounty
ROUNDS=${1:-5}
A=detect_leaks=0
N=detect_leaks=0:allocator_may_return_null=1
OUT=v3/verify5
rm -rf $OUT && mkdir -p $OUT

# columns: id|PoC|binary|ASAN_OPTIONS selector|expected location
cat > $OUT/targets.txt <<'EOF'
1|v3/variants/sec_infloop_min.lit|CLIT|A|TIMEOUT
1b|poc/lit/m_0_16.lit|CLIT|A|TIMEOUT
1c|poc/lit/c1.lit|CLIT|A|TIMEOUT
2|v3/variants/sec_oob_np5.lit|CLIT|A|litheaders.c:633
2b|poc/lit/m_0_8.lit|CLIT|A|litheaders.c:634
2c|poc/lit/c0.lit|CLIT|A|litheaders.c:634
4|poc/lit/piece_oob.lit|CLIT|A|litheaders.c:329
5|poc/lit/d_ovf_2x.lit|CLIT|A|litdirectory.c:304
5b|poc/lit/d_ovf_16x.lit|CLIT|A|litdirectory.c:304
5c|poc/lit/d_ovf_big.lit|CLIT|A|litdirectory.c:304
10|v3/gen/final/f10.lit|CLIT|A|litembiggen
11|v3/gen/final/f11.lit|CLIT|A|litembiggen.c:437
12a|v3/gen/final/f12a.lit|CLIT|A|litatom.c:126
12b|v3/gen/final/f12b.lit|CLIT|A|litatom.c:99
12c|v3/gen/final/f12c.lit|CLIT|A|litatom.c:189
13|v3/gen/final/f13.lit|CLIT|A|litatom.c:186
14|v3/gen/final/f14.lit|CLIT0|N|litsections.c:369
15|v3/gen/final/f15.lit|CLIT|A|litutil.c:132
16a|v3/gen/final/f16a.lit|CLIT|N|litsections.c:388
16b|v3/gen/final/f16b.lit|CLIT|N|litsections.c:388
16c|v3/gen/final/f16c.lit|CLIT|N|litsections.c:389
6|poc/chm/a_encint.chm|CHM|A|chm_lib.c:1109
7|poc/chm/b_pmgiloop.chm|CHM|A|TIMEOUT
8a|poc/chm/e_blocklen1.chm|CHM|A|chm_lib.c:1280
8b|poc/chm/e_blocklen4.chm|CHM|A|chm_lib.c:272
8c|poc/chm/e_blocklen19.chm|CHM|A|chm_lib.c:260
8d|poc/chm/e_blocklen20.chm|CHM|A|TIMEOUT
9|poc/chm/d_utf8oob.chm|CHM|A|chm_lib.c:1129
EOF

run_one() {  # (see VERIFICATION.md)
  local d=$(mktemp -d /tmp/v5XXXXXX)
  local o
  case "$1" in
    CLIT)  o=$(ASAN_OPTIONS=$3 timeout 10 ./v3/bin/clit_arch    "$2" "$d/" 2>&1); rc=$? ;;
    CLIT0) o=$(ASAN_OPTIONS=$3 timeout 10 ./v3/bin/clit_arch_O0 "$2" "$d/" 2>&1); rc=$? ;;
    CHM)   o=$(ASAN_OPTIONS=$3 timeout 10 ./v3/bin/chm_repro_pristine "$2" 2>&1); rc=$? ;;
  esac
  rm -rf "$d"
  local sig loc
  sig=$(echo "$o" | grep -oE 'AddressSanitizer: [A-Za-z0-9_-]+' | head -1 | sed 's/.*: //')
  loc=$(echo "$o" | grep -oE '(lit[a-z]*|chm_lib)\.c:[0-9]+' | head -1)
  if [ -z "$sig" ] && [ "$rc" = "124" ]; then echo "TIMEOUT|-"; 
  elif [ -z "$sig" ]; then echo "NOCRASH|exit$rc";
  else echo "$sig|${loc:--}"; fi
}

for r in $(seq 1 $ROUNDS); do
  : > $OUT/round$r.txt
  while IFS='|' read -r n poc bin opt exp; do
    [ -z "$n" ] && continue
    ov=$A; [ "$opt" = "N" ] && ov=$N
    if [ -f "$poc" ]; then echo "$n|$(run_one $bin "$poc" "$ov")" >> $OUT/round$r.txt
    else echo "$n|MISSING|-" >> $OUT/round$r.txt; fi
  done < $OUT/targets.txt
done
echo "done: $ROUNDS rounds"
