#!/usr/bin/env bash
# Full verification suite for the deep-research skill after adding sources.
# Resolve the engine to an ABSOLUTE path before cd-ing, or a relative invocation
# (bash scripts/verify_deep_research.sh) resolves against /tmp and fails.
S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/deep_research.py"
cd /tmp || exit 1
pass=0; fail=0; gap=0
chk() { # chk "label" expected actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; pass=$((pass+1));
  else echo "  FAIL  $1 (want $2, got $3)"; fail=$((fail+1)); fi
}
chkc() { # chkc "label" condition-result(0/1)
  if [ "$2" = "0" ]; then echo "  PASS  $1"; pass=$((pass+1));
  else echo "  FAIL  $1"; fail=$((fail+1)); fi
}

echo "=== compile + registry ==="
python3 -m py_compile "$S"; chkc "compiles" $?
python3 -m unittest discover -s "$(dirname "$S")/../tests" >/tmp/v_unit.txt 2>&1
chkc "deterministic unit tests" $?
python3 "$S" --sources > /tmp/v_reg.txt 2>&1
grep -q "91 configured sources across 10 lanes" /tmp/v_reg.txt; chkc "registry = 91 sources / 10 lanes" $?

echo "=== positive control: residential proxy networks ==="
python3 "$S" "residential proxy networks" --deep --limit 5 --no-unrelated > /tmp/v_pos.txt 2>/tmp/v_pos_err.txt
grep -q '^## NEWS' /tmp/v_pos.txt; chkc "NEWS section present (RSS not regressed)" $?
grep -q '^## ACADEMIC' /tmp/v_pos.txt; chkc "ACADEMIC section present" $?
[ "$(grep -c '^## Sources (' /tmp/v_pos.txt)" = "1" ]; chkc "exactly one Sources header" $?
[ "$(sed -n '/^## Sources (/,$p' /tmp/v_pos.txt | grep -ci 'painting')" = "0" ]; chkc "off-topic rows excluded from Sources" $?
[ "$(sed -n '/^## WEB/,/^## Unrelated/p' /tmp/v_pos.txt | grep -ci 'painting')" = "0" ]; chkc "no off-topic in WEB lane" $?
echo "  info: $(sed -n '3p' /tmp/v_pos.txt)"

echo "=== negative control: CVE-2021-44228 ==="
python3 "$S" "CVE-2021-44228" --deep --limit 5 --no-unrelated > /tmp/v_cve.txt 2>&1
kev=$(grep -c 'sources:.*CISA KEV' /tmp/v_cve.txt)
[ "$kev" -ge 1 ]; chkc "CISA KEV merged into a finding (>=1, was $kev)" $?
grep -q '^## SECURITY' /tmp/v_cve.txt; chkc "SECURITY section present" $?
if grep -q 'sources:.*Ubuntu CVE' /tmp/v_cve.txt; then
  echo "  PASS  Ubuntu CVE contributing"; pass=$((pass+1))
elif grep -q 'ERR: Ubuntu CVE:' /tmp/v_cve.txt; then
  echo "  GAP   Ubuntu CVE endpoint unavailable (reported as a coverage gap)"
  gap=$((gap+1))
else
  echo "  FAIL  Ubuntu CVE returned no finding and no explicit gap"
  fail=$((fail+1))
fi
grep -q 'sources:.*Red Hat CVE' /tmp/v_cve.txt; chkc "Red Hat CVE contributing" $?
grep -q 'ERR: Red Hat' /tmp/v_cve.txt; [ "$?" = "1" ]; chkc "no Red Hat error" $?
grep -q 'ERR: MITRE' /tmp/v_cve.txt; [ "$?" = "1" ]; chkc "no MITRE error" $?
grep -q 'query shape: cve=' /tmp/v_cve.txt; chkc "query shape reports cve" $?
echo "  info: $(sed -n '3p' /tmp/v_cve.txt)"

echo "=== CWE-shaped query ==="
python3 "$S" "CWE-89 SQL injection" --lanes security --limit 5 --no-unrelated > /tmp/v_cwe.txt 2>&1
grep -q 'sources: MITRE CWE' /tmp/v_cwe.txt; chkc "CWE resolves" $?
grep -q 'CAPEC-66 related to CWE-89' /tmp/v_cwe.txt; chkc "CWE-89 maps to CAPEC-66 SQL injection" $?
grep -q 'CAPEC-89 related to CWE-89' /tmp/v_cwe.txt; [ "$?" = "1" ]; chkc "CWE id is not reused as a CAPEC id" $?
grep -q 'CWE-44228' /tmp/v_cwe.txt; [ "$?" = "1" ]; chkc "no CVE-as-CWE id confusion" $?

echo "=== Bluesky (credentialed source) ==="
python3 "$S" "residential proxy networks" --lanes community --limit 5 --no-unrelated > /tmp/v_bsky.txt 2>&1
if grep -q 'ERR: Bluesky' /tmp/v_bsky.txt; then
  # a 401/expired app password must degrade, not crash the run
  echo "  FAIL  Bluesky errored (check BSKY_HANDLE/BSKY_APP_PASSWORD in ~/.hermes/.env)"
  fail=$((fail+1))
elif grep -q 'sources:.*Bluesky' /tmp/v_bsky.txt; then
  echo "  PASS  Bluesky authenticated and contributing"; pass=$((pass+1))
else
  echo "  SKIP  Bluesky skipped (no BSKY_ credential configured)"
fi

echo "=== quick mode + sources block flags ==="
python3 "$S" "residential proxy networks" --quick > /tmp/v_quick.txt 2>&1
echo "  info: $(sed -n '3p' /tmp/v_quick.txt)"
python3 "$S" "residential proxy networks" --deep --limit 3 --max-sources 5 --no-unrelated > /tmp/v_max.txt 2>&1
[ "$(grep -cE '^\[[0-9]+\] ' /tmp/v_max.txt)" = "5" ]; chkc "--max-sources 5 prints 5 entries" $?
grep -q 'more not shown' /tmp/v_max.txt; chkc "truncation line present" $?

echo "=== json compact round-trip ==="
python3 "$S" "residential proxy networks" --deep --limit 3 --json compact > /tmp/v.json 2>&1
python3 "$S" --render /tmp/v.json > /tmp/v_render.txt 2>/dev/null
[ "$(grep -c '^## Sources (' /tmp/v_render.txt)" = "1" ]; chkc "--render round-trip prints one Sources header" $?
python3 - <<'PY'
import json
d = json.load(open("/tmp/v.json"))
print("  info: compact omits by_lane:", "by_lane" not in d, "| on_topic:", len(d.get("on_topic", [])))
PY

echo "=== bad lane rejected ==="
python3 "$S" "x" --lanes nope >/dev/null 2>&1; [ "$?" != "0" ]; chkc "unknown lane exits non-zero" $?

echo
echo "RESULT: $pass passed, $fail failed, $gap live gaps"
[ "$fail" = "0" ]
