#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral oracle for the nearcore Mayhem integration.
#
# Runs the DYNAMICALLY-LINKED KAT probe /mayhem/kat (built by mayhem/build.sh),
# which decodes a known borsh-encoded SignedTransaction through the real
# near_primitives decoder and prints the decoded fields. We assert the EXACT values
# with grep (bash + coreutils are whitelisted by the verify-repo sabotage shim, so
# the comparison happens where sabotage cannot hide). If near_primitives is neutered
# to a no-op / exit(0), the probe prints nothing and every grep FAILS — so this
# oracle FAILS under sabotage (SPEC §6.3), which is the whole point.
#
# The probe is UNCONDITIONAL: a missing binary or a missing expected value is a
# FAILURE, never a skip. Emits a CTRF summary; exits non-zero iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASS=0
FAIL=0
check() { # <description> <expected-substring> <actual-output>
  local desc="$1" want="$2" got="$3"
  if printf '%s' "$got" | grep -qF -- "$want"; then
    echo "  ok   : $desc ($want)"
    PASS=$((PASS+1))
  else
    echo "  FAIL : $desc — expected '$want' in KAT output" >&2
    FAIL=$((FAIL+1))
  fi
}

KAT=/mayhem/kat
if [ ! -x "$KAT" ]; then
  echo "ERROR: KAT probe $KAT missing or not executable — build.sh must produce it" >&2
  emit_ctrf "nearcore-kat" 0 1 0
  exit 1
fi

echo "=== running KAT probe: $KAT ==="
OUT="$("$KAT" 2>&1)"; RC=$?
echo "$OUT"
if [ "$RC" -ne 0 ]; then
  echo "ERROR: KAT probe exited $RC (decoder produced wrong values or was neutered)" >&2
  emit_ctrf "nearcore-kat" 0 1 0
  exit 1
fi

# Known answers decoded from the fixed SignedTransaction through near_primitives.
check "signer_id decodes to alice.near"  "signer=alice.near"   "$OUT"
check "receiver_id decodes to bob.near"  "receiver=bob.near"   "$OUT"
check "nonce decodes to 42"              "nonce=42"            "$OUT"
check "action count decodes to 0"        "actions=0"           "$OUT"
check "borsh round-trip is canonical"    "roundtrip=OK"        "$OUT"

emit_ctrf "nearcore-kat" "$PASS" "$FAIL"
