#!/usr/bin/env bash
#
# mayhem/test.sh — RUN upstream's own TPM 2 shell tests (tests/test_tpm2_*) against the normal
# (unsanitized) swtpm build in mayhem/build-test made by mayhem/build.sh. exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
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

# Upstream's tests drive swtpm / swtpm_ioctl / swtpm_bios over the control and data channels and
# assert responses (TPM result codes, hashes, PCR values, state round-trips). The selection is every
# TPM 2 test that runs without root, a TSS stack, CUSE, vTPM proxy or swtpm_setup's external tools.
TESTS=(
  test_tpm2_print_states test_tpm2_ctrlchannel2 test_tpm2_getcap test_tpm2_hashing
  test_tpm2_hashing2 test_tpm2_save_load_state test_tpm2_save_load_encrypted_state
  test_tpm2_encrypted_state test_tpm2_setbuffersize test_tpm2_resume_volatile test_tpm2_locality
  test_tpm2_print_capabilities test_tpm2_init test_tpm2_parameters test_tpm2_migration_key
)
BUILDDIR="$SRC/mayhem/build-test"
for b in src/swtpm/swtpm src/swtpm_ioctl/swtpm_ioctl; do
  [ -x "$BUILDDIR/$b" ] || { echo "missing $BUILDDIR/$b — run mayhem/build.sh first" >&2; emit_ctrf swtpm-tests 0 1; exit 1; }
done

passed=0 failed=0 skipped=0
LOGDIR="$(mktemp -d "${TMPDIR:-/tmp}/swtpm-tests.XXXXXX")"
for t in "${TESTS[@]}"; do
  ( cd "$BUILDDIR/tests" && \
    abs_top_testdir="$SRC/tests" abs_top_builddir="$BUILDDIR" abs_top_srcdir="$SRC" \
    timeout 300 bash "$SRC/tests/$t" ) > "$LOGDIR/$t.log" 2>&1
  rc=$?
  case $rc in
    0)  echo "PASS: $t"; passed=$((passed + 1)) ;;
    77) echo "SKIP: $t"; skipped=$((skipped + 1)) ;;
    *)  echo "FAIL: $t (rc=$rc)"; tail -20 "$LOGDIR/$t.log"; failed=$((failed + 1)) ;;
  esac
done
rm -rf "$LOGDIR"
emit_ctrf swtpm-tests "$passed" "$failed" "$skipped"
