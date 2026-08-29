#!/usr/bin/env bash
#
# mayhem/build.sh — build nearcore's borsh transaction decoder as a sanitized
# libFuzzer binary (OSS-Fuzz Rust path: cargo-fuzz + ASan via RUSTFLAGS), plus a
# small clean KAT probe binary that mayhem/test.sh runs as the behavioral oracle.
#
# Runs inside the commit image (RUST mayhem/Dockerfile) as `mayhem` in /mayhem.
# Toolchain + cargo registry live at $CARGO_HOME=/opt/toolchains/rust/cargo.
#
# nearcore ships a root rust-toolchain.toml pinning STABLE 1.95.0, which would
# hijack every bare `cargo` in the tree (and ASan needs nightly). We override it for
# the whole script with RUSTUP_TOOLCHAIN (higher precedence than rust-toolchain.toml),
# pointing at the nightly the Dockerfile installed.
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (online) populates the cargo registry under $CARGO_HOME and
#     resolves the additive crates' committed lockfiles.
#   - The PATCH re-run resolves crates from that cache (CARGO_NET_OFFLINE=true is
#     exported by the runtime), so we do NOT hard-code `--offline` here.
#
# We use ADDITIVE crates under mayhem/ (own standalone [workspace] tables) that only
# CALL the unmodified near-primitives / near-crypto path crates. Upstream is untouched.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Force the nightly regardless of nearcore's root rust-toolchain.toml (1.95.0 stable).
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-2026-08-27}"

: "${MAYHEM_JOBS:=$(nproc)}"
export CARGO_BUILD_JOBS="$MAYHEM_JOBS"   # cargo-fuzz has no --jobs flag

cd "$SRC"

# Sanitizers (§6.1): the base provides clang $SANITIZER_FLAGS (ASan+UBSan, halting).
# rustc can't consume clang flags, but we honor the KNOB: a non-empty $SANITIZER_FLAGS
# instruments the Rust build with ASan (the OSS-Fuzz Rust path); an explicit empty
# `--build-arg SANITIZER_FLAGS=` yields an un-sanitized build.
RUST_SAN=""
if [ -n "${SANITIZER_FLAGS:-}" ]; then
  RUST_SAN="-Zsanitizer=address"
fi

# DWARF < 4 (§6.2 item 10): Mayhem triage can't read DWARF >= 4, and rustc nightly
# defaults to DWARF-5. Pin -Zdwarf-version=3 for Rust and -gdwarf-3 for the cc shim.
export RUSTFLAGS="${RUSTFLAGS:-} ${RUST_DEBUG_FLAGS:-} --cfg fuzzing ${RUST_SAN} -Zdwarf-version=3 -Cdebuginfo=1 -Cforce-frame-pointers"
export CFLAGS="${CFLAGS:-} -gdwarf-3"
export CXXFLAGS="${CXXFLAGS:-} -gdwarf-3"

# The bundled ASan runtime archive `-Zsanitizer=address` links is precompiled with
# clang (DWARF-5, full debug info), whose CU would otherwise land at .debug_info
# offset 0 and fail the DWARF < 4 gate. Strip its debug info (a toolchain artifact,
# not project code). Idempotent, so the offline PATCH re-run stays clean.
if [ -n "${RUST_SAN}" ]; then
  RT_LIB_DIR="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/lib"
  for asan in "$RT_LIB_DIR"/librustc-*_rt.asan.a; do
    [ -f "$asan" ] || continue
    if [ -w "$asan" ]; then
      objcopy --strip-debug "$asan" "$asan.stripped" && mv "$asan.stripped" "$asan"
      echo "stripped debug info from bundled ASan runtime: $asan"
    fi
  done
fi

FUZZ_DIR="mayhem/fuzz"
TRIPLE="x86_64-unknown-linux-gnu"

# One binary per fuzz target (discovered from fuzz_targets/).
FUZZ_TARGETS=()
for f in "$FUZZ_DIR"/fuzz_targets/*.rs; do
  FUZZ_TARGETS+=("$(basename "${f%.*}")")
done
[ "${#FUZZ_TARGETS[@]}" -gt 0 ] || { echo "ERROR: no fuzz targets under $FUZZ_DIR/fuzz_targets/" >&2; exit 1; }

echo "=== cargo fuzz build (toolchain=$RUSTUP_TOOLCHAIN, ASan via RUSTFLAGS) ==="
echo "RUSTFLAGS=$RUSTFLAGS"
echo "targets: ${FUZZ_TARGETS[*]}"

# mayhem/fuzz is its OWN standalone workspace, so cargo-fuzz writes to
# mayhem/fuzz/target/<triple>/release/<t> (NOT the nearcore root target/).
for t in "${FUZZ_TARGETS[@]}"; do
  echo "--- building fuzz target: $t ---"
  cargo fuzz build --fuzz-dir "$FUZZ_DIR" -O --debug-assertions "$t"
  bin="$SRC/$FUZZ_DIR/target/$TRIPLE/release/$t"
  [ -x "$bin" ] || { echo "ERROR: expected fuzz binary not found at $bin" >&2; exit 1; }
  cp "$bin" "/mayhem/$t"
  echo "built /mayhem/$t"
done

# ── KAT probe (the oracle) — a CLEAN, dynamically-linked binary (no ASan, no
# -gdwarf-3): it must be an honest oracle, not an instrumented one. Built with the
# same nightly (near-primitives compiles on it, verified). ────────────────────────
echo "=== building KAT probe (clean, dynamically linked) ==="
env -u RUSTFLAGS -u CFLAGS -u CXXFLAGS \
  cargo build --release --manifest-path mayhem/kat/Cargo.toml
KAT_BIN="$SRC/mayhem/kat/target/release/kat"
[ -x "$KAT_BIN" ] || { echo "ERROR: KAT probe not built at $KAT_BIN" >&2; exit 1; }
cp "$KAT_BIN" /mayhem/kat
echo "built /mayhem/kat"

# Regression guard: the oracle MUST stay dynamically linked or the sabotage shim
# (LD_PRELOAD constructor) can't neuter it and the oracle silently degrades.
if ! file /mayhem/kat | grep -q 'dynamically linked'; then
  echo "ERROR: /mayhem/kat is not dynamically linked — oracle would be sabotage-immune" >&2
  file /mayhem/kat >&2
  exit 1
fi
echo "confirmed: /mayhem/kat is dynamically linked"

echo "build.sh complete"
