# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — RUST target (cargo / cargo-fuzz) for nearcore. Builds ON
# TOP of the org C/C++ base (ghcr.io/savantenvs/base), adding a pinned Rust nightly +
# cargo-fuzz under /opt/toolchains/rust, then runs mayhem/build.sh + mayhem/test.sh.
#
# The Rust toolchain + cargo registry live at a FIXED, $HOME-independent prefix
# (/opt/toolchains/rust) so the offline PATCH re-run (different $HOME) still finds the
# cache the first online build populated (SPEC §6.5).
#
# nearcore pins STABLE 1.95.0 in its root rust-toolchain.toml (which would hijack bare
# cargo, and ASan needs nightly). build.sh overrides it with RUSTUP_TOOLCHAIN; here we
# install a nightly NEWER than 1.95.0 so nearcore's edition-2024 / rust-version="1.95.0"
# crates still compile (an older ASan nightly is rejected by cargo's rust-version gate).
#
# Build (from the repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) -t nearcore-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS

# nightly-2026-08-27 reports rustc 1.100.0-nightly (>= nearcore's rust-version 1.95.0)
# and post-dates the old unstable-feature traps (zerocopy/avx512, generic_arg_infer).
ARG RUST_CHANNEL=nightly-2026-08-27
ARG CARGO_FUZZ_VERSION=0.13.2

ENV RUSTUP_HOME=/opt/toolchains/rust/rustup \
    CARGO_HOME=/opt/toolchains/rust/cargo \
    PATH=/opt/toolchains/rust/cargo/bin:${PATH}

USER root
RUN install -d /opt/toolchains/rust \
 && curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
        --default-toolchain "${RUST_CHANNEL}" \
 && rustup component add rust-src --toolchain "${RUST_CHANNEL}" \
 && cargo install cargo-fuzz --version "${CARGO_FUZZ_VERSION}" --locked \
 && rm -f /tmp/rustup-init.sh \
 # The commit build AND the offline PATCH re-run run as `mayhem` (2000): it must read
 # the toolchain and read/refresh the cargo registry cache, so hand the prefix to 2000.
 && chown -R 2000:2000 /opt/toolchains/rust

# Source enters from the build CONTEXT (CI checkout): the FULL repo (incl. .git) → /mayhem.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Populates $CARGO_HOME (online, this first build) and builds the sanitized fuzz
# target(s) + the clean KAT probe.
RUN bash mayhem/build.sh

# Run the behavioral oracle at build time (a failing suite fails the build).
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
