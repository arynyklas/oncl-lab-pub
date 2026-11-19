#
# The plugin builder: the reference build of publishers' plugins
# (docs/design/publishers.md, «Сборщик»; docs/dev/publishers.md for its use), published as
# ghcr.io/arynyklas/oncl-plugin-builder by .github/workflows/plugin-builder.yml. The image is
# the reference by its digest in publishers/builders.toml, never by this file: a rebuild of
# this file gives another image (the Debian packages below are not pinned), so a digest once
# listed there is never replaced.
#
# Built from the root of the repository at the commit the image is for:
#
#   docker build -f xtask/assets/plugin-builder/Dockerfile -t oncl-plugin-builder .
#
# Inside:
#   - Debian 13 slim, by digest;
#   - Rust 1.99.1 (rustc, cargo, the standard libraries of x86_64-unknown-linux-gnu and
#     wasm32-unknown-unknown), the release tarballs checked against their SHA-256 and installed
#     in /opt/rust. There is no rustup, so a rust-toolchain.toml of the sources is never read;
#   - gcc and the C library headers, for the build scripts and procedural macros Cargo builds
#     for the host; git, for `oncl-pack source --git`;
#   - /usr/local/bin/oncl-pack, built here from the same commit (its crates fetched in one
#     step, the build itself without the network), the entry point.
#
# It runs as the unprivileged user 10001 with CARGO_HOME=/cargo (mount a volume) and the work
# directory /build (mount a tmpfs or a volume: the build unpacks the sources at /build/src and
# builds in /build/target).

# Debian 13 slim by digest; update together with the comment above.
ARG BASE_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# The toolchain: the release and its date on static.rust-lang.org/dist, then the SHA-256 of each
# tarball as channel-rust-1.99.1.toml lists them (xz_hash). Update all together, and
# rust-toolchain.toml with them.
ARG RUST_VERSION=1.99.1
ARG RUST_DATE=2026-10-15
ARG RUSTC_SHA256=2ff05ff9c08a90861e7f6e4065b40a8b87463b4576186fd613871c3e37f2091f
ARG CARGO_SHA256=53f3521949404d595efb06a55c12c5658d4ed1c75566f33d3d514eaebe70bd8a
ARG STD_HOST_SHA256=109b074225bf5b9ea3820890876bfdf4ed161adbfaf94b2b4b5984c85ee5d958
ARG STD_WASM_SHA256=5f628f857dd00a8aa3fcac2e275665d2782066a5795274ed124c5b560f46423c

FROM ${BASE_IMAGE} AS toolchain
ARG RUST_VERSION
ARG RUST_DATE
ARG RUSTC_SHA256
ARG CARGO_SHA256
ARG STD_HOST_SHA256
ARG STD_WASM_SHA256
RUN apt-get -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3 update \
 && apt-get -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3 \
        install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/rust
RUN set -eu; \
    base="https://static.rust-lang.org/dist/${RUST_DATE}"; \
    for spec in \
        "rustc-${RUST_VERSION}-x86_64-unknown-linux-gnu ${RUSTC_SHA256}" \
        "cargo-${RUST_VERSION}-x86_64-unknown-linux-gnu ${CARGO_SHA256}" \
        "rust-std-${RUST_VERSION}-x86_64-unknown-linux-gnu ${STD_HOST_SHA256}" \
        "rust-std-${RUST_VERSION}-wasm32-unknown-unknown ${STD_WASM_SHA256}"; \
    do \
        set -- $spec; \
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 30 \
            -o "$1.tar.xz" "$base/$1.tar.xz"; \
        echo "$2  $1.tar.xz" | sha256sum -c -; \
        tar -xJf "$1.tar.xz"; \
        "$1/install.sh" --prefix=/opt/rust --disable-ldconfig; \
    done; \
    rm -rf /tmp/rust /opt/rust/share/doc; \
    /opt/rust/bin/rustc -vV; \
    test -x "/opt/rust/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"

FROM ${BASE_IMAGE} AS runtime
RUN apt-get -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3 update \
 && apt-get -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3 \
        install -y --no-install-recommends ca-certificates gcc libc6-dev git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=toolchain /opt/rust /opt/rust
ENV PATH=/opt/rust/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# oncl-pack from this commit: the workspace's crates fetched for Linux, then built offline.
FROM runtime AS pack
# Cargo's parallelism while building oncl-pack (`--build-arg CARGO_BUILD_JOBS=…`); it changes
# nothing in the image.
ARG CARGO_BUILD_JOBS=8
ENV CARGO_HOME=/opt/cargo-home
WORKDIR /src
COPY . .
RUN cargo fetch --locked --target x86_64-unknown-linux-gnu
RUN --network=none cargo build --frozen --release -p oncl-pack \
 && install -m 0755 target/release/oncl-pack /oncl-pack

FROM runtime
ARG REVISION=unknown
LABEL org.opencontainers.image.title="oncl-plugin-builder" \
      org.opencontainers.image.description="OpenNCALayer's reference builder of plugins: canonical source archives and reproducible .onclp builds" \
      org.opencontainers.image.source="https://github.com/arynyklas/OpenNCALayer" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0"
# One unprivileged account with a fixed id; /cargo and /build are its own, so a new named
# volume mounted there starts owned by it.
RUN groupadd --gid 10001 builder \
 && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/builder \
        --shell /usr/sbin/nologin builder \
 && install -d -m 0755 -o 10001 -g 10001 /cargo /build
COPY --from=pack /oncl-pack /usr/local/bin/oncl-pack
ENV CARGO_HOME=/cargo \
    HOME=/home/builder
USER 10001:10001
WORKDIR /build
ENTRYPOINT ["/usr/local/bin/oncl-pack"]
CMD ["--help"]
