FROM docker.io/library/alpine:3.21.0 AS zig

ARG ZIG_VERSION=0.14.0

RUN export ARCH="$(uname -m)" && \
    case "${ARCH}" in \
        x86_64) ;; \
        aarch64) ;; \
        *) printf "Unsupported architecture: %s\n" "${ARCH}"; exit 1 ;; \
    esac && \
    set -eux && \
    wget -O "/zig.tar.gz" "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ARCH}-${ZIG_VERSION}.tar.xz" && \
    tar -xJf "/zig.tar.gz" -C /opt && \
    cd /opt && \
    mv "zig-linux-${ARCH}-${ZIG_VERSION}" "zig"

FROM docker.io/library/rust:1.86.0 AS cargo-zigbuild

RUN cargo install cargo-zigbuild

FROM docker.io/library/rust:1.86.0 AS bpf-linker

RUN cargo install bpf-linker

FROM docker.io/library/rust:1.86.0 AS builder

COPY --from=zig /opt/zig /opt/zig
ENV PATH="/opt/zig:${PATH}"
COPY --from=cargo-zigbuild "/usr/local/cargo/bin/cargo-zigbuild" "/usr/local/bin/cargo-zigbuild"
COPY --from=bpf-linker "/usr/local/cargo/bin/bpf-linker" "/usr/local/bin/bpf-linker"

RUN export ARCH="$(uname -m)" && \
    case "${ARCH}" in \
        x86_64) ;; \
        aarch64) ;; \
        *) printf "Unsupported architecture: %s\n" "${ARCH}"; exit 1 ;; \
    esac && \
    set -eux && \
    rustup toolchain install "nightly" --component "rust-src" && \
    # rustup target add "${ARCH}-unknown-linux-musl"
    rustup target add "x86_64-unknown-linux-musl" && \
    rustup target add "aarch64-unknown-linux-musl" && \
    rustup target add "armv7-unknown-linux-musleabi" && \
    rustup target add "powerpc64le-unknown-linux-musl" && \
    rustup target add "riscv64gc-unknown-linux-musl"

FROM builder AS snoopy

COPY . /app
WORKDIR /app

RUN export ARCH="$(uname -m)" && \
    case "${ARCH}" in \
        x86_64) ;; \
        aarch64) ;; \
        *) printf "Unsupported architecture: %s\n" "${ARCH}"; exit 1 ;; \
    esac && \
    set -eux && \
    # cargo zigbuild --package "snoopy" --release --target="${ARCH}-unknown-linux-musl" && \
    cargo zigbuild --package "snoopy" --release --target="x86_64-unknown-linux-musl" && \
    cargo zigbuild --package "snoopy" --release --target="aarch64-unknown-linux-musl" && \
    cargo zigbuild --package "snoopy" --release --target="armv7-unknown-linux-musleabi" && \
    cargo zigbuild --package "snoopy" --release --target="riscv64gc-unknown-linux-musl" && \
    cargo zigbuild --package "snoopy" --release --target="powerpc64le-unknown-linux-musl" && \
    mkdir "dist" && \
    # cp "target/${ARCH}-unknown-linux-musl/release/snoopy" "/usr/local/bin/snoopy"
    cp "target/x86_64-unknown-linux-musl/release/snoopy" "/usr/local/bin/x86_64-snoopy" && \
    cp "target/aarch64-unknown-linux-musl/release/snoopy" "/usr/local/bin/aarch64-snoopy" && \
    cp "target/riscv64gc-unknown-linux-musl/release/snoopy" "/usr/local/bin/riscv64-snoopy" && \
    cp "target/powerpc64le-unknown-linux-musl/release/snoopy" "/usr/local/bin/powerpc64le-snoopy" && \
    cp "target/armv7-unknown-linux-musleabi/release/snoopy" "/usr/local/bin/armv7-snoopy"

FROM docker.io/library/alpine:3.21.0

# COPY --from=snoopy "/usr/local/bin/snoopy" "/usr/local/bin/snoopy"
COPY --from=snoopy "/usr/local/bin/x86_64-snoopy" "/usr/local/bin/x86_64-snoopy"
COPY --from=snoopy "/usr/local/bin/aarch64-snoopy" "/usr/local/bin/aarch64-snoopy"
COPY --from=snoopy "/usr/local/bin/armv7-snoopy" "/usr/local/bin/armv7-snoopy"
COPY --from=snoopy "/usr/local/bin/riscv64-snoopy" "/usr/local/bin/riscv64-snoopy"
COPY --from=snoopy "/usr/local/bin/powerpc64le-snoopy" "/usr/local/bin/powerpc64le-snoopy"

RUN apk add --no-cache "dumb-init" && ls -lah "/usr/local/bin/"

ENTRYPOINT [ "dumb-init", "--" ]
CMD [ "x86_64-snoopy" ]
