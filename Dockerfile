FROM docker.io/library/alpine:3.22.2 AS zig

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

FROM docker.io/library/rust:1.90.0 AS cargo-zigbuild

RUN cargo install cargo-zigbuild

FROM docker.io/library/rust:1.90.0 AS bpf-linker

RUN cargo install bpf-linker

FROM docker.io/library/rust:1.90.0 AS builder

COPY --from=zig /opt/zig /opt/zig
ENV PATH="/opt/zig:${PATH}"
COPY --from=cargo-zigbuild "/usr/local/cargo/bin/cargo-zigbuild" "/usr/local/bin/cargo-zigbuild"
COPY --from=bpf-linker "/usr/local/cargo/bin/bpf-linker" "/usr/local/bin/bpf-linker"

RUN export ARCH="$(uname -m)" && \
    case "${ARCH}" in \
        x86_64) ;; \
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

RUN cargo install cargo-set-version

RUN VERSION=$(git describe --tags $(git rev-list --tags --max-count=1) | sed 's/^v//') && \
    cargo-set-version ${VERSION}

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
    cp "target/x86_64-unknown-linux-musl/release/snoopy" "/usr/local/bin/snoopy_x86_64-unknown-linux-musl" && \
    cp "target/aarch64-unknown-linux-musl/release/snoopy" "/usr/local/bin/snoopy_aarch64-unknown-linux-musl" && \
    cp "target/riscv64gc-unknown-linux-musl/release/snoopy" "/usr/local/bin/snoopy_riscv64-unknown-linux-musl" && \
    cp "target/powerpc64le-unknown-linux-musl/release/snoopy" "/usr/local/bin/snoopy_powerpc64le-unknown-linux-musl" && \
    cp "target/armv7-unknown-linux-musleabi/release/snoopy" "/usr/local/bin/snoopy_armv7-unknown-linux-musleabi"

FROM docker.io/library/alpine:3.22.2

# COPY --from=snoopy "/usr/local/bin/snoopy" "/usr/local/bin/snoopy"
COPY --from=snoopy "/usr/local/bin/snoopy_x86_64-unknown-linux-musl" "/usr/local/bin/snoopy_x86_64-unknown-linux-musl"
COPY --from=snoopy "/usr/local/bin/snoopy_aarch64-unknown-linux-musl" "/usr/local/bin/snoopy_aarch64-unknown-linux-musl"
COPY --from=snoopy "/usr/local/bin/snoopy_armv7-unknown-linux-musleabi" "/usr/local/bin/snoopy_armv7-unknown-linux-musleabi"
COPY --from=snoopy "/usr/local/bin/snoopy_riscv64-unknown-linux-musl" "/usr/local/bin/snoopy_riscv64-unknown-linux-musl"
COPY --from=snoopy "/usr/local/bin/snoopy_powerpc64le-unknown-linux-musl" "/usr/local/bin/snoopy_powerpc64le-unknown-linux-musl"

RUN apk add --no-cache "dumb-init" && ls -lah "/usr/local/bin/"

ENTRYPOINT [ "dumb-init", "--" ]
CMD [ "snoopy_x86_64-unknown-linux-musl" ]
