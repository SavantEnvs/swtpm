# syntax=docker/dockerfile:1.7
#
# Commit image for swtpm (software TPM emulator). Builds on the org base.
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

# Build deps from apt (libtpms comes from source below: trixie ships 0.9.2, swtpm needs >= 0.11).
# socat/expect/gnutls-bin/python3 are used by upstream's own shell test suite (mayhem/test.sh).
USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        libssl-dev libtasn1-6-dev libjson-glib-dev libglib2.0-dev libgmp-dev \
        libgnutls28-dev gnutls-bin openssl socat expect python3 net-tools iproute2 gawk \
        libtool automake autoconf pkg-config \
 && rm -rf /var/lib/apt/lists/*

# libtpms 0.11.0 (master, pinned by commit + sha256), static, uninstrumented, DWARF 3 (SPEC §6.2 item 19).
ARG LIBTPMS_COMMIT=165c303ccc4784fb3d8cadbb3d71205641ba380b
ARG LIBTPMS_SHA256=b5b4917ab5f9360377a93f74b406fbc2e5ee0a1a0b6d18018762793d03f48741
RUN d=/opt/toolchains/deps/libtpms-0.11.0 && mkdir -p "$d/src" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz https://github.com/stefanberger/libtpms/archive/${LIBTPMS_COMMIT}.tar.gz \
 && echo "${LIBTPMS_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" \
 && cd "$d/src" && autoreconf -fi \
 && cd /tmp/dep-build \
 && "$d/src/configure" --prefix="$d" --with-openssl --with-tpm2 --disable-shared --enable-static \
        CC=clang CFLAGS="-O2 -g -gdwarf-3" \
 && make -j"$(nproc)" install \
 && cd / && rm -rf /tmp/dep-build /tmp/dep.tgz "$d/src/autom4te.cache" && chmod -R a+rX "$d"
ENV PKG_CONFIG_PATH=/opt/toolchains/deps/libtpms-0.11.0/lib/pkgconfig

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
