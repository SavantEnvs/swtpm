#!/usr/bin/env bash
#
# mayhem/build.sh — build swtpm's fuzz harnesses (sanitized, libFuzzer) and a normal build of
# swtpm for upstream's own test suite (mayhem/test.sh). Re-runnable and offline: libtpms comes
# from /opt/toolchains/deps (Dockerfile), everything else from apt.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${PKG_CONFIG_PATH:=/opt/toolchains/deps/libtpms-0.11.0/lib/pkgconfig}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS PKG_CONFIG_PATH

cd "$SRC"

# configure is generated (gitignored upstream); regenerate it when missing.
[ -x configure ] || autoreconf -fi

# swtpm's Makefiles do not add LIBTPMS_CFLAGS (they expect libtpms in /usr/include).
TPMS_CPPFLAGS="$(pkg-config --cflags libtpms)"
COMMON_CONF=(--without-cuse --without-seccomp --without-selinux --disable-hardening)

# 1) Normal build (project's own flags) for upstream's test suite.
mkdir -p mayhem/build-test
(
  cd mayhem/build-test
  [ -f Makefile ] || env -u CFLAGS -u LDFLAGS ../../configure "${COMMON_CONF[@]}" \
      --enable-tests --with-gnutls --disable-shared --enable-static CC="$CC" CFLAGS="-O2 -g $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" CPPFLAGS="$TPMS_CPPFLAGS"
  make -j"$MAYHEM_JOBS"
)

# 2) Sanitized + coverage-instrumented static build of the swtpm library for the harnesses.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1"
mkdir -p mayhem/build-fuzz
(
  cd mayhem/build-fuzz
  [ -f Makefile ] || ../../configure "${COMMON_CONF[@]}" --disable-tests --without-gnutls \
      --disable-shared --enable-static CC="$CC" CFLAGS="$FUZZ_CFLAGS" CPPFLAGS="$TPMS_CPPFLAGS"
  make -j"$MAYHEM_JOBS" -C src/utils
  make -j"$MAYHEM_JOBS" -C src/swtpm libswtpm_libtpms.la
)

LIBSWTPM="$SRC/mayhem/build-fuzz/src/swtpm/.libs/libswtpm_libtpms.a"
INCS=(-I"$SRC/mayhem/build-fuzz" -I"$SRC/mayhem/build-fuzz/include" -I"$SRC/include"
      -I"$SRC/include/swtpm" -I"$SRC/src/utils" -I"$SRC/src/swtpm" -I"$SRC/mayhem/harnesses"
      $(pkg-config --cflags libtpms glib-2.0 json-glib-1.0))
LIBS=($(pkg-config --static --libs libtpms) $(pkg-config --libs json-glib-1.0 glib-2.0 libcrypto) -lpthread -lm)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/mayhem/build-fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/mayhem/build-fuzz/standalone_main.o"

for h in fuzz_ctrlchannel fuzz_nvstore_linear fuzz_stateblob fuzz_keyfile fuzz_profile fuzz_options fuzz_datachannel; do
  $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 "${INCS[@]}" \
      -c "$SRC/mayhem/harnesses/$h.c" -o "$SRC/mayhem/build-fuzz/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/build-fuzz/$h.o" \
      "$SRC/mayhem/build-fuzz/lsan_off.o" "$LIBSWTPM" "${LIBS[@]}" -o "$SRC/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/mayhem/build-fuzz/standalone_main.o" "$SRC/mayhem/build-fuzz/$h.o" \
      "$SRC/mayhem/build-fuzz/lsan_off.o" "$LIBSWTPM" "${LIBS[@]}" -o "$SRC/$h-standalone"
done

# swtpm_setup's profile handling: src/swtpm_setup/profile.c is compiled into the swtpm_setup
# program only, so build it (and the helpers it calls) with the fuzz flags next to the harness.
SETUP_INCS=(-I"$SRC/mayhem/build-fuzz" -I"$SRC/mayhem/build-fuzz/src/utils" -I"$SRC/include"
            -I"$SRC/src/utils" -I"$SRC/src/swtpm_setup" -I"$SRC/mayhem/harnesses" $(pkg-config --cflags glib-2.0 json-glib-1.0))
SETUP_OBJS=()
for f in profile swtpm_setup_utils; do
  $CC $FUZZ_CFLAGS "${SETUP_INCS[@]}" -c "$SRC/src/swtpm_setup/$f.c" -o "$SRC/mayhem/build-fuzz/setup_$f.o"
  SETUP_OBJS+=("$SRC/mayhem/build-fuzz/setup_$f.o")
done
$CC $FUZZ_CFLAGS "${SETUP_INCS[@]}" -c "$SRC/mayhem/harnesses/fuzz_setup_profile.c" -o "$SRC/mayhem/build-fuzz/fuzz_setup_profile.o"
SETUP_LIBS=("$SRC/mayhem/build-fuzz/src/utils/.libs/libswtpm_utils.a" $(pkg-config --libs json-glib-1.0 glib-2.0 libcrypto))
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/build-fuzz/fuzz_setup_profile.o" "${SETUP_OBJS[@]}" \
    "$SRC/mayhem/build-fuzz/lsan_off.o" "${SETUP_LIBS[@]}" -o "$SRC/fuzz_setup_profile"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/mayhem/build-fuzz/standalone_main.o" "$SRC/mayhem/build-fuzz/fuzz_setup_profile.o" \
    "${SETUP_OBJS[@]}" "$SRC/mayhem/build-fuzz/lsan_off.o" "${SETUP_LIBS[@]}" -o "$SRC/fuzz_setup_profile-standalone"
