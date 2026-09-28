#!/bin/sh
# Build libfprint with the goodixtls511 driver on any distribution.
#
#   ./build.sh              fetch libfprint, add the driver, build in ./work
#   ./build.sh --install    ... and install it over the system libfprint (sudo)
#
# The result replaces the distribution's libfprint: every other driver keeps
# working, the goodixtls511 driver is added.
set -eu

LIBFPRINT_URL=https://gitlab.freedesktop.org/libfprint/libfprint.git
LIBFPRINT_TAG=v1.94.100
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$HERE/work
SRC=$WORK/libfprint

if [ ! -d "$SRC" ]; then
    mkdir -p "$WORK"
    git clone --depth 1 --branch "$LIBFPRINT_TAG" "$LIBFPRINT_URL" "$SRC"
fi

if [ ! -d "$SRC/libfprint/drivers/goodixtls511" ]; then
    cp -r "$HERE/driver/goodixtls511" "$SRC/libfprint/drivers/"
    git -C "$SRC" apply "$HERE/patches/libfprint-1.94.100-goodixtls511.patch"
fi

if [ ! -d "$WORK/build" ]; then
    meson setup "$WORK/build" "$SRC" \
        --prefix=/usr --buildtype=release \
        -Ddoc=false -Dinstalled-tests=false
fi
meson compile -C "$WORK/build"

if [ "${1:-}" = "--install" ]; then
    sudo meson install -C "$WORK/build"
    sudo udevadm hwdb --update || true
    echo "Installed. Restart fprintd: sudo systemctl restart fprintd"
fi
