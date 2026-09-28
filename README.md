# libfprint-goodixtls511

A [libfprint](https://fprint.freedesktop.org/) driver for the **Goodix `27c6:5117`**
USB fingerprint reader, which has no Linux support upstream. With it the reader works
through the standard stack (libfprint → fprintd → PAM): enrollment, verification,
identification, `sudo`, polkit and lock screens.

```
$ lsusb | grep 27c6
Bus 001 Device 002: ID 27c6:5117 Shenzhen Goodix Technology Co.,Ltd. Fingerprint Reader
```

**This driver was developed for, and tested only with, the Goodix `27c6:5117`.** It
declares only that USB ID and supports no other sensor. The name `goodixtls511` follows
libfprint's convention of naming drivers after the chip family (as `goodixmoc`,
`elanmoc` or `vfs5011` do) and matches the name used by earlier reverse-engineering
work on this family; it is not a claim that other `511x` sensors work.

> [!WARNING]
> Before the driver can talk to the sensor, the sensor has to be **provisioned**: its
> firmware is erased and re-flashed, and the key it shares with the Windows driver is
> replaced. After that **the reader stops working on Windows** (the Windows driver may
> re-provision it, this is untested). The original firmware cannot be read back, so
> there is no backup. Do this only if you accept that.

## Status

| | |
|---|---|
| Device | `27c6:5117` only, firmware `GF_ST411SEC_APP_12109` (installed by the provisioning tool) |
| Features | enroll, verify, identify (host-side matching, prints stored by fprintd) |
| Base | libfprint 1.94.100 |
| Tested on | one sensor, Arch Linux, fprintd 1.94.5 |

Results on that sensor:

- enrollment: 15/15 stages accepted;
- verification with the enrolled finger: 8/8 after the final fixes;
- verification with other fingers: 14/14 rejected (scores 0–1, threshold 40);
- on a recorded set (20 touches of the enrolled finger, 21 of other fingers, one person,
  random 15-touch templates): ~82% accepted at the first attempt, 0 false accepts.

These numbers come from a single person and a small set: they show the approach works,
they are not a measurement of security. Reports from other units are very welcome.

## How it works

- The sensor speaks Goodix's "message pack" protocol over a USB CDC data interface.
  Images are only sent through a **TLS 1.2 PSK** channel in which the sensor is the
  client; the driver runs the TLS server itself on OpenSSL memory BIOs.
- Frames are 64×80 pixels, 12 bit, stored with a stride of 88. Calibration registers
  are computed from the sensor's own OTP, so they fit each unit.
- The hardware finger-detection mode (FDT) does not work with the known parameters, so
  while an operation is running the driver polls ~6 frames/s and detects the finger
  against a background frame. Partial touches are rejected with "center your finger".
- The sensor is too small for libfprint's NBIS minutiae matcher (0–3 minutiae per image,
  every score 0), so the driver matches on the host with **SIGFM** (SIFT keypoints +
  geometric consistency, via OpenCV) and stores the features of each enrollment sample
  in the fprintd print. The rest of libfprint is untouched.

## Install

### 1. Build and install libfprint with the driver

This replaces your distribution's libfprint; all its other drivers keep working.

**Arch Linux** (and derivatives):

```sh
cd packaging/arch
makepkg -si        # replaces libfprint / libfprint-git / libfprint-tod
```

**Any other distribution**: install the build dependencies, then run `./build.sh --install`.

| Distribution | Build dependencies |
|---|---|
| Debian / Ubuntu | `git meson ninja-build pkg-config g++ libglib2.0-dev libgusb-dev libgudev-1.0-dev libpixman-1-dev libssl-dev libopencv-dev gobject-introspection libgirepository1.0-dev` |
| Fedora | `git meson gcc gcc-c++ glib2-devel libgusb-devel libgudev-devel pixman-devel openssl-devel opencv-devel gobject-introspection-devel` |

Only Arch has been tested; the other lists are best effort. OpenCV ≥ 4.5 and OpenSSL ≥ 3
are required.

`build.sh --install` writes over the files of your libfprint package, so a later
package update would overwrite the driver. Hold the package: `sudo apt-mark hold
libfprint-2-2` (Debian/Ubuntu) or `sudo dnf versionlock add libfprint` (Fedora).

### 2. Provision the sensor (once)

Needs Python 3 and pyusb (`python-pyusb`, `python3-usb` or `python3-pyusb`). fprintd
must not be using the reader.

```sh
sudo systemctl stop fprintd
sudo tools/goodix511-provision status      # read-only
sudo tools/goodix511-provision provision   # erase, write the PSK, flash 12109
```

The firmware is downloaded from
[goodix-fp-linux-dev/goodix-firmware](https://github.com/goodix-fp-linux-dev/goodix-firmware)
and checked against its SHA-256 before flashing; it is not redistributed here. The
provisioning sequence is the one of
[goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump); the standalone
tool reimplements it with pyusb only (its erase/flash path mirrors the sequence tested
with goodix-fp-dump, its read-only path was tested directly).

### 3. Enroll and use

```sh
fprintd-enroll -f right-index-finger
fprintd-verify
```

Press, hold ~1 s, lift completely, and move the finger a little between touches: the
sensor is small, so varied positions give a better template. fprintd first checks that
the finger is not already enrolled, which takes one extra touch.

Then enable `pam_fprintd` for `sudo`, polkit or your lock screen the way your
distribution documents it (e.g. `auth sufficient pam_fprintd.so` at the top of
`/etc/pam.d/sudo`). Keep a password fallback.

## Troubleshooting

- Debug log: `G_MESSAGES_DEBUG=all` (for fprintd, add it to the service environment).
- `GOODIX511_DUMP_DIR=/some/dir` saves every captured image as PGM. These are images of
  your fingerprint: do not share them publicly.
- "Unsupported firmware" / "unknown PSK": the sensor is not provisioned (or Windows
  re-provisioned it); run `goodix511-provision status`.
- Nothing happens on touch: check that no other process holds the reader and that
  the libfprint in use is this one (`fprintd-list $USER` shows
  "Goodix 5117 TLS Fingerprint Sensor").

## Limitations and security notes

- Only `27c6:5117` with firmware `GF_ST411SEC_APP_12109` is supported. Other Goodix
  sensors are not handled by this driver, even where the protocol looks similar.
- No hardware finger detection: the sensor is polled while an operation is active.
- The TLS PSK is the well-known all-zero key used by the Linux tools: the channel
  protects nothing against someone with access to the USB bus.
- Stored prints contain SIFT features of the enrollment images (biometric data), kept by
  fprintd in `/var/lib/fprint` like any other driver's prints.
- The match threshold (40) was chosen with a large margin over the impostor scores
  seen (≤ 5); it was not validated on a large population.

## Credits and license

- Driver, SIGFM integration, provisioning tool and packaging: developed by
  [danieledisint](https://github.com/danieledisint).
- Driver (`driver/`, `patches/`): LGPL-2.1-or-later, like libfprint (`LICENSE`).
- Provisioning tool (`tools/`): MIT, derived from goodix-fp-dump.
- Protocol knowledge, MCU configuration and provisioning sequence:
  [goodix-fp-linux-dev](https://github.com/goodix-fp-linux-dev) (goodix-fp-dump and the
  libfprint fork for the 5110). SIGFM matcher: from the same fork, with its match
  de-duplication fixed (it compared only the y coordinate).
