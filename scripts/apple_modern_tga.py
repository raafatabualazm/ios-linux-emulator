#!/usr/bin/env python3
"""Minimal TGA reader for Apple's `usr/share/progressui/*.tga` boot artwork.

Supports uncompressed (type 2) and RLE (type 10) true-colour images at 24 or 32 bpp,
which is what the retained iOS 27 restore ramdisk ships. Returns a numpy array
shaped (height, width, 4) in RGBA with the origin at the top left.

Used by the logo acceptance gate to build the reference mask it looks for, and by the
gate's own self-check to synthesise a true-positive frame.

SPDX-License-Identifier: GPL-2.0-or-later
"""
import struct

import numpy as np


def read(path):
    with open(path, 'rb') as fh:
        data = fh.read()
    (idlen, cmaptype, imgtype, _cmapfirst, cmaplen, cmapbits,
     _x0, _y0, width, height, bpp, descriptor) = struct.unpack('<BBBHHBHHHHBB', data[:18])
    if imgtype not in (2, 10):
        raise ValueError('%s: TGA image type %d is not a true-colour image' % (path, imgtype))
    if bpp not in (24, 32):
        raise ValueError('%s: %d bits per pixel is not supported' % (path, bpp))
    off = 18 + idlen + (cmaplen * (cmapbits // 8) if cmaptype else 0)
    nbytes = bpp // 8
    npix = width * height
    if imgtype == 2:
        raw = np.frombuffer(data, dtype=np.uint8, count=npix * nbytes, offset=off)
        flat = raw.reshape(npix, nbytes)
    else:
        flat = np.zeros((npix, nbytes), dtype=np.uint8)
        i, p = off, 0
        while p < npix:
            packet = data[i]
            i += 1
            count = (packet & 0x7F) + 1
            if packet & 0x80:
                flat[p:p + count] = np.frombuffer(data, dtype=np.uint8, count=nbytes, offset=i)
                i += nbytes
            else:
                run = np.frombuffer(data, dtype=np.uint8, count=count * nbytes,
                                    offset=i).reshape(count, nbytes)
                flat[p:p + count] = run
                i += count * nbytes
            p += count
    img = flat.reshape(height, width, nbytes)
    rgba = np.zeros((height, width, 4), dtype=np.uint8)
    rgba[..., 0] = img[..., 2]          # TGA stores BGR(A)
    rgba[..., 1] = img[..., 1]
    rgba[..., 2] = img[..., 0]
    rgba[..., 3] = img[..., 3] if nbytes == 4 else 255
    if not descriptor & 0x20:           # bit 5 clear = origin at the bottom left
        rgba = rgba[::-1]
    return rgba


def mask(path, threshold=128):
    """Foreground mask of the artwork: alpha if it has one, else luminance."""
    rgba = read(path)
    if rgba[..., 3].min() != 255:
        return rgba[..., 3] > threshold
    lum = (0.299 * rgba[..., 0] + 0.587 * rgba[..., 1] + 0.114 * rgba[..., 2])
    return lum > threshold


if __name__ == '__main__':
    import sys
    for p in sys.argv[1:]:
        rgba = read(p)
        m = mask(p)
        print('%-60s %dx%d alpha=%s fg=%d (%.1f%%)' % (
            p.split('/')[-1], rgba.shape[1], rgba.shape[0],
            'yes' if rgba[..., 3].min() != 255 else 'no', int(m.sum()),
            100.0 * m.sum() / m.size))
