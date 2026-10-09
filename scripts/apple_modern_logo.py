"""Decide whether Apple's boot logo is drawn on a framebuffer capture.

The modern board's scanout is 1024x768 and the only thing that has ever appeared on it
so far is XNU's own 8x16 text console. Apple's `restored_external` draws the logo by
blitting one of the `usr/share/progressui/applelogo*.tga` images through an
IOMobileFramebuffer user client, so the acceptance test for "real pixels" is: does the
capture contain that exact artwork?

The check is a shape match, not "are there non-black pixels":

  * the capture is reduced to a foreground mask (luminance above a threshold derived
    from the capture itself, so a dimmed swap still matches);
  * for every candidate artwork file, the intersection of that mask with the artwork's
    own alpha mask is computed at *every* offset at once, by FFT cross-correlation;
  * the score is intersection-over-union, and the best offset over all candidates and
    all offsets wins.

IoU is used rather than coverage because coverage alone is satisfied by a white
rectangle, and a screen full of console text has a very low IoU against a 300x300
apple silhouette (measured by the gate's own self-check, which is required to pass
before any guest result is accepted).

SPDX-License-Identifier: GPL-2.0-or-later
"""
import numpy as np
from PIL import Image

# IoU at the best offset that counts as "the logo is on screen". Exact artwork blitted
# into the scanout scores 1.0; the self-check measures both tails every run. 0.85 is
# chosen from those measurements: the hardest negative (a solid white rectangle the
# size of the artwork) scores 0.71 and an 8%-eroded, 0.5%-speckled logo still scores
# well above 0.85, so the threshold sits in the gap rather than next to either tail.
IOU_PASS = 0.85
# Minimum artwork size accepted as a logo, so a stray small blob cannot match.
MIN_SIDE = 256


def luminance(path):
    with Image.open(path) as image:
        return np.asarray(image.convert('L')).astype(np.float32)


def foreground(lum, floor=40.0):
    """Mask of lit pixels. The threshold is half-way to the capture's own 99.5th
    percentile, never below `floor`, so a brightness-scaled swap still separates."""
    high = float(np.percentile(lum, 99.5))
    threshold = max(floor, 0.5 * high)
    return lum > threshold, threshold


def _kernel_spec(kernel, shape):
    """conj(rfft2(zero-padded kernel)) - the part that does not depend on the frame."""
    h, w = kernel.shape
    pad = np.zeros(shape, dtype=np.float64)
    pad[:h, :w] = kernel
    return np.conj(np.fft.rfft2(pad))


def _correlate(frame_spec, kernel_spec, shape):
    """sum_{i,j} frame[y+i, x+j] * kernel[i,j] for every (y, x), via FFT.

    Offsets with y + h <= H and x + w <= W are exact; wrap-around only affects the
    offsets we never look at."""
    return np.fft.irfft2(frame_spec * kernel_spec, s=shape)


def match(frame_mask, logo_mask, cache=None, key=None, frame_spec=None):
    """Return (best_iou, (y, x), coverage, precision) for one artwork mask.

    `cache` memoises the artwork-side FFTs across frames (they depend only on the
    artwork and the frame shape) and `frame_spec` the frame-side FFT across artworks."""
    H, W = frame_mask.shape
    h, w = logo_mask.shape
    if h > H or w > W:
        return 0.0, None, 0.0, 0.0
    k = logo_mask.astype(np.float64)
    if cache is None:
        cache = {}
    ck = (key, (H, W))
    if ck not in cache:
        cache[ck] = (_kernel_spec(k, (H, W)), _kernel_spec(np.ones((h, w)), (H, W)))
    kspec, ospec = cache[ck]
    if frame_spec is None:
        frame_spec = np.fft.rfft2(frame_mask.astype(np.float64))
    inter = _correlate(frame_spec, kspec, (H, W))
    area_a = _correlate(frame_spec, ospec, (H, W))
    area_b = float(k.sum())
    valid = np.zeros((H, W), dtype=bool)
    valid[:H - h + 1, :W - w + 1] = True
    union = area_a + area_b - inter
    iou = np.where(valid & (union > 0), inter / np.maximum(union, 1e-9), 0.0)
    y, x = np.unravel_index(int(np.argmax(iou)), iou.shape)
    best = float(iou[y, x])
    i = float(inter[y, x])
    return (best, (int(y), int(x)), i / area_b if area_b else 0.0,
            i / area_a[y, x] if area_a[y, x] else 0.0)


class LogoDetector:
    """Matches a framebuffer capture against a fixed set of artwork masks."""

    def __init__(self, artwork):
        """artwork: {name: boolean mask array}. Masks smaller than MIN_SIDE are refused
        so the detector cannot be satisfied by a small blob."""
        self.artwork = {}
        self._cache = {}
        for name, mask in artwork.items():
            if min(mask.shape) < MIN_SIDE:
                raise ValueError('%s is %dx%d, below the %d-pixel minimum side'
                                 % (name, mask.shape[1], mask.shape[0], MIN_SIDE))
            self.artwork[name] = mask

    def inspect_mask(self, frame_mask):
        results = {}
        frame_spec = np.fft.rfft2(frame_mask.astype(np.float64))
        for name, mask in self.artwork.items():
            iou, at, coverage, precision = match(frame_mask, mask, self._cache, name,
                                                 frame_spec)
            results[name] = {'iou': round(iou, 4), 'at': at,
                             'coverage': round(coverage, 4),
                             'precision': round(precision, 4),
                             'size': [int(mask.shape[1]), int(mask.shape[0])]}
        best = max(results, key=lambda n: results[n]['iou']) if results else None
        return {
            'best': best,
            'best_iou': results[best]['iou'] if best else 0.0,
            'at': results[best]['at'] if best else None,
            'logo_present': bool(best and results[best]['iou'] >= IOU_PASS),
            'threshold': IOU_PASS,
            'per_artwork': results,
        }

    def inspect(self, png_path):
        lum = luminance(png_path)
        mask, threshold = foreground(lum)
        out = self.inspect_mask(mask)
        out['frame'] = {'width': int(lum.shape[1]), 'height': int(lum.shape[0]),
                        'lit_pixels': int(mask.sum()),
                        'lit_fraction': round(float(mask.mean()), 5),
                        'luminance_threshold': round(threshold, 1),
                        'max_luminance': float(lum.max())}
        return out


def composite(background_mask, logo_mask, opaque=True):
    """Place `logo_mask` in the centre of a copy of `background_mask`, the way a swapped
    surface would: the artwork's own rectangle replaces whatever was under it."""
    out = background_mask.copy()
    H, W = out.shape
    h, w = logo_mask.shape
    y, x = (H - h) // 2, (W - w) // 2
    if opaque:
        out[y:y + h, x:x + w] = logo_mask
    else:
        out[y:y + h, x:x + w] |= logo_mask
    return out, (y, x)
