"""Decode XNU's built-in text console from a framebuffer capture, without OCR.

The modern board's only guest-rendered output is the kernel's own text console:
white 8x16 glyphs on black in a 1024x768 scanout. The kernel carries the glyph
table in the boot kernel collection, so a capture can be turned back into text
by exact lookup instead of guessing from pixels.

The table's offset is only valid for one exact file, so the collection's SHA-256
is checked first and a different file is refused rather than decoded with a wrong
table. Cells that match no glyph decode to U+FFFD and are counted; a solid cell
is the cursor and decodes to a block.

SPDX-License-Identifier: GPL-2.0-or-later
"""
import hashlib
from pathlib import Path

import numpy as np
from PIL import Image

# iOS 27.0 / 24A437 boot kernel collection as pinned in the project record.
BOOTKC_SHA256 = 'a36b924108b63eefd7cc8fa9e54acc3a07544786d3edb316fbcf3b9fb7426b35'
# File offset of glyph 0x00; the 'A' glyph was located by exact match at 0x4706c98.
GLYPH_BASE = 0x4706c98 - 0x41 * 16
CELL_W, CELL_H = 8, 16
CURSOR = '█'
UNKNOWN = '�'


class Console:
    def __init__(self, bootkc):
        data = Path(bootkc).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != BOOTKC_SHA256:
            raise ValueError('glyph table offset is pinned to boot kernel collection sha256 '
                             f'{BOOTKC_SHA256}; got {digest}')
        self.font = {}
        for code in range(32, 127):
            start = GLYPH_BASE + code * CELL_H
            self.font.setdefault(data[start:start + CELL_H], chr(code))
        self.blank = bytes(CELL_H)

    def cells(self, image_path):
        """Return an array of 16-byte cell keys, shape (rows, columns), LSB = leftmost pixel."""
        with Image.open(image_path) as image:
            lit = np.asarray(image.convert('L')) > 128
        height, width = lit.shape
        rows, columns = height // CELL_H, width // CELL_W
        lit = lit[:rows * CELL_H, :columns * CELL_W]
        blocks = lit.reshape(rows, CELL_H, columns, CELL_W)
        packed = np.packbits(blocks, axis=3, bitorder='little')[..., 0]   # (rows, 16, columns)
        return np.ascontiguousarray(packed.transpose(0, 2, 1)), blocks

    def decode(self, image_path):
        """Return (rows_of_text, unknown_cells, text_cells)."""
        keys, blocks = self.cells(image_path)
        out, unknown, text = [], 0, 0
        for r in range(keys.shape[0]):
            line = []
            for c in range(keys.shape[1]):
                key = keys[r, c].tobytes()
                if key == self.blank:
                    line.append(' ')
                elif key in self.font:
                    line.append(self.font[key])
                    text += 1
                elif blocks[r, :, c, :].all():
                    line.append(CURSOR)
                else:
                    line.append(UNKNOWN)
                    unknown += 1
            out.append(''.join(line).rstrip())
        return out, unknown, text

    def render(self, text, columns=128, rows=48):
        """Draw text with the kernel's own glyphs; used to self-test the decoder."""
        reverse = {ch: key for key, ch in self.font.items()}
        frame = np.zeros((rows * CELL_H, columns * CELL_W), dtype=bool)
        for r, line in enumerate(text):
            for c, ch in enumerate(line[:columns]):
                if ch == ' ':
                    continue
                glyph = reverse[ch]
                for y in range(CELL_H):
                    for x in range(CELL_W):
                        frame[r * CELL_H + y, c * CELL_W + x] = bool((glyph[y] >> x) & 1)
        return frame
