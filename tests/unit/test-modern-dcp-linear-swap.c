/* Standalone tests against the retained A408 capture, never a running guest.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * cc -std=c11 -Wall -Wextra -Werror -I. tests/unit/test-modern-dcp-linear-swap.c -o /tmp/test-dcp-swap
 * /tmp/test-dcp-swap /path/to/swap-live-v1/dart-capture/dcp-command.bin
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hw/arm/apple-silicon/modern-dcp-linear-swap.h"

static unsigned checks;

static void put32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++) {
        p[i] = v >> (i * 8);
    }
}

static void put64(uint8_t *p, uint64_t v)
{
    put32(p, v);
    put32(p + 4, v >> 32);
}

static void reject(const uint8_t *p, size_t size)
{
    DcpLinearSwap out = { .id = 0x12345678, .iova = 0x87654321 };
    assert(dcp_linear_swap_decode(p, size, &out));
    assert(out.id == 0x12345678 && out.iova == 0x87654321);
    checks++;
}

int main(int argc, char **argv)
{
    uint8_t header[12], input[DCP_LINEAR_SWAP_INPUT_SIZE];
    uint8_t changed[sizeof(input)];
    DcpLinearSwap out;
    FILE *f;

    if (argc != 2 || !(f = fopen(argv[1], "rb"))) {
        fprintf(stderr, "usage: %s captured-dcp-command.bin\n", argv[0]);
        return 2;
    }
    assert(fread(header, 1, sizeof(header), f) == sizeof(header));
    assert(!memcmp(header, "804A", 4));
    assert(dcp_swap_u32(header + 4) == sizeof(input));
    assert(dcp_swap_u32(header + 8) == 12);
    assert(fread(input, 1, sizeof(input), f) == sizeof(input));
    fclose(f);
    assert(!dcp_linear_swap_decode(input, sizeof(input), &out));
    assert(out.id == 29434 && out.iova == 0x640000);
    checks++;

    reject(NULL, sizeof(input));
    reject(input, sizeof(input) - 1);
    reject(input, sizeof(input) + 1);
    assert(dcp_linear_swap_decode(input, sizeof(input), NULL));
    checks++;

    /* Exact raw control is copied before each independent malformed case. */
#define REFUSE_BYTE(offset, value) do { \
    memcpy(changed, input, sizeof(input)); \
    changed[(offset)] = (value); \
    reject(changed, sizeof(changed)); \
} while (0)
#define REFUSE_WORD(offset, value) do { \
    memcpy(changed, input, sizeof(input)); \
    put32(changed + (offset), (value)); \
    reject(changed, sizeof(changed)); \
} while (0)
    REFUSE_BYTE(0xfea, 1);       /* Null transaction. */
    REFUSE_BYTE(0xfeb, 1);       /* Null selected descriptor. */
    REFUSE_BYTE(0xfec, 0);       /* Unexpected extra descriptor. */
    REFUSE_WORD(0x14c, 0);      /* No layer. */
    REFUSE_WORD(0x14c, 2);      /* Primary layer not changed. */
    REFUSE_WORD(0x14c, 0x11);   /* Unknown layer mask bit. */
    REFUSE_BYTE(0x6e0, 1);     /* Tiled. */
    REFUSE_WORD(0x6e0 + 3, 1); /* Planar. */
    REFUSE_BYTE(0x6e0 + 0x1ed, 1); /* Compressed. */
    REFUSE_WORD(0x6e0 + 0xb, 0x52474241); /* RGBA is not BGRA. */
    REFUSE_WORD(0x6e0 + 0x15, 4092); /* Short stride. */
    REFUSE_WORD(0x6e0 + 0x25, 767);  /* Partial frame. */
    REFUSE_WORD(0x6e0 + 0x29, DCP_LINEAR_SWAP_BYTES - 1);
    REFUSE_WORD(0x6e0 + 0x1d, 4); /* Offset semantics unqualified. */
    REFUSE_WORD(0xac, 1);        /* Source crop. */
    REFUSE_WORD(0x114, 512);     /* Scaling. */
    REFUSE_WORD(0xec, 3);        /* Unqualified layer flags. */
    REFUSE_WORD(0x98, 0);        /* Unknown swap. */
    REFUSE_WORD(0x6e0 + 0x35, 4); /* Mismatched surface identity. */
    memcpy(changed, input, sizeof(input));
    put64(changed + 0xf90, UINT64_C(0x10fffffffff));
    reject(changed, sizeof(changed)); /* Full read crosses 36-bit aperture. */
    memcpy(changed, input, sizeof(input));
    put64(changed + 0xf90, UINT64_C(0x20000640000));
    reject(changed, sizeof(changed)); /* Wrong address tag. */
    memcpy(changed, input, sizeof(input));
    put64(changed + 0xf90, UINT64_C(0x10000000000));
    assert(!dcp_linear_swap_decode(changed, sizeof(changed), &out));
    assert(out.iova == 0); /* Valid address zero still requires actual DMA. */
    checks++;
    put32(changed + 0x14c, 0x80000007);
    assert(!dcp_linear_swap_decode(changed, sizeof(changed), &out));
    checks++; /* Background update plus clear null layers 1 and 2. */
    printf("%u raw-capture and refusal checks passed\n", checks);
    return 0;
}
