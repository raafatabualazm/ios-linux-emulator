/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "hw/arm/apple-silicon/sep-sks-wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { \
    fprintf(stderr, "check failed at %d: %s\n", __LINE__, #x); exit(1); \
} } while (0)

static void store32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; i++) {
        p[i] = value >> (8 * i);
    }
}

int main(void)
{
    /* An unaligned buffer catches accidental native-word casts. */
    uint8_t backing[256] = {0};
    uint8_t *buf = backing + 1;
    AppleSEPSKSWire view, old;
    memset(&old, 0xa5, sizeof(old));
    for (unsigned modern = 0; modern < 2; modern++) {
        for (unsigned version = 1; version <= 2; version++) {
            unsigned header = modern && version == 1 ? 72 : 80;
            memset(buf, 0, 200);
            store32(buf, header);
            store32(buf + 20, version);
            store32(buf + 32, 0x76543210);
            for (unsigned size = 0; size < header + 4; size++) {
                view = old;
                CHECK(!apple_sep_sks_wire_parse(buf, size, modern, &view));
                CHECK(!memcmp(&view, &old, sizeof(view)));
            }
            for (unsigned body = 0; body <= 32; body++) {
                CHECK(apple_sep_sks_wire_parse(buf, header + 4 + body,
                                               modern, &view));
                CHECK(view.version == version && view.header_size == header);
                CHECK(view.flags == 0x76543210 && view.body_size == body);
                CHECK(view.body_offset == header + 4 && view.hash_offset == 20);
                CHECK(view.hash_size == (version == 1 ? 56u : 64u));
                CHECK(view.hash_offset + view.hash_size <= view.body_offset);
            }
            static const uint32_t bad_sizes[] = {0, 1, 16, 71, 73, 79, 81, UINT32_MAX};
            for (unsigned i = 0; i < sizeof(bad_sizes) / sizeof(*bad_sizes); i++) {
                store32(buf, bad_sizes[i]);
                CHECK(!apple_sep_sks_wire_parse(buf, 100, modern, &view));
            }
            store32(buf, header);
            for (unsigned version_bad = 0; version_bad < 256; version_bad++) {
                if (version_bad == 1 || version_bad == 2) {
                    continue;
                }
                store32(buf + 20, version_bad);
                CHECK(!apple_sep_sks_wire_parse(buf, 100, modern, &view));
            }
        }
    }
    store32(buf, 80);
    store32(buf + 20, 1);
    CHECK(!apple_sep_sks_wire_parse(buf, 100, true, &view));
    CHECK(apple_sep_sks_wire_parse(buf, 100, false, &view));
    store32(buf, 72);
    CHECK(!apple_sep_sks_wire_parse(buf, 100, false, &view));
    CHECK(apple_sep_sks_wire_parse(buf, 100, true, &view));
    CHECK(!apple_sep_sks_wire_parse(NULL, 100, true, &view));
    CHECK(!apple_sep_sks_wire_parse(buf, 100, true, NULL));
    CHECK(!apple_sep_sks_wire_parse(buf, SIZE_MAX, true, &view));
    CHECK(!apple_sep_sks_wire_parse(buf, 65536, true, &view));
    CHECK(backing[0] == 0 && backing[201] == 0);
    printf("%u SKS wire checks passed\n", checks);
    return 0;
}
