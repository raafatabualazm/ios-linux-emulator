/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stddef.h>
#include <stdint.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-adt-ioaccelerator-es.h"

/* name = "IOAcceleratorES" */
static const uint8_t ioacceles_name[] = {
    'I', 'O', 'A', 'c', 'c', 'e', 'l', 'e', 'r', 'a', 't', 'o', 'r', 'E', 'S',
    0x00
};
/* AAPL,phandle = 0x10b (stock sgx; free when sgx is deleted) */
static const uint8_t ioacceles_phandle[] = {
    0x0b, 0x01, 0x00, 0x00
};

static const AppleModernAdtNodeProp ioacceles_props[] = {
    {"name", ioacceles_name, (uint32_t)sizeof(ioacceles_name)},
    {"AAPL,phandle", ioacceles_phandle, (uint32_t)sizeof(ioacceles_phandle)},
};

static const AppleModernAdtNode ioacceles_node = {
    .parent = "/arm-io",
    .name = "IOAcceleratorES",
    .props = ioacceles_props,
    .prop_count = sizeof(ioacceles_props) / sizeof(ioacceles_props[0]),
};

const AppleModernAdtNode *apple_modern_adt_ioaccelerator_es_node(void)
{
    return &ioacceles_node;
}
