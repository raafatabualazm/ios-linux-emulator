/*
 * Modern Apple bootloader framebuffer scanout.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "hw/qdev-properties.h"
#include "hw/sysbus.h"
#include "hw/arm/apple-silicon/modern-boot-display.h"
#include "hw/arm/apple-silicon/modern-boot-input.h"
#include "ui/console.h"

#define TYPE_APPLE_MODERN_BOOT_DISPLAY "apple-modern-boot-display"
OBJECT_DECLARE_SIMPLE_TYPE(AppleModernBootDisplay, APPLE_MODERN_BOOT_DISPLAY)

struct AppleModernBootDisplay {
    SysBusDevice parent_obj;
    MemoryRegion *ram;
    uint64_t offset;
    uint32_t width, height, stride;
    const uint8_t *pixels;
    QemuConsole *console;
    Chardev *uart;
    AppleModernConsoleInput *input;
};

static void boot_display_update(void *opaque)
{
    AppleModernBootDisplay *s = opaque;
    DisplaySurface *surface = qemu_console_surface(s->console);
    uint8_t *dest = surface_data(surface);

    /* Copy visible pixels only: guest row padding is not part of the image. */
    for (uint32_t row = 0; row < s->height; row++) {
        memcpy(dest + (size_t)row * surface_stride(surface),
               s->pixels + (size_t)row * s->stride, (size_t)s->width * 4);
    }
    dpy_gfx_update_full(s->console);
}

static const GraphicHwOps boot_display_ops = {
    .gfx_update = boot_display_update,
};

static void boot_display_realize(DeviceState *dev, Error **errp)
{
    AppleModernBootDisplay *s = APPLE_MODERN_BOOT_DISPLAY(dev);
    uint64_t size = (uint64_t)s->stride * s->height;

    if (!s->ram || !memory_region_is_ram(s->ram) ||
        !s->width || s->width > 4096 || !s->height || s->height > 4096 ||
        s->stride < (uint64_t)s->width * 4 || (s->stride & 3) ||
        size > 64 * MiB || s->offset > memory_region_size(s->ram) ||
        size > memory_region_size(s->ram) - s->offset) {
        error_setg(errp, "modern boot display requires bounded 32-bit geometry "
                   "wholly inside its RAM reservation");
        return;
    }
    s->pixels = (uint8_t *)memory_region_get_ram_ptr(s->ram) + s->offset;
    s->console = graphic_console_init(dev, 0, &boot_display_ops, s);
    /* Explicit format keeps the BootVideo ABI independent of host depth. */
    dpy_gfx_replace_surface(s->console, qemu_create_displaysurface_from(
        s->width, s->height, PIXMAN_x8r8g8b8, s->width * 4, NULL));
    s->input = apple_modern_console_input_create(dev, s->console, s->uart);
    if (s->uart && !s->input) {
        graphic_console_close(s->console);
        error_setg(errp, "cannot bind modern boot console keyboard");
    }
}

static void boot_display_reset(DeviceState *dev)
{
    apple_modern_console_input_reset(APPLE_MODERN_BOOT_DISPLAY(dev)->input);
}

static void boot_display_unrealize(DeviceState *dev)
{
    AppleModernBootDisplay *s = APPLE_MODERN_BOOT_DISPLAY(dev);

    apple_modern_console_input_destroy(s->input);
    s->input = NULL;
    graphic_console_close(s->console);
    s->console = NULL;
    s->pixels = NULL;
}

static const Property boot_display_properties[] = {
    DEFINE_PROP_LINK("ram", AppleModernBootDisplay, ram, TYPE_MEMORY_REGION,
                     MemoryRegion *),
    DEFINE_PROP_UINT64("offset", AppleModernBootDisplay, offset, 0),
    DEFINE_PROP_UINT32("width", AppleModernBootDisplay, width, 0),
    DEFINE_PROP_UINT32("height", AppleModernBootDisplay, height, 0),
    DEFINE_PROP_UINT32("stride", AppleModernBootDisplay, stride, 0),
    DEFINE_PROP_LINK("uart", AppleModernBootDisplay, uart, TYPE_CHARDEV,
                     Chardev *),
};

static void boot_display_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = boot_display_realize;
    dc->unrealize = boot_display_unrealize;
    device_class_set_legacy_reset(dc, boot_display_reset);
    dc->user_creatable = false;
    dc->desc = "Apple boot framebuffer (fixed RAM scanout)";
    set_bit(DEVICE_CATEGORY_DISPLAY, dc->categories);
    device_class_set_props(dc, boot_display_properties);
}

static const TypeInfo boot_display_type = {
    .name = TYPE_APPLE_MODERN_BOOT_DISPLAY,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleModernBootDisplay),
    .class_init = boot_display_class_init,
};

static void register_boot_display(void)
{
    type_register_static(&boot_display_type);
}
type_init(register_boot_display);

bool apple_modern_boot_display_create(MemoryRegion *ram, uint64_t offset,
                                      uint32_t width, uint32_t height,
                                      uint32_t stride, Chardev *uart,
                                      Error **errp)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_MODERN_BOOT_DISPLAY);

    dev->id = g_strdup("modern-boot-display");
    object_property_set_link(OBJECT(dev), "ram", OBJECT(ram), &error_abort);
    qdev_prop_set_uint64(dev, "offset", offset);
    qdev_prop_set_uint32(dev, "width", width);
    qdev_prop_set_uint32(dev, "height", height);
    qdev_prop_set_uint32(dev, "stride", stride);
    object_property_set_link(OBJECT(dev), "uart", OBJECT(uart), &error_abort);
    return qdev_realize_and_unref(dev, BUS(sysbus_get_default()), errp);
}
