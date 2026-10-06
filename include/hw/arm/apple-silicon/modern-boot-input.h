/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_BOOT_INPUT_H
#define HW_ARM_APPLE_MODERN_BOOT_INPUT_H

typedef struct DeviceState DeviceState;
typedef struct QemuConsole QemuConsole;
typedef struct Chardev Chardev;
typedef struct AppleModernConsoleInput AppleModernConsoleInput;

/*
 * Main-thread console keyboard adapter for an already registered UART
 * frontend. owner must be a named sysbus display device on its bus, bound to
 * console. A missing owner/console/UART creates no handler. The caller resets
 * this adapter with the display and destroys it before closing the console.
 * Pending sequences are bounded to 256 bytes and delivered one byte at a time
 * every 20 ms of virtual time, subject to the UART frontend's receive capacity.
 */
AppleModernConsoleInput *apple_modern_console_input_create(DeviceState *owner,
                                                          QemuConsole *console,
                                                          Chardev *uart);
void apple_modern_console_input_reset(AppleModernConsoleInput *input);
void apple_modern_console_input_destroy(AppleModernConsoleInput *input);

#endif
