/*
 * Modern Apple boot console keyboard to UART adapter.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * The normal US/VT100 key mapping follows d0lb33/qemu-sptm b0f7bc6,
 * hw/arm/darwin_fb.c. UART delivery uses Inferno's existing frontend capacity
 * checks and pacing, with bounded pending input rather than direct bursts.
 */
#ifdef APPLE_MODERN_INPUT_STANDALONE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "hw/qdev-core.h"
#include "chardev/char.h"
#include "ui/console.h"
#include "ui/input.h"
#endif
#include "standard-headers/linux/input-event-codes.h"
#include "hw/arm/apple-silicon/modern-boot-input.h"

#define INPUT_CAPACITY 256
#define INPUT_INTERVAL_MS 20

struct AppleModernConsoleInput {
    DeviceState *owner;
    QemuConsole *console;
    Chardev *uart;
    uint8_t queue[INPUT_CAPACITY];
    size_t head, length;
    bool shift_left, shift_right, ctrl_left, ctrl_right;
    bool alt_left, alt_right, caps, caps_down;
    int (*can_write)(Chardev *uart);
    void (*write)(Chardev *uart, const uint8_t *bytes, int length);
#ifndef APPLE_MODERN_INPUT_STANDALONE
    QemuInputHandlerState *handler;
    QEMUTimer *timer;
    AppleModernConsoleInput *next;
#endif
};

static const uint8_t keys_lower[] = {
    [KEY_ESC] = 0x1b,
    [KEY_1] = '1', [KEY_2] = '2', [KEY_3] = '3', [KEY_4] = '4',
    [KEY_5] = '5', [KEY_6] = '6', [KEY_7] = '7', [KEY_8] = '8',
    [KEY_9] = '9', [KEY_0] = '0', [KEY_MINUS] = '-', [KEY_EQUAL] = '=',
    [KEY_BACKSPACE] = 0x7f, [KEY_TAB] = '\t', [KEY_ENTER] = '\r',
    [KEY_Q] = 'q', [KEY_W] = 'w', [KEY_E] = 'e', [KEY_R] = 'r',
    [KEY_T] = 't', [KEY_Y] = 'y', [KEY_U] = 'u', [KEY_I] = 'i',
    [KEY_O] = 'o', [KEY_P] = 'p', [KEY_LEFTBRACE] = '[',
    [KEY_RIGHTBRACE] = ']', [KEY_A] = 'a', [KEY_S] = 's', [KEY_D] = 'd',
    [KEY_F] = 'f', [KEY_G] = 'g', [KEY_H] = 'h', [KEY_J] = 'j',
    [KEY_K] = 'k', [KEY_L] = 'l', [KEY_SEMICOLON] = ';',
    [KEY_APOSTROPHE] = '\'', [KEY_GRAVE] = '`', [KEY_BACKSLASH] = '\\',
    [KEY_Z] = 'z', [KEY_X] = 'x', [KEY_C] = 'c', [KEY_V] = 'v',
    [KEY_B] = 'b', [KEY_N] = 'n', [KEY_M] = 'm', [KEY_COMMA] = ',',
    [KEY_DOT] = '.', [KEY_SLASH] = '/', [KEY_SPACE] = ' ',
    [KEY_KPASTERISK] = '*', [KEY_KP7] = '7', [KEY_KP8] = '8',
    [KEY_KP9] = '9', [KEY_KPMINUS] = '-', [KEY_KP4] = '4', [KEY_KP5] = '5',
    [KEY_KP6] = '6', [KEY_KPPLUS] = '+', [KEY_KP1] = '1', [KEY_KP2] = '2',
    [KEY_KP3] = '3', [KEY_KP0] = '0', [KEY_KPDOT] = '.',
    [KEY_102ND] = '\\', [KEY_KPENTER] = '\r', [KEY_KPSLASH] = '/',
};

static const uint8_t keys_upper[] = {
    [KEY_ESC] = 0x1b,
    [KEY_1] = '!', [KEY_2] = '@', [KEY_3] = '#', [KEY_4] = '$',
    [KEY_5] = '%', [KEY_6] = '^', [KEY_7] = '&', [KEY_8] = '*',
    [KEY_9] = '(', [KEY_0] = ')', [KEY_MINUS] = '_', [KEY_EQUAL] = '+',
    [KEY_BACKSPACE] = 0x7f, [KEY_TAB] = '\t', [KEY_ENTER] = '\r',
    [KEY_Q] = 'Q', [KEY_W] = 'W', [KEY_E] = 'E', [KEY_R] = 'R',
    [KEY_T] = 'T', [KEY_Y] = 'Y', [KEY_U] = 'U', [KEY_I] = 'I',
    [KEY_O] = 'O', [KEY_P] = 'P', [KEY_LEFTBRACE] = '{',
    [KEY_RIGHTBRACE] = '}', [KEY_A] = 'A', [KEY_S] = 'S', [KEY_D] = 'D',
    [KEY_F] = 'F', [KEY_G] = 'G', [KEY_H] = 'H', [KEY_J] = 'J',
    [KEY_K] = 'K', [KEY_L] = 'L', [KEY_SEMICOLON] = ':',
    [KEY_APOSTROPHE] = '"', [KEY_GRAVE] = '~', [KEY_BACKSLASH] = '|',
    [KEY_Z] = 'Z', [KEY_X] = 'X', [KEY_C] = 'C', [KEY_V] = 'V',
    [KEY_B] = 'B', [KEY_N] = 'N', [KEY_M] = 'M', [KEY_COMMA] = '<',
    [KEY_DOT] = '>', [KEY_SLASH] = '?', [KEY_SPACE] = ' ',
    [KEY_KPASTERISK] = '*', [KEY_KP7] = '7', [KEY_KP8] = '8',
    [KEY_KP9] = '9', [KEY_KPMINUS] = '-', [KEY_KP4] = '4', [KEY_KP5] = '5',
    [KEY_KP6] = '6', [KEY_KPPLUS] = '+', [KEY_KP1] = '1', [KEY_KP2] = '2',
    [KEY_KP3] = '3', [KEY_KP0] = '0', [KEY_KPDOT] = '.',
    [KEY_102ND] = '|', [KEY_KPENTER] = '\r', [KEY_KPSLASH] = '/',
};

static const char *special_key(unsigned key)
{
    switch (key) {
    case KEY_UP: return "\x1b[A";
    case KEY_DOWN: return "\x1b[B";
    case KEY_RIGHT: return "\x1b[C";
    case KEY_LEFT: return "\x1b[D";
    case KEY_HOME: return "\x1b[H";
    case KEY_END: return "\x1b[F";
    case KEY_INSERT: return "\x1b[2~";
    case KEY_DELETE: return "\x1b[3~";
    case KEY_PAGEUP: return "\x1b[5~";
    case KEY_PAGEDOWN: return "\x1b[6~";
    case KEY_F1: return "\x1bOP";
    case KEY_F2: return "\x1bOQ";
    case KEY_F3: return "\x1bOR";
    case KEY_F4: return "\x1bOS";
    default: return NULL;
    }
}

static bool enqueue(AppleModernConsoleInput *s, const uint8_t *bytes,
                    size_t length)
{
    if (length > INPUT_CAPACITY - s->length) {
        return false; /* Drop the whole sequence; never leave a partial ESC. */
    }
    for (size_t i = 0; i < length; i++) {
        s->queue[(s->head + s->length + i) % INPUT_CAPACITY] = bytes[i];
    }
    s->length += length;
    return true;
}

static void console_key(AppleModernConsoleInput *s, unsigned key, bool down)
{
    uint8_t bytes[8];
    size_t length = 0;
    bool shift;
    const char *sequence;

    switch (key) {
    case KEY_LEFTSHIFT: s->shift_left = down; return;
    case KEY_RIGHTSHIFT: s->shift_right = down; return;
    case KEY_LEFTCTRL: s->ctrl_left = down; return;
    case KEY_RIGHTCTRL: s->ctrl_right = down; return;
    case KEY_LEFTALT: s->alt_left = down; return;
    case KEY_RIGHTALT: s->alt_right = down; return;
    case KEY_CAPSLOCK:
        if (down && !s->caps_down) {
            s->caps = !s->caps;
        }
        s->caps_down = down;
        return;
    default: break;
    }
    if (!down) {
        return;
    }
    shift = s->shift_left || s->shift_right;
    sequence = key == KEY_TAB && shift ? "\x1b[Z" : special_key(key);
    if (s->alt_left || s->alt_right) {
        bytes[length++] = 0x1b;
    }
    if (sequence) {
        size_t sequence_length = strlen(sequence);
        memcpy(bytes + length, sequence, sequence_length);
        length += sequence_length;
    } else {
        uint8_t ch;
        if (key >= sizeof(keys_lower) || !keys_lower[key]) {
            return;
        }
        ch = (shift ? keys_upper : keys_lower)[key];
        if (s->caps && ch >= 'a' && ch <= 'z') {
            ch -= 'a' - 'A';
        } else if (s->caps && ch >= 'A' && ch <= 'Z') {
            ch += 'a' - 'A';
        }
        if (s->ctrl_left || s->ctrl_right) {
            if (ch >= 'a' && ch <= 'z') {
                ch -= 'a' - 'A';
            }
            if (ch >= '@' && ch <= '_') {
                ch &= 0x1f;
            } else if (ch == ' ' || ch == '2') {
                ch = 0;
            } else if (ch == '?') {
                ch = 0x7f;
            }
        }
        bytes[length++] = ch;
    }
    enqueue(s, bytes, length);
}

static void drain_one(AppleModernConsoleInput *s)
{
    if (s->length && s->can_write(s->uart) > 0) {
        s->write(s->uart, s->queue + s->head, 1);
        s->head = (s->head + 1) % INPUT_CAPACITY;
        s->length--;
    }
}

void apple_modern_console_input_reset(AppleModernConsoleInput *s)
{
    if (!s) {
        return;
    }
#ifndef APPLE_MODERN_INPUT_STANDALONE
    timer_del(s->timer);
#endif
    memset(s->queue, 0, sizeof(s->queue));
    s->head = s->length = 0;
    s->shift_left = s->shift_right = s->ctrl_left = s->ctrl_right = false;
    s->alt_left = s->alt_right = s->caps = s->caps_down = false;
}

#ifndef APPLE_MODERN_INPUT_STANDALONE
/* QEMU's handler callback carries its owner, so resolve the private adapter. */
static AppleModernConsoleInput *inputs;

static void input_tick(void *opaque)
{
    AppleModernConsoleInput *s = opaque;

    drain_one(s);
    if (s->length) {
        timer_mod(s->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                            INPUT_INTERVAL_MS);
    }
}

static void input_event(DeviceState *owner, QemuConsole *console, InputEvent *event)
{
    AppleModernConsoleInput *s;
    int qcode;

    if (event->type != INPUT_EVENT_KIND_KEY) {
        return;
    }
    for (s = inputs; s; s = s->next) {
        if (s->owner == owner && s->console == console) {
            break;
        }
    }
    if (!s) {
        return;
    }
    qcode = qemu_input_key_value_to_qcode(event->u.key.data->key);
    if (qcode < 0 || (unsigned)qcode >= qemu_input_map_qcode_to_linux_len) {
        return;
    }
    console_key(s, qemu_input_map_qcode_to_linux[qcode], event->u.key.data->down);
    if (s->length && !timer_pending(s->timer)) {
        timer_mod(s->timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                            INPUT_INTERVAL_MS);
    }
}

static const QemuInputHandler input_handler = {
    .name = "Apple modern boot console keyboard",
    .mask = INPUT_EVENT_MASK_KEY,
    .event = input_event,
};

AppleModernConsoleInput *apple_modern_console_input_create(DeviceState *owner,
                                                          QemuConsole *console,
                                                          Chardev *uart)
{
    AppleModernConsoleInput *s;
    Error *error = NULL;

    if (!owner || !console || !uart || !owner->id) {
        return NULL;
    }
    for (s = inputs; s; s = s->next) {
        if (s->owner == owner) {
            error_report("modern boot console input owner is already registered");
            return NULL;
        }
    }
    s = g_new0(AppleModernConsoleInput, 1);
    s->owner = owner;
    s->console = console;
    s->uart = uart;
    s->can_write = qemu_chr_be_can_write;
    s->write = qemu_chr_be_write;
    s->handler = qemu_input_handler_register(owner, &input_handler);
    qemu_input_handler_bind(s->handler, owner->id,
                            qemu_console_get_head(console), &error);
    if (error) {
        error_report_err(error);
        qemu_input_handler_unregister(s->handler);
        g_free(s);
        return NULL;
    }
    object_ref(OBJECT(uart));
    s->timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, input_tick, s);
    s->next = inputs;
    inputs = s;
    return s;
}

void apple_modern_console_input_destroy(AppleModernConsoleInput *s)
{
    AppleModernConsoleInput **link;

    if (!s) {
        return;
    }
    apple_modern_console_input_reset(s);
    timer_free(s->timer);
    qemu_input_handler_unregister(s->handler);
    for (link = &inputs; *link; link = &(*link)->next) {
        if (*link == s) {
            *link = s->next;
            break;
        }
    }
    object_unref(OBJECT(s->uart));
    g_free(s);
}
#endif
