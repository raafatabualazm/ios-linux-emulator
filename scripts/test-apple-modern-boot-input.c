/* Production mapping/queue checks with a simulated receiving UART.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define APPLE_MODERN_INPUT_STANDALONE
#include "../hw/arm/apple-silicon/modern-boot-input.c"
#include <assert.h>
#include <stdio.h>

struct Chardev {
    int capacity;
    uint8_t received[2048];
    size_t used, calls;
};

static unsigned checks;

static int receive_capacity(Chardev *uart)
{
    return uart->capacity;
}

static void receive_byte(Chardev *uart, const uint8_t *bytes, int length)
{
    assert(length == 1 && uart->capacity > 0 && uart->used < sizeof(uart->received));
    uart->received[uart->used++] = bytes[0];
    uart->calls++;
}

static void expect(AppleModernConsoleInput *s, const void *bytes, size_t length)
{
    Chardev *uart = s->uart;
    assert(s->length == length);
    uart->used = uart->calls = 0;
    for (size_t i = 0; i < length; i++) {
        drain_one(s);
        assert(s->length == length - i - 1 && uart->calls == i + 1);
    }
    assert(uart->used == length && !memcmp(uart->received, bytes, length));
    drain_one(s); assert(uart->calls == length);
    checks++;
}

static void press(AppleModernConsoleInput *s, unsigned key)
{
    console_key(s, key, true);
    size_t length = s->length;
    console_key(s, key, false);
    assert(length == s->length); /* Printable release produces no bytes. */
}

int main(void)
{
    static const unsigned letters[] = {
        KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H, KEY_I,
        KEY_J, KEY_K, KEY_L, KEY_M, KEY_N, KEY_O, KEY_P, KEY_Q, KEY_R,
        KEY_S, KEY_T, KEY_U, KEY_V, KEY_W, KEY_X, KEY_Y, KEY_Z,
    };
    static const unsigned punctuation[] = {
        KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9,
        KEY_0, KEY_MINUS, KEY_EQUAL, KEY_LEFTBRACE, KEY_RIGHTBRACE,
        KEY_SEMICOLON, KEY_APOSTROPHE, KEY_GRAVE, KEY_BACKSLASH,
        KEY_COMMA, KEY_DOT, KEY_SLASH, KEY_SPACE,
    };
    static const struct {
        unsigned key;
        const char *sequence;
    } navigation[] = {
        {KEY_UP, "\033[A"}, {KEY_DOWN, "\033[B"}, {KEY_RIGHT, "\033[C"},
        {KEY_LEFT, "\033[D"}, {KEY_HOME, "\033[H"}, {KEY_END, "\033[F"},
        {KEY_INSERT, "\033[2~"}, {KEY_DELETE, "\033[3~"},
        {KEY_PAGEUP, "\033[5~"}, {KEY_PAGEDOWN, "\033[6~"},
        {KEY_F1, "\033OP"}, {KEY_F2, "\033OQ"},
        {KEY_F3, "\033OR"}, {KEY_F4, "\033OS"},
    };
    Chardev uart = {.capacity = 1};
    AppleModernConsoleInput s = {.uart = &uart, .can_write = receive_capacity,
                                 .write = receive_byte};
    setvbuf(stdout, NULL, _IONBF, 0);
    for (size_t i = 0; i < sizeof(letters) / sizeof(*letters); i++) {
        press(&s, letters[i]);
    }
    expect(&s, "abcdefghijklmnopqrstuvwxyz", 26);
    console_key(&s, KEY_LEFTSHIFT, true);
    for (size_t i = 0; i < sizeof(letters) / sizeof(*letters); i++) {
        press(&s, letters[i]);
    }
    expect(&s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);
    console_key(&s, KEY_LEFTSHIFT, false);
    for (size_t i = 0; i < sizeof(punctuation) / sizeof(*punctuation); i++) {
        press(&s, punctuation[i]);
    }
    expect(&s, "1234567890-=[];'`\\,./ ", 22);
    console_key(&s, KEY_RIGHTSHIFT, true);
    for (size_t i = 0; i < sizeof(punctuation) / sizeof(*punctuation); i++) {
        press(&s, punctuation[i]);
    }
    expect(&s, "!@#$%^&*()_+{}:\"~|<>? ", 22);
    console_key(&s, KEY_RIGHTSHIFT, false);
    press(&s, KEY_ESC); press(&s, KEY_ENTER); press(&s, KEY_KPENTER);
    press(&s, KEY_BACKSPACE); press(&s, KEY_TAB);
    expect(&s, "\033\r\r\177\t", 5);
    for (size_t i = 0; i < sizeof(navigation) / sizeof(*navigation); i++) {
        press(&s, navigation[i].key);
        expect(&s, navigation[i].sequence, strlen(navigation[i].sequence));
    }
    console_key(&s, KEY_LEFTSHIFT, true); console_key(&s, KEY_RIGHTSHIFT, true);
    console_key(&s, KEY_LEFTSHIFT, false);
    press(&s, KEY_A); press(&s, KEY_TAB); expect(&s, "A\033[Z", 4);
    console_key(&s, KEY_RIGHTSHIFT, false); press(&s, KEY_A); expect(&s, "a", 1);
    console_key(&s, KEY_LEFTCTRL, true); console_key(&s, KEY_RIGHTCTRL, true);
    console_key(&s, KEY_LEFTCTRL, false);
    uint8_t controls[26];
    for (size_t i = 0; i < sizeof(letters) / sizeof(*letters); i++) {
        press(&s, letters[i]); controls[i] = i + 1;
    }
    expect(&s, controls, sizeof(controls));
    press(&s, KEY_SPACE); press(&s, KEY_2); press(&s, KEY_LEFTBRACE);
    press(&s, KEY_BACKSLASH); press(&s, KEY_RIGHTBRACE);
    expect(&s, "\0\0\033\034\035", 5);
    console_key(&s, KEY_RIGHTCTRL, false); press(&s, KEY_C); expect(&s, "c", 1);
    console_key(&s, KEY_CAPSLOCK, true); console_key(&s, KEY_CAPSLOCK, true);
    press(&s, KEY_A); press(&s, KEY_1); expect(&s, "A1", 2);
    console_key(&s, KEY_LEFTSHIFT, true); press(&s, KEY_A); expect(&s, "a", 1);
    console_key(&s, KEY_LEFTSHIFT, false); console_key(&s, KEY_CAPSLOCK, false);
    console_key(&s, KEY_CAPSLOCK, true); console_key(&s, KEY_CAPSLOCK, false);
    press(&s, KEY_A); expect(&s, "a", 1);
    console_key(&s, KEY_LEFTALT, true); console_key(&s, KEY_RIGHTALT, true);
    console_key(&s, KEY_LEFTALT, false);
    press(&s, KEY_A); press(&s, KEY_UP); expect(&s, "\033a\033\033[A", 6);
    console_key(&s, KEY_RIGHTALT, false);
    press(&s, KEY_F12); press(&s, UINT32_MAX); press(&s, KEY_RESERVED);
    expect(&s, "", 0);
    uart.capacity = 0; press(&s, KEY_A); press(&s, KEY_B);
    uart.used = uart.calls = 0;
    for (unsigned i = 0; i < 100; i++) {
        drain_one(&s); assert(s.length == 2 && !uart.calls);
    }
    uart.capacity = -1; drain_one(&s); assert(s.length == 2 && !uart.calls);
    uart.capacity = 256; drain_one(&s);
    assert(s.length == 1 && uart.calls == 1 && uart.received[0] == 'a'); checks++;
    expect(&s, "b", 1);
    /* Full input drops new characters; insufficient room drops an entire ESC. */
    uint8_t repeated[INPUT_CAPACITY]; memset(repeated, 'a', sizeof(repeated));
    for (unsigned i = 0; i < INPUT_CAPACITY; i++) {
        press(&s, KEY_A);
    }
    press(&s, KEY_B); assert(s.length == INPUT_CAPACITY);
    uart.used = 0; drain_one(&s);
    assert(s.length == INPUT_CAPACITY - 1);
    press(&s, KEY_UP); assert(s.length == INPUT_CAPACITY - 1);
    expect(&s, repeated, INPUT_CAPACITY - 1);
    /* Wrap the FIFO across its end with an intact navigation sequence. */
    s.head = INPUT_CAPACITY - 1;
    press(&s, KEY_LEFT); expect(&s, "\033[D", 3);
    console_key(&s, KEY_LEFTSHIFT, true); console_key(&s, KEY_RIGHTCTRL, true);
    console_key(&s, KEY_LEFTALT, true); console_key(&s, KEY_CAPSLOCK, true);
    press(&s, KEY_UP); assert(s.length);
    apple_modern_console_input_reset(&s);
    assert(!s.length && !s.head && !s.shift_left && !s.ctrl_right &&
           !s.alt_left && !s.caps && !s.caps_down);
    for (size_t i = 0; i < sizeof(s.queue); i++) {
        assert(!s.queue[i]);
    }
    press(&s, KEY_A); expect(&s, "a", 1);
    apple_modern_console_input_reset(NULL);
    printf("PASS %u console input semantic checks; simulated UART, no guest execution\n", checks);
    return 0;
}
