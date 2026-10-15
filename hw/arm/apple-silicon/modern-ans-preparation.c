/* Bounded native ANS metadata preparation; no loader or execution.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#endif
#include "hw/arm/apple-silicon/modern-ans-preparation.h"

#ifdef APPLE_MODERN_LAYOUT_STANDALONE
static void error_setg(Error **errp, const char *format, ...)
{
    if (errp) {
        va_list args;
        if (*errp) {
            abort();
        }
        *errp = calloc(1, sizeof(**errp));
        if (!*errp) {
            abort();
        }
        va_start(args, format);
        vsnprintf((*errp)->message, sizeof((*errp)->message), format, args);
        va_end(args);
    }
}
#endif

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
    return le32(p) | (uint64_t)le32(p + 4) << 32;
}

static bool span(uint64_t start, uint64_t size, uint64_t limit)
{
    return start <= limit && size <= limit - start;
}

static bool overlap(uint64_t a, uint64_t as, uint64_t b, uint64_t bs)
{
    /* All callers establish nonwrapping extents first. Empty extents do not
     * overlap, including colocated zero-size sections in this firmware. */
    return as && bs && a < b + bs && b < a + as;
}

static bool aliases(const void *a, size_t as, const void *b, size_t bs)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return as && bs && (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y ||
                       (x < y + bs && y < x + as));
}

static bool fail(Error **errp, const char *reason)
{
    error_setg(errp, "modern ANS preparation: %s", reason);
    return false;
}

static bool name_copy(char name[17], const uint8_t *source)
{
    bool padding = false;
    if (!source[0]) {
        return false;
    }
    for (unsigned i = 0; i < 16; i++) {
        if (!source[i]) {
            padding = true;
        } else if (padding || source[i] < 32 || source[i] > 126) {
            return false;
        }
        name[i] = source[i];
    }
    name[16] = 0;
    return true;
}

static bool parse_segment(AppleModernBlob native, const uint8_t *command,
                          uint32_t command_size,
                          AppleModernANSPreparation *plan, Error **errp)
{
    AppleModernANSSegmentMetadata *s;
    uint32_t count, index = plan->segment_count;
    if (command_size < 72 || index == APPLE_MODERN_ANS_MAX_SEGMENTS) {
        return fail(errp, "truncated segment or segment limit exceeded");
    }
    count = le32(command + 64);
    if (count > APPLE_MODERN_ANS_MAX_SECTIONS - plan->section_count ||
        command_size != 72 + (uint64_t)count * 80) {
        return fail(errp, "section count/table bounds mismatch");
    }
    s = &plan->segments[index];
    if (!name_copy(s->name, command + 8)) {
        return fail(errp, "invalid segment name");
    }
    s->virtual_address = le64(command + 24);
    s->memory_size = le64(command + 32);
    s->source_offset = le64(command + 40);
    s->declared_file_bytes = le64(command + 48);
    s->maximum_protection = le32(command + 56);
    s->initial_protection = le32(command + 60);
    s->first_section = plan->section_count;
    s->section_count = count;
    if (!s->memory_size || s->memory_size > APPLE_MODERN_ANS_MAX_IMAGE_SIZE ||
        !span(s->virtual_address, s->memory_size, UINT64_MAX) ||
        s->declared_file_bytes > s->memory_size ||
        s->source_offset > native.size ||
        !span(s->source_offset, s->declared_file_bytes,
              APPLE_MODERN_ANS_MAX_IMAGE_SIZE) ||
        (s->maximum_protection & ~7U) ||
        (s->initial_protection & ~s->maximum_protection) ||
        le32(command + 68)) {
        return fail(errp, "invalid segment bounds/protection or unsupported flags");
    }
    if (s->declared_file_bytes > APPLE_MODERN_ANS_MAX_IMAGE_SIZE -
            plan->total_declared_file_bytes) {
        return fail(errp, "aggregate file extent limit exceeded");
    }
    for (uint32_t i = 0; i < index; i++) {
        AppleModernANSSegmentMetadata *old = &plan->segments[i];
        if (!strcmp(old->name, s->name) ||
            overlap(s->virtual_address, s->memory_size,
                    old->virtual_address, old->memory_size) ||
            overlap(s->source_offset, s->declared_file_bytes,
                    old->source_offset, old->declared_file_bytes)) {
            return fail(errp, "duplicate or overlapping segments");
        }
    }
    s->available_file_bytes = native.size - s->source_offset;
    if (s->available_file_bytes > s->declared_file_bytes) {
        s->available_file_bytes = s->declared_file_bytes;
    }
    s->missing_file_tail_bytes = s->declared_file_bytes - s->available_file_bytes;
    if (s->missing_file_tail_bytes) {
        s->missing_tail_virtual_address = s->virtual_address + s->available_file_bytes;
    }
    s->declared_zero_bytes = s->memory_size - s->declared_file_bytes;
    if (s->declared_zero_bytes) {
        s->declared_zero_virtual_address = s->virtual_address + s->declared_file_bytes;
    }
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *c = command + 72 + (uint64_t)i * 80;
        AppleModernANSSectionMetadata *section = &plan->sections[plan->section_count];
        char owner[17];
        uint64_t relative;
        if (!name_copy(section->name, c) || !name_copy(owner, c + 16) ||
            strcmp(owner, s->name)) {
            return fail(errp, "invalid section name or segment owner");
        }
        section->segment_index = index;
        section->virtual_address = le64(c + 32);
        section->size = le64(c + 40);
        section->source_offset = le32(c + 48);
        section->alignment_exponent = le32(c + 52);
        section->relocation_source_offset = le32(c + 56);
        section->relocation_count = le32(c + 60);
        section->flags = le32(c + 64);
        section->type = section->flags & 255;
        section->reserved1 = le32(c + 68);
        section->reserved2 = le32(c + 72);
        section->reserved3 = le32(c + 76);
        section->file_backed = section->type != 1 && section->type != 12 &&
                               section->type != 18;
        if (section->virtual_address < s->virtual_address ||
            !span(section->virtual_address - s->virtual_address,
                  section->size, s->memory_size) ||
            section->alignment_exponent > 31 ||
            (section->virtual_address &
                ((UINT64_C(1) << section->alignment_exponent) - 1)) ||
            !span(section->relocation_source_offset,
                  (uint64_t)section->relocation_count * 8, native.size)) {
            return fail(errp, "invalid section VM/alignment/relocation extent");
        }
        relative = section->virtual_address - s->virtual_address;
        if (section->file_backed &&
            (!span(section->source_offset, section->size, native.size) ||
             section->source_offset < s->source_offset ||
             !span(section->source_offset - s->source_offset, section->size,
                   s->declared_file_bytes) ||
             section->source_offset - s->source_offset != relative)) {
            return fail(errp, "section file extent/mapping invalid or truncated");
        }
        if (s->missing_file_tail_bytes &&
            overlap(section->virtual_address, section->size,
                    s->missing_tail_virtual_address, s->missing_file_tail_bytes)) {
            return fail(errp, "missing declared file tail is covered by a section");
        }
        for (uint32_t j = s->first_section; j < plan->section_count; j++) {
            AppleModernANSSectionMetadata *old = &plan->sections[j];
            if (!strcmp(old->name, section->name) ||
                overlap(section->virtual_address, section->size,
                        old->virtual_address, old->size)) {
                return fail(errp, "duplicate or overlapping sections");
            }
        }
        if (!strcmp(s->name, "__TEXT") &&
            !strcmp(section->name, "__chain_starts")) {
            if (plan->chain_section_present) {
                return fail(errp, "duplicate chain starts section");
            }
            plan->chain_section_present = true;
            plan->chain_section_index = plan->section_count;
        }
        plan->section_count++;
    }
    plan->total_declared_file_bytes += s->declared_file_bytes;
    plan->total_available_file_bytes += s->available_file_bytes;
    plan->total_missing_file_tail_bytes += s->missing_file_tail_bytes;
    if (s->virtual_address < plan->virtual_low) {
        plan->virtual_low = s->virtual_address;
    }
    if (s->virtual_address + s->memory_size > plan->virtual_high) {
        plan->virtual_high = s->virtual_address + s->memory_size;
    }
    plan->segment_count++;
    return true;
}

bool apple_modern_ans_preparation_parse(AppleModernBlob native,
                                      AppleModernANSPreparation *output,
                                      Error **errp)
{
    AppleModernANSPreparation plan = {0};
    uint64_t cursor, end;
    uint32_t bytes, count;
    if (!output || aliases(output, sizeof(*output), native.data, native.size)) {
        return fail(errp, "output missing or aliases input");
    }
    memset(output, 0, sizeof(*output));
    if (!native.data || native.size < 32 ||
        native.size > APPLE_MODERN_ANS_MAX_IMAGE_SIZE) {
        return fail(errp, "native image missing, truncated or over budget");
    }
    if (le32(native.data) != 0xfeedfacf || le32(native.data + 4) != 0x0100000c ||
        (le32(native.data + 8) != 2 && le32(native.data + 8) != 0x80000002) ||
        le32(native.data + 12) != 5 || le32(native.data + 28)) {
        return fail(errp, "expected little-endian ARM64e MH_PRELOAD header");
    }
    count = le32(native.data + 16);
    bytes = le32(native.data + 20);
    if (!count || count > APPLE_MODERN_ANS_MAX_COMMANDS ||
        bytes > APPLE_MODERN_ANS_MAX_COMMAND_BYTES ||
        !span(32, bytes, native.size)) {
        return fail(errp, "command table count/extent limit");
    }
    plan.cpu_subtype = le32(native.data + 8);
    plan.header_flags = le32(native.data + 24);
    plan.command_count = count;
    plan.image_bytes = native.size;
    plan.virtual_low = UINT64_MAX;
    cursor = 32;
    end = cursor + bytes;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *c;
        uint32_t cmd, size;
        if (!span(cursor, 8, end)) {
            return fail(errp, "truncated command header");
        }
        c = native.data + cursor;
        cmd = le32(c);
        size = le32(c + 4);
        if (size < 8 || size % 8 || !span(cursor, size, end)) {
            return fail(errp, "command size/alignment invalid");
        }
        if (cmd == 0x19) {
            if (!parse_segment(native, c, size, &plan, errp)) {
                return false;
            }
        } else if (cmd == 5) {
            if (plan.thread_entry_present || plan.main_entry_present ||
                size != 288 || le32(c + 8) != 6 || le32(c + 12) != 68) {
                return fail(errp, "invalid or duplicate ARM64 thread entry metadata");
            }
            plan.thread_entry_present = true;
            plan.thread_entry_virtual_address = le64(c + 272);
        } else if (cmd == 0x80000028) {
            if (plan.thread_entry_present || plan.main_entry_present || size != 24) {
                return fail(errp, "invalid or duplicate main entry metadata");
            }
            plan.main_entry_present = true;
            plan.main_entry_source_offset = le64(c + 8);
            plan.main_stack_size = le64(c + 16);
        } else {
            return fail(errp, "unsupported load command");
        }
        cursor += size;
    }
    if (cursor != end || !plan.segment_count ||
        plan.virtual_high - plan.virtual_low > APPLE_MODERN_ANS_MAX_IMAGE_SIZE) {
        return fail(errp, "command coverage, segment count or VM-span limit");
    }
    plan.metadata_valid = true;
    plan.full_segment_copy_eligible = !plan.total_missing_file_tail_bytes;
    /* No entry ABI, mappings, chain fixups or CPU state are provided here. */
    plan.execution_eligible = false;
    *output = plan;
    return true;
}
