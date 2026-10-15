/* Bounded native ANS metadata preparation; no loader or execution.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef HW_ARM_APPLE_MODERN_ANS_PREPARATION_H
#define HW_ARM_APPLE_MODERN_ANS_PREPARATION_H

#include "hw/arm/apple-silicon/modern-boot-layout.h"

#define APPLE_MODERN_ANS_MAX_IMAGE_SIZE (UINT64_C(16) << 20)
#define APPLE_MODERN_ANS_MAX_COMMAND_BYTES (UINT64_C(64) << 10)
#define APPLE_MODERN_ANS_MAX_COMMANDS 128U
#define APPLE_MODERN_ANS_MAX_SEGMENTS 16U
#define APPLE_MODERN_ANS_MAX_SECTIONS 128U

typedef struct AppleModernANSSegmentMetadata {
    char name[17];
    uint64_t virtual_address, memory_size;
    uint64_t source_offset, declared_file_bytes, available_file_bytes;
    /* Informational anomaly, never an implicit copy or zero-fill policy. */
    uint64_t missing_file_tail_bytes, missing_tail_virtual_address;
    /* Ordinary Mach-O memory beyond the declared filesize, not a short file. */
    uint64_t declared_zero_virtual_address, declared_zero_bytes;
    uint32_t maximum_protection, initial_protection;
    uint32_t first_section, section_count;
} AppleModernANSSegmentMetadata;

typedef struct AppleModernANSSectionMetadata {
    char name[17];
    uint32_t segment_index;
    uint64_t virtual_address, size, source_offset;
    uint32_t alignment_exponent, type, flags;
    uint32_t relocation_source_offset, relocation_count;
    uint32_t reserved1, reserved2, reserved3;
    bool file_backed;
} AppleModernANSSectionMetadata;

typedef struct AppleModernANSPreparation {
    AppleModernANSSegmentMetadata segments[APPLE_MODERN_ANS_MAX_SEGMENTS];
    AppleModernANSSectionMetadata sections[APPLE_MODERN_ANS_MAX_SECTIONS];
    uint32_t segment_count, section_count, command_count;
    uint32_t cpu_subtype, header_flags;
    uint64_t image_bytes, virtual_low, virtual_high;
    uint64_t total_declared_file_bytes, total_available_file_bytes;
    uint64_t total_missing_file_tail_bytes;
    bool metadata_valid;
    /* True only when every declared segment file extent is available. This
     * authorizes no mapping, padding, fixups or execution by itself. */
    bool full_segment_copy_eligible;
    bool chain_section_present;
    uint32_t chain_section_index;
    bool thread_entry_present, main_entry_present;
    uint64_t thread_entry_virtual_address;
    uint64_t main_entry_source_offset, main_stack_size;
    /* Always false: boot ABI, mappings, fixups and CPU/device state are outside
     * this preparation module, including when an entry command is present. */
    bool execution_eligible;
} AppleModernANSPreparation;

/* Parse an unchanged, decoded ARM64e MH_PRELOAD blob into bounded metadata.
 * Recognized commands are LC_SEGMENT_64, a canonical ARM64 LC_UNIXTHREAD,
 * and LC_MAIN. Unsupported commands and segment flags are rejected.
 * A missing declared file tail is accepted only when no nonempty section
 * covers it; it is recorded and makes full_segment_copy_eligible false.
 * Section-covered truncation and malformed extents fail. No pointer chains,
 * payload instructions, authentication, allocation policy or guest memory are
 * processed. Output contains no input pointers and input is never modified.
 * Non-alias failures clear output; a forbidden output/input alias leaves both
 * untouched. A successful parse is not execution eligibility. */
bool apple_modern_ans_preparation_parse(AppleModernBlob native,
                                      AppleModernANSPreparation *output,
                                      Error **errp);

#endif
