/* Resolver for the w14-compatsweep "adt-compat-restore" board option.  The group
 * tables themselves are generated into modern-compat-groups.c; this file holds
 * the hand-written lookup and '+'-composition logic and nothing else.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifdef APPLE_MODERN_LAYOUT_STANDALONE
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#else
#include "qemu/osdep.h"
#include "qapi/error.h"
#endif
#include "hw/arm/apple-silicon/modern-compat-groups.h"

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

/* Longest list this resolver accepts, so the name buffer and the seen[] array
 * below are both fixed size and the parser can never run away. */
#define COMPAT_GROUP_LIST_MAX 512
#define COMPAT_GROUP_NAME_MAX 64

const AppleModernCompatGroup *apple_modern_compat_group(const char *name)
{
    if (!name) {
        return NULL;
    }
    for (size_t i = 0; i < apple_modern_compat_group_count; i++) {
        if (!strcmp(apple_modern_compat_groups[i].name, name)) {
            return &apple_modern_compat_groups[i];
        }
    }
    return NULL;
}

const char *apple_modern_compat_group_names(void)
{
    static char buffer[COMPAT_GROUP_LIST_MAX];
    size_t used = 0;

    buffer[0] = '\0';
    for (size_t i = 0; i < apple_modern_compat_group_count; i++) {
        const char *name = apple_modern_compat_groups[i].name;
        size_t need = strlen(name) + (used ? 2 : 0);
        if (used + need + 1 > sizeof(buffer)) {
            break;
        }
        if (used) {
            memcpy(buffer + used, ", ", 2);
            used += 2;
        }
        memcpy(buffer + used, name, strlen(name));
        used += strlen(name);
        buffer[used] = '\0';
    }
    return buffer;
}

/*
 * Walk a '+'-separated list, handing each group to the caller's visitor.  One
 * parser for resolve() and supply_dart_id() so the two can never disagree about
 * what a list means.  Returns false with errp set on the first bad token.
 */
static bool for_each_group(const char *list,
                           const AppleModernCompatGroup **found,
                           size_t *found_count, Error **errp)
{
    size_t count = 0;

    *found_count = 0;
    if (!list || !*list) {
        error_setg(errp, "adt-compat-restore: empty group list");
        return false;
    }
    if (strlen(list) >= COMPAT_GROUP_LIST_MAX) {
        error_setg(errp, "adt-compat-restore: group list longer than %d bytes",
                   COMPAT_GROUP_LIST_MAX - 1);
        return false;
    }
    for (const char *cursor = list;;) {
        const char *plus = strchr(cursor, '+');
        size_t length = plus ? (size_t)(plus - cursor) : strlen(cursor);
        char name[COMPAT_GROUP_NAME_MAX];
        const AppleModernCompatGroup *group;

        if (length == 0 || length >= sizeof(name)) {
            error_setg(errp, "adt-compat-restore: empty or over-long group "
                       "name in '%s' (supported: %s)", list,
                       apple_modern_compat_group_names());
            return false;
        }
        memcpy(name, cursor, length);
        name[length] = '\0';
        group = apple_modern_compat_group(name);
        if (!group) {
            error_setg(errp, "adt-compat-restore: unknown group '%s' "
                       "(supported: %s)", name,
                       apple_modern_compat_group_names());
            return false;
        }
        for (size_t i = 0; i < count; i++) {
            if (found[i] == group) {
                error_setg(errp, "adt-compat-restore: group '%s' named twice",
                           name);
                return false;
            }
        }
        if (count >= apple_modern_compat_group_count) {
            /* Unreachable with the duplicate check above, but the array bound
             * is enforced rather than reasoned about. */
            error_setg(errp, "adt-compat-restore: too many groups");
            return false;
        }
        found[count++] = group;
        if (!plus) {
            break;
        }
        cursor = plus + 1;
    }
    *found_count = count;
    return true;
}

bool apple_modern_compat_groups_resolve(const char *list,
                                        AppleModernAdtOverride *out,
                                        size_t *count, size_t capacity,
                                        Error **errp)
{
    const AppleModernCompatGroup *found[16];
    size_t found_count = 0, total = 0;

    if (!out || !count) {
        error_setg(errp, "adt-compat-restore: no output");
        return false;
    }
    if (apple_modern_compat_group_count > sizeof(found) / sizeof(found[0])) {
        error_setg(errp, "adt-compat-restore: resolver array too small");
        return false;
    }
    if (!for_each_group(list, found, &found_count, errp)) {
        return false;
    }
    for (size_t i = 0; i < found_count; i++) {
        total += found[i]->row_count;
    }
    if (*count > capacity || total > capacity - *count) {
        error_setg(errp, "adt-compat-restore: '%s' needs %zu ADT overrides and "
                   "only %zu of %zu are free", list, total, capacity - *count,
                   capacity);
        return false;
    }
    for (size_t i = 0; i < found_count; i++) {
        for (size_t row = 0; row < found[i]->row_count; row++) {
            out[(*count)++] = found[i]->rows[row];
        }
    }
    return true;
}

bool apple_modern_compat_groups_supply_dart_id(const char *list)
{
    const AppleModernCompatGroup *found[16];
    size_t found_count = 0;

    if (apple_modern_compat_group_count > sizeof(found) / sizeof(found[0]) ||
        !for_each_group(list, found, &found_count, NULL)) {
        return false;
    }
    for (size_t i = 0; i < found_count; i++) {
        for (size_t row = 0; row < found[i]->row_count; row++) {
            if (!strcmp(found[i]->rows[row].name, "dart-id")) {
                return true;
            }
        }
    }
    return false;
}
