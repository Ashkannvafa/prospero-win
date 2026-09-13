/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The typed NT handle table on its own.
 *
 * A handle the guest holds is a value it can keep, copy, forge or reuse after
 * the object is gone, so three properties have to hold without the rest of the
 * gate: a value names a live slot of the generation it was issued for, a
 * released value never resolves again even though the slot has been reused,
 * and the table says what kind of object a live handle names so a file, a
 * directory and a key cannot be used as one another.
 */
#include "../src/pw_nt_handle.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    PwNtHandleTable table;
    PwNtObject object;
    PwNtObject *found = NULL;
    PwNtObject released;
    unsigned kind = PW_NT_HANDLE_NONE;
    uint32_t first = 0u;
    uint32_t values[PW_NT_HANDLE_MAX];

    pw_nt_handle_init(&table);
    assert(table.live == 0u);
    assert(pw_nt_handle_value_of(&table, 0u) == 0u);

    /* The first handle the guest ever sees is the documented base. */
    memset(&object, 0, sizeof(object));
    object.token = (void *)(uintptr_t)0x1111u;
    object.size = 0x4000u;
    memcpy(object.path, "\\knowndlls", sizeof("\\knowndlls"));
    assert(pw_nt_handle_alloc(&table, PW_NT_HANDLE_OBJECT_DIRECTORY, &object,
                              &first) == PW_OK);
    assert(first == PW_NT_HANDLE_BASE);
    assert(table.live == 1u);

    /* A lookup says what the handle really is. */
    assert(pw_nt_handle_lookup(&table, first, &found, &kind) == PW_OK);
    assert(kind == PW_NT_HANDLE_OBJECT_DIRECTORY);
    assert(found != NULL && found->token == object.token);
    assert(found->size == object.size);
    assert(strcmp(found->path, "\\knowndlls") == 0);
    assert(pw_nt_handle_lookup(&table, 0u, &found, &kind) == PW_ERR_NOT_FOUND);
    assert(pw_nt_handle_lookup(&table, 0x0fu, &found, &kind) == PW_ERR_NOT_FOUND);
    /* One past the last slot of the first generation is not a handle. */
    assert(pw_nt_handle_lookup(&table,
                               PW_NT_HANDLE_BASE +
                                   PW_NT_HANDLE_MAX * PW_NT_HANDLE_GENERATIONS,
                               &found, &kind) == PW_ERR_NOT_FOUND);

    /* Releasing advances the geneneration: the old value is dead, and the
     * slot's next occupant gets a different one. */
    memset(&released, 0, sizeof(released));
    assert(pw_nt_handle_release(&table, first, &released, &kind) == PW_OK);
    assert(kind == PW_NT_HANDLE_OBJECT_DIRECTORY);
    assert(released.token == object.token);
    assert(strcmp(released.path, "\\knowndlls") == 0);
    assert(table.live == 0u);
    assert(pw_nt_handle_lookup(&table, first, &found, &kind) == PW_ERR_NOT_FOUND);
    assert(pw_nt_handle_release(&table, first, &released, &kind) ==
           PW_ERR_NOT_FOUND);
    {
        uint32_t second = 0u;

        memset(&object, 0, sizeof(object));
        object.token = (void *)(uintptr_t)0x2222u;
        assert(pw_nt_handle_alloc(&table, PW_NT_HANDLE_KEY, &object,
                                  &second) == PW_OK);
        assert(second != first);
        assert(pw_nt_handle_lookup(&table, second, &found, &kind) == PW_OK);
        assert(kind == PW_NT_HANDLE_KEY);
        assert(pw_nt_handle_lookup(&table, first, &found, &kind) ==
               PW_ERR_NOT_FOUND);
        assert(pw_nt_handle_release(&table, second, &released, &kind) == PW_OK);
        assert(kind == PW_NT_HANDLE_KEY);
    }

    /* The table fills up, refuses one more, and the sweep value of every live
     * slot is distinct. */
    for (uint32_t index = 0u; index < (uint32_t)PW_NT_HANDLE_MAX; ++index) {
        memset(&object, 0, sizeof(object));
        object.token = (void *)(uintptr_t)(0x3000u + index);
        assert(pw_nt_handle_alloc(&table, PW_NT_HANDLE_FILE, &object,
                                  &values[index]) == PW_OK);
    }
    assert(table.live == PW_NT_HANDLE_MAX);
    for (uint32_t a = 0u; a < (uint32_t)PW_NT_HANDLE_MAX; ++a) {
        assert(pw_nt_handle_value_of(&table, a) == values[a]);
        for (uint32_t b = a + 1u; b < (uint32_t)PW_NT_HANDLE_MAX; ++b)
            assert(values[a] != values[b]);
    }
    memset(&object, 0, sizeof(object));
    assert(pw_nt_handle_alloc(&table, PW_NT_HANDLE_FILE, &object, &first) ==
           PW_ERR_LIMIT);
    assert(table.live == PW_NT_HANDLE_MAX);

    /* Freeing one makes room, and the value it hands out is still new. */
    assert(pw_nt_handle_release(&table, values[3], &released, &kind) == PW_OK);
    assert(pw_nt_handle_value_of(&table, 3u) == 0u);
    assert(table.live == PW_NT_HANDLE_MAX - 1u);
    assert(pw_nt_handle_alloc(&table, PW_NT_HANDLE_SECTION, &object,
                              &first) == PW_OK);
    /* The slot is the same one, one generation later. */
    assert(first == values[3] + 1u);
    for (uint32_t index = 0u; index < (uint32_t)PW_NT_HANDLE_MAX; ++index)
        if (index != 3u)
            assert(first != values[index]);
    assert(pw_nt_handle_lookup(&table, values[3], &found, &kind) ==
           PW_ERR_NOT_FOUND);
    return 0;
}
