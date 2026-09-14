/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The typed NT handle table on its own.
 *
 * A handle the guest holds is a value it can keep, copy, forge or reuse after
 * the object is gone, so three properties have to hold without the rest of the
 * gate: a value names a live slot, a released value never resolves again even
 * though the slot has been reused many times, and the table says what kind of
 * object a live handle names so a file, a directory and a key cannot be used
 * as one another. The opacity is the point; secrecy is not claimed.
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
    /* A value the table never issued is not a handle. */
    assert(pw_nt_handle_lookup(&table, PW_NT_HANDLE_BASE + 0x1000u, &found,
                               &kind) == PW_ERR_NOT_FOUND);

    /* Releasing retires the value: the old one is dead, and the slot's next
     * occupant gets a fresh one. */
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
    /* The slot is reused, but the value is fresh - it is not the retired one
     * and it is not a value any other live handle carries. */
    assert(first != values[3]);
    assert(first > values[3]);
    for (uint32_t index = 0u; index < (uint32_t)PW_NT_HANDLE_MAX; ++index)
        if (index != 3u)
            assert(first != values[index]);
    assert(pw_nt_handle_lookup(&table, values[3], &found, &kind) ==
           PW_ERR_NOT_FOUND);

    /*
     * The regression the final review asked for: reuse one slot many times
     * over - well past the 16 cycles the old generation counter allowed - and
     * prove every retired value stays dead. The first value must not resolve
     * again even after the slot has been handed out 17 more times.
     */
    {
        uint32_t current = first;
        uint32_t retired[24];

        for (unsigned cycle = 0u; cycle < 24u; ++cycle) {
            uint32_t next = 0u;

            retired[cycle] = current;
            assert(pw_nt_handle_release(&table, current, &released, &kind) ==
                   PW_OK);
            assert(pw_nt_handle_lookup(&table, current, &found, &kind) ==
                   PW_ERR_NOT_FOUND);
            memset(&object, 0, sizeof(object));
            object.token = (void *)(uintptr_t)(0x9000u + cycle);
            assert(pw_nt_handle_alloc(&table, PW_NT_HANDLE_FILE, &object,
                                      &next) == PW_OK);
            for (unsigned earlier = 0u; earlier <= cycle; ++earlier)
                assert(next != retired[earlier]);
            for (unsigned earlier = 0u; earlier <= cycle; ++earlier)
                assert(pw_nt_handle_lookup(&table, retired[earlier], &found,
                                           &kind) == PW_ERR_NOT_FOUND);
            current = next;
        }
        /* Every value the loop issued is still usable while it is live. */
        assert(pw_nt_handle_lookup(&table, current, &found, &kind) == PW_OK);
        assert(pw_nt_handle_release(&table, current, &released, &kind) ==
               PW_OK);
    }
    for (uint32_t index = 0u; index < (uint32_t)PW_NT_HANDLE_MAX; ++index)
        if (index != 3u && table.slots[index].used)
            assert(pw_nt_handle_release(&table, table.slots[index].value,
                                        &released, &kind) == PW_OK);
    assert(table.live == 0u);
    return 0;
}
