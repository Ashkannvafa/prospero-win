/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_nt_handle.h"

#include <string.h>

void pw_nt_handle_init(PwNtHandleTable *table)
{
    if (!table)
        return;
    memset(table, 0, sizeof(*table));
}

int pw_nt_handle_alloc(PwNtHandleTable *table, unsigned kind,
                       const PwNtObject *object, uint32_t *value)
{
    uint32_t issued;

    if (!table || !object || !value || kind == PW_NT_HANDLE_NONE)
        return PW_ERR_PRECONDITION;
    if (table->exhausted)
        return PW_ERR_LIMIT;
    if (table->next_value < (uint32_t)PW_NT_HANDLE_BASE)
        table->next_value = (uint32_t)PW_NT_HANDLE_BASE;
    /*
     * A value is issued once in the table's lifetime. Reaching the end of the
     * 32-bit space stops the table rather than wrapping: a wrapped value could
     * resolve to a different object, which is the aliasing this design exists
     * to prevent. PW_NT_HANDLE_MAX is 16 and a run opens far fewer objects
     * than 2^32, so the bound is a guarantee, not a practical limit.
     */
    if (table->next_value == 0u || table->next_value == UINT32_MAX) {
        table->exhausted = 1u;
        return PW_ERR_LIMIT;
    }
    for (uint32_t slot = 0u; slot < (uint32_t)PW_NT_HANDLE_MAX; ++slot) {
        if (table->slots[slot].used)
            continue;
        issued = table->next_value++;
        table->slots[slot].object = *object;
        table->slots[slot].value = issued;
        table->slots[slot].kind = (uint8_t)kind;
        table->slots[slot].used = 1u;
        table->live++;
        *value = issued;
        return PW_OK;
    }
    return PW_ERR_LIMIT;
}

uint32_t pw_nt_handle_value_of(const PwNtHandleTable *table, uint32_t slot)
{
    if (!table || slot >= (uint32_t)PW_NT_HANDLE_MAX ||
        !table->slots[slot].used)
        return 0u;
    return table->slots[slot].value;
}

int pw_nt_handle_exhausted(const PwNtHandleTable *table)
{
    return table && table->exhausted;
}

/* The slot holding `value`, or PW_NT_HANDLE_MAX when no live slot does. */
static uint32_t find_slot(const PwNtHandleTable *table, uint32_t value)
{
    if (!table || value == 0u)
        return (uint32_t)PW_NT_HANDLE_MAX;
    for (uint32_t slot = 0u; slot < (uint32_t)PW_NT_HANDLE_MAX; ++slot)
        if (table->slots[slot].used && table->slots[slot].value == value)
            return slot;
    return (uint32_t)PW_NT_HANDLE_MAX;
}

int pw_nt_handle_lookup(PwNtHandleTable *table, uint32_t value,
                        PwNtObject **object, unsigned *kind)
{
    const uint32_t slot = find_slot(table, value);

    if (slot >= (uint32_t)PW_NT_HANDLE_MAX)
        return PW_ERR_NOT_FOUND;
    if (object)
        *object = &table->slots[slot].object;
    if (kind)
        *kind = table->slots[slot].kind;
    return PW_OK;
}

int pw_nt_handle_release(PwNtHandleTable *table, uint32_t value,
                         PwNtObject *released, unsigned *kind)
{
    const uint32_t slot = find_slot(table, value);

    if (slot >= (uint32_t)PW_NT_HANDLE_MAX)
        return PW_ERR_NOT_FOUND;
    if (released)
        *released = table->slots[slot].object;
    if (kind)
        *kind = table->slots[slot].kind;
    /* The slot becomes free and the value it carried is retired: the next
     * occupant gets a fresh one, so a handle the guest kept from here can
     * never resolve again - however often this slot is reused. */
    memset(&table->slots[slot], 0, sizeof(table->slots[slot]));
    if (table->live)
        table->live--;
    return PW_OK;
}
