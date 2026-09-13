/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_nt_handle.h"

#include <string.h>

static uint32_t handle_value(uint32_t slot, uint32_t generation)
{
    return (uint32_t)PW_NT_HANDLE_BASE +
           slot * (uint32_t)PW_NT_HANDLE_GENERATIONS + generation;
}

void pw_nt_handle_init(PwNtHandleTable *table)
{
    if (!table)
        return;
    memset(table, 0, sizeof(*table));
}

int pw_nt_handle_alloc(PwNtHandleTable *table, unsigned kind,
                       const PwNtObject *object, uint32_t *value)
{
    if (!table || !object || !value || kind == PW_NT_HANDLE_NONE)
        return PW_ERR_PRECONDITION;
    for (uint32_t slot = 0u; slot < (uint32_t)PW_NT_HANDLE_MAX; ++slot) {
        if (table->slots[slot].used)
            continue;
        table->slots[slot].object = *object;
        table->slots[slot].kind = (uint8_t)kind;
        table->slots[slot].used = 1u;
        table->live++;
        *value = handle_value(slot, table->slots[slot].generation);
        return PW_OK;
    }
    return PW_ERR_LIMIT;
}

uint32_t pw_nt_handle_value_of(const PwNtHandleTable *table, uint32_t slot)
{
    if (!table || slot >= (uint32_t)PW_NT_HANDLE_MAX ||
        !table->slots[slot].used)
        return 0u;
    return handle_value(slot, table->slots[slot].generation);
}

int pw_nt_handle_lookup(PwNtHandleTable *table, uint32_t value,
                        PwNtObject **object, unsigned *kind)
{
    uint32_t encoded;
    uint32_t slot;
    uint32_t generation;

    if (!table || value < (uint32_t)PW_NT_HANDLE_BASE)
        return PW_ERR_NOT_FOUND;
    encoded = value - (uint32_t)PW_NT_HANDLE_BASE;
    slot = encoded / (uint32_t)PW_NT_HANDLE_GENERATIONS;
    generation = encoded % (uint32_t)PW_NT_HANDLE_GENERATIONS;
    if (slot >= (uint32_t)PW_NT_HANDLE_MAX)
        return PW_ERR_NOT_FOUND;
    if (!table->slots[slot].used ||
        table->slots[slot].generation != generation)
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
    uint32_t slot;
    uint32_t generation;
    uint32_t encoded;

    if (!table || value < (uint32_t)PW_NT_HANDLE_BASE)
        return PW_ERR_NOT_FOUND;
    encoded = value - (uint32_t)PW_NT_HANDLE_BASE;
    slot = encoded / (uint32_t)PW_NT_HANDLE_GENERATIONS;
    generation = encoded % (uint32_t)PW_NT_HANDLE_GENERATIONS;
    if (slot >= (uint32_t)PW_NT_HANDLE_MAX ||
        !table->slots[slot].used ||
        table->slots[slot].generation != generation)
        return PW_ERR_NOT_FOUND;
    if (released)
        *released = table->slots[slot].object;
    if (kind)
        *kind = table->slots[slot].kind;
    /* The slot is free, and its next occupant gets a different value: a
     * handle the guest kept from here can never resolve again. */
    memset(&table->slots[slot], 0, sizeof(table->slots[slot]));
    table->slots[slot].generation =
        (uint8_t)((generation + 1u) % (uint32_t)PW_NT_HANDLE_GENERATIONS);
    if (table->live)
        table->live--;
    return PW_OK;
}
