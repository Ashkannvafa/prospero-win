/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The second-dispatcher table on its own.
 *
 * The table is versioned data: a guest passes a code and the gate must either
 * name the pinned entry or refuse. Two properties matter here and neither
 * needs Wine: the table is dense and ordered (code == index, count matches the
 * declared maximum) and anything outside it - including the huge values a
 * malicious caller can pass - is refused rather than wrapped into a valid
 * entry. tests/test_unixlib_table.py holds the other half of the contract, the
 * comparison with the pinned Wine source.
 */
#include "../src/pw_unixlib.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    uint32_t count = 0u;
    const PwUnixlibFunc *funcs = pw_unixlib_funcs(&count);
    const PwUnixlibFunc *entry;

    assert(funcs != NULL);
    assert(count == (uint32_t)PW_UNIXLIB_MAX_FUNCS);
    for (uint32_t index = 0u; index < count; ++index) {
        assert(funcs[index].code == index);
        assert(funcs[index].name != NULL);
        assert(strlen(funcs[index].name) <= PW_UNIXLIB_NAME_MAX);
        assert(pw_unixlib_lookup(index) == &funcs[index]);
    }
    /* The first call the pinned trace reaches, by name and by code. */
    entry = pw_unixlib_lookup(PW_UNIXLIB_CODE_WINE_DBG_WRITE);
    assert(entry != NULL && strcmp(entry->name, "unix_wine_dbg_write") == 0);
    /* One past the table and the widest possible guest value: both refused. */
    assert(pw_unixlib_lookup(count) == NULL);
    assert(pw_unixlib_lookup(0xffffffffu) == NULL);
    /* The count is optional for callers that only want the table. */
    assert(pw_unixlib_funcs(NULL) == funcs);
    return 0;
}
