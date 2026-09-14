/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Direct boundary contract for the reusable Wine handle-object builder. */
#include "../src/pw_wine_handle.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    PwNtObject object;
    char exact[PW_NT_HANDLE_PATH_MAX + 1u];
    char over[PW_NT_HANDLE_PATH_MAX + 2u];
    void *const token = (void *)(uintptr_t)0x1234u;

    memset(exact, 'a', sizeof(exact) - 1u);
    exact[sizeof(exact) - 1u] = '\0';
    memset(over, 'b', sizeof(over) - 1u);
    over[sizeof(over) - 1u] = '\0';

    assert(pw_wine_handle_object(token, 42u, NULL, NULL) ==
           PW_ERR_PRECONDITION);

    memset(&object, 0xa5, sizeof(object));
    assert(pw_wine_handle_object(token, 42u, NULL, &object) == PW_OK);
    assert(object.token == token);
    assert(object.size == 42u);
    assert(object.path[0] == '\0');

    memset(&object, 0xa5, sizeof(object));
    assert(pw_wine_handle_object(token, 42u, exact, &object) == PW_OK);
    assert(object.token == token);
    assert(object.size == 42u);
    assert(strlen(object.path) == PW_NT_HANDLE_PATH_MAX);
    assert(strcmp(object.path, exact) == 0);

    memset(&object, 0xa5, sizeof(object));
    assert(pw_wine_handle_object(token, 42u, over, &object) == PW_ERR_LIMIT);
    assert(object.path[0] == '\0');

    puts("wine handle object passed: null, exact and over-limit paths");
    return 0;
}
