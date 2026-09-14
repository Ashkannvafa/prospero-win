/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The run workspace on its own: two of them are two objects.
 *
 * The gate used to keep its loader, import workspace, export resolver and
 * translation cache in function-local statics, so a second run in one host
 * process shared mutable state. This pins the replacement: independent
 * initialization, no aliasing between instances, a released instance refused,
 * and an uninitialized one refused too.
 */
#include "../src/pw_wine_runner.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    static PwWineRunner first, second;
    PwWineRunner uninitialized;

    pw_wine_runner_init(&first);
    pw_wine_runner_init(&second);
    assert(pw_wine_runner_ready(&first));
    assert(pw_wine_runner_ready(&second));
    /* Two objects, not two views of one: the caches do not alias. */
    assert(&first.cache[0] != &second.cache[0]);
    assert(&first.loader != &second.loader);
    /* Writing one leaves the other exactly as it was: the two workspaces are
     * identical while both are fresh, and differ as soon as one is touched. */
    assert(memcmp(&first.workspace, &second.workspace,
                  sizeof(first.workspace)) == 0);
    memset(&first.workspace, 0x5a, sizeof(first.workspace));
    assert(memcmp(&first.workspace, &second.workspace,
                  sizeof(first.workspace)) != 0);
    first.loader.module_count = 3u;
    assert(second.loader.module_count == 0u);
    /* Releasing one does not disturb the other, and the released one is
     * refused until it is initialized again. */
    pw_wine_runner_release(&first);
    assert(!pw_wine_runner_ready(&first));
    assert(pw_wine_runner_ready(&second));
    pw_wine_runner_init(&first);
    assert(pw_wine_runner_ready(&first));
    assert(first.loader.module_count == 0u);
    /* An object nobody initialized, and no object at all. */
    memset(&uninitialized, 0, sizeof(uninitialized));
    assert(!pw_wine_runner_ready(&uninitialized));
    assert(!pw_wine_runner_ready(NULL));
    /* The lifecycle calls tolerate NULL so a cleanup path can always call
     * them. */
    pw_wine_runner_release(NULL);
    pw_wine_runner_init(NULL);
    return 0;
}
