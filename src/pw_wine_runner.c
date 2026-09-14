/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_wine_runner.h"

#include <string.h>

void pw_wine_runner_init(PwWineRunner *runner)
{
    if (!runner)
        return;
    memset(runner, 0, sizeof(*runner));
    runner->ready = PW_WINE_RUNNER_READY;
}

void pw_wine_runner_release(PwWineRunner *runner)
{
    if (!runner)
        return;
    memset(runner, 0, sizeof(*runner));
}

int pw_wine_runner_ready(const PwWineRunner *runner)
{
    return runner && runner->ready == PW_WINE_RUNNER_READY;
}
