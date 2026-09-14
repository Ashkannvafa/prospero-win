/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The call the self-contained tests use when they need a run to stop because
 * the bridge has no handler for it.
 *
 * It is one definition on purpose: when a handler lands, this is the single
 * place to move it on, instead of three tests that each carry their own idea
 * of what is still unimplemented. The real frontier is pinned separately by
 * tests/test_wine_gate_host.py, which knows the exact call the staged runtime
 * reaches.
 */
#ifndef PROSPERO_WIN_TESTS_PW_UNHANDLED_CALL_H
#define PROSPERO_WIN_TESTS_PW_UNHANDLED_CALL_H

/* NtQueryAttributesFile: a call the pinned runtime's ntdll issues and this
 * bridge does not service yet, which is all a test needs to stop a run. */
#define PW_TEST_UNHANDLED_CALL_ID 0x003du
#define PW_TEST_UNHANDLED_CALL_NAME "NtQueryAttributesFile"
#define PW_TEST_UNHANDLED_CALL_ARGS 8u

#endif /* PROSPERO_WIN_TESTS_PW_UNHANDLED_CALL_H */
