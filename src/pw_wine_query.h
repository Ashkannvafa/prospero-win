/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The calls that answer questions about the run itself.
 *
 * These three have nothing in common except that their answer is host state
 * rather than a platform object: NtQuerySystemInformation's Wine version class
 * reports the distribution the guest is actually executing (derived by the
 * host from the manifest), NtQueryInformationToken's TokenUser reports the SID
 * the host declares for the process, and NtQueryInformationProcess's
 * ProcessImageInformation describes the mapped module out of its own PE
 * headers. None of them invents an answer: with no declared value the class is
 * STATUS_NOT_SUPPORTED rather than a guess.
 */
#ifndef PROSPERO_WIN_PW_WINE_QUERY_H
#define PROSPERO_WIN_PW_WINE_QUERY_H

#include "pw_nt_dispatch.h"

struct PwWineCallContext;

/* NtQuerySystemInformation (0x0036), the Wine version class (1000). */
int pw_wine_query_system_information(struct PwWineCallContext *calls,
                                     const PwUnixCallFrame *frame,
                                     PwUnixCallAccess guest, void *context,
                                     uint32_t *status,
                                     uint32_t *argument_index);

/* NtQueryInformationToken (0x0021), TokenUser for the current token. */
int pw_wine_query_token(struct PwWineCallContext *calls,
                        const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                        void *context, uint32_t *status,
                        uint32_t *argument_index);

/* NtQueryInformationProcess (0x0019), ProcessImageInformation. */
int pw_wine_query_process_image(struct PwWineCallContext *calls,
                                const PwUnixCallFrame *frame,
                                PwUnixCallAccess guest, void *context,
                                uint32_t *status, uint32_t *argument_index);

#endif /* PROSPERO_WIN_PW_WINE_QUERY_H */
