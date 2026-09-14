/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The file adapter: NtOpenFile, NtReadFile, NtQueryInformationFile,
 * NtQueryVolumeInformationFile and the gate-owned directory object.
 *
 * The distribution's files live behind the pluggable PwWineFileService, so the
 * portable core makes no host file-system call itself. What this unit owns is
 * everything between the guest and that service: the DOS/NT path shape a Wine
 * loader actually uses, the gate-owned directory object for the Windows
 * directory (no enumeration, no platform token - only its existence and
 * Directory = 1), the IO_STATUS_BLOCK written back through the validated
 * accessor, and the real NTSTATUS for every refused shape.
 */
#ifndef PROSPERO_WIN_PW_WINE_FILE_H
#define PROSPERO_WIN_PW_WINE_FILE_H

#include "pw_nt_dispatch.h"

struct PwWineCallContext;

/* NtOpenFile (0x0033). */
int pw_wine_file_open(struct PwWineCallContext *calls,
                      const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                      void *context, uint32_t *status,
                      uint32_t *argument_index);

/* NtReadFile (0x0006). */
int pw_wine_file_read(struct PwWineCallContext *calls,
                      const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                      void *context, uint32_t *status,
                      uint32_t *argument_index);

/* NtQueryInformationFile (0x0011), FileStandardInformation only. */
int pw_wine_file_query_information(struct PwWineCallContext *calls,
                                   const PwUnixCallFrame *frame,
                                   PwUnixCallAccess guest, void *context,
                                   uint32_t *status, uint32_t *argument_index);

/* NtQueryVolumeInformationFile (0x0049), FileFsDeviceInformation only. */
int pw_wine_file_query_volume_information(struct PwWineCallContext *calls,
                                          const PwUnixCallFrame *frame,
                                          PwUnixCallAccess guest, void *context,
                                          uint32_t *status,
                                          uint32_t *argument_index);

/* NtFsControlFile (0x0039), FSCTL_GET_OBJECT_ID only. */
int pw_wine_file_fs_control(struct PwWineCallContext *calls,
                            const PwUnixCallFrame *frame,
                            PwUnixCallAccess guest, void *context,
                            uint32_t *status, uint32_t *argument_index);

#endif /* PROSPERO_WIN_PW_WINE_FILE_H */
