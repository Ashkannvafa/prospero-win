/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_IMPORT_BIND_H
#define PW_IMPORT_BIND_H
#include "pe_import.h"
#include "pw_map.h"
enum { PW_IMPORT_BIND_CAPACITY=512 };
typedef enum PwImportKind { PW_IMPORT_FUNCTION=1, PW_IMPORT_DATA=2 } PwImportKind;
typedef struct PwImportTarget { uint64_t address; PwImportKind kind; } PwImportTarget;
typedef int (*PwImportResolver)(void *,const char *,const PeImportSymbol *,PwImportTarget *);
typedef struct PwImportWrite { void *slot; uint32_t rva,value; PwImportKind kind; } PwImportWrite;
typedef struct PwImportBindWorkspace {
    PeImportTable table;
    PeImportSymbol symbols[PW_IMPORT_BIND_CAPACITY];
    PwImportWrite writes[PW_IMPORT_BIND_CAPACITY];
} PwImportBindWorkspace;
typedef struct PwImportBindReport { unsigned functions,data,total; } PwImportBindReport;
/* Bind a PE32 image while its mapper-owned writable region is live and before
 * final protections. All slots/targets resolve before the first IAT write.
 * Resolver must supply live guest data addresses or dispatcher-owned guest
 * function destinations, not arbitrary host pointers. Resolver side effects
 * and their rollback are caller-owned. No PE64, delay imports or forwarder
 * resolution is implied. Resolver must not mutate the image, mappings or
 * IAT. Workspace must not alias the image or report. */
int pw_import_bind32(const PeImage *image,PwMappedImage *mapped,
                     PwImportResolver resolve,void *context,
                     PwImportBindWorkspace *workspace,PwImportBindReport *report);
#endif
