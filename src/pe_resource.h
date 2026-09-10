/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_PE_RESOURCE_H
#define PW_PE_RESOURCE_H
#include "pe_image.h"
typedef struct PeResource {
    const uint8_t *bytes;
    uint32_t size,codepage,language;
} PeResource;
/* Numeric type/name lookup in a parsed, immutable file image. Language policy:
 * exact, neutral (0), then lowest numeric language. No OS locale/MUI search.
 * Borrowed output remains valid only while image bytes remain live. On error
 * output is unchanged. Named keys and nonstandard tree depths are unsupported. */
int pe_resource_find(const PeImage *,uint32_t type,uint32_t name,
                     uint16_t language,PeResource *);
/* ASCII named-resource lookup. The PE key is compared exactly against its
 * counted UTF-16 directory name; non-ASCII keys are outside this contract. */
int pe_resource_find_name(const PeImage *,uint32_t type,const char *name,
                          uint16_t language,PeResource *);
/* RT_STRING: 16 counted UTF-16LE strings, no terminating NUL required.
 * Validate the whole block; return the selected borrowed byte span. */
int pe_resource_string(const PeImage *,uint32_t id,uint16_t language,
                       const uint8_t **utf16,size_t *units);
#endif
