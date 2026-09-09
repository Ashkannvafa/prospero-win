/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef PW_REGISTRY_H
#define PW_REGISTRY_H
#include "../include/prospero_win.h"

enum {
    PW_HKEY_CURRENT_USER = 0x80000001u,
    PW_REG_CREATED_NEW_KEY = 1,
    PW_REG_OPENED_EXISTING_KEY = 2,
    PW_REG_NONE = 0,
    PW_REG_SZ = 1,
    PW_REG_BINARY = 3,
    PW_REG_DWORD = 4,
    PW_REG_ERROR_SUCCESS = 0,
    PW_REG_ERROR_FILE_NOT_FOUND = 2,
    PW_REG_ERROR_ACCESS_DENIED = 5,
    PW_REG_ERROR_INVALID_HANDLE = 6,
    PW_REG_ERROR_INVALID_PARAMETER = 87,
    PW_REG_ERROR_MORE_DATA = 234,
    PW_REG_PATH_MAX = 255,
    PW_REG_NAME_MAX = 63,
    PW_REG_DATA_MAX = 512,
};

typedef struct PwRegistryKey {
    char path[PW_REG_PATH_MAX + 1];
    uint32_t handle;
    uint32_t open_count;
    unsigned used;
} PwRegistryKey;

typedef struct PwRegistryValue {
    char name[PW_REG_NAME_MAX + 1];
    uint8_t data[PW_REG_DATA_MAX];
    uint32_t size,type,key_index;
    unsigned used;
} PwRegistryValue;

typedef struct PwRegistry {
    PwRegistryKey *keys;
    PwRegistryValue *values;
    uint32_t key_capacity,value_capacity;
} PwRegistry;

int pw_registry_init(PwRegistry *,PwRegistryKey *,uint32_t,
                     PwRegistryValue *,uint32_t);
uint32_t pw_registry_create(PwRegistry *,uint32_t,const char *,
                            uint32_t *,uint32_t *);
uint32_t pw_registry_open(PwRegistry *,uint32_t,const char *,uint32_t *);
uint32_t pw_registry_close(PwRegistry *,uint32_t);
uint32_t pw_registry_set(PwRegistry *,uint32_t,const char *,uint32_t,
                         const void *,uint32_t);
uint32_t pw_registry_query(const PwRegistry *,uint32_t,const char *,
                           uint32_t *,void *,uint32_t *);
#endif
