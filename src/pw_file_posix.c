#include "pw_file_posix.h"

#include "pw_module_name.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    PW_FILE_MAX_BYTES = 256u * 1024u * 1024u,
};

static int join(char *out, size_t out_bytes, const char *directory,
                const char *name)
{
    const size_t directory_length = strlen(directory);
    const size_t name_length = strlen(name);

    if (directory_length + 1u + name_length + 1u > out_bytes)
        return PW_ERR_LIMIT;
    memcpy(out, directory, directory_length);
    out[directory_length] = '/';
    memcpy(out + directory_length + 1u, name, name_length);
    out[directory_length + 1u + name_length] = '\0';
    return PW_OK;
}

int pw_file_posix_init(PwFilePosix *state, const char *directory)
{
    size_t length;

    if (!state || !directory)
        return PW_ERR_PRECONDITION;
    memset(state, 0, sizeof(*state));
    length = strlen(directory);
    if (length == 0u || length > PW_PATH_MAX)
        return PW_ERR_LIMIT;
    memcpy(state->directory, directory, length);
    state->directory[length] = '\0';
    return PW_OK;
}

int pw_file_posix_read(PwFilePosix *state, const char *path, PwFileSpan *out)
{
    FILE *handle;
    long size;
    void *bytes;
    size_t read_bytes;

    if (!state || !path || !out)
        return PW_ERR_PRECONDITION;
    memset(out, 0, sizeof(*out));
    handle = fopen(path, "rb");
    if (!handle)
        return PW_ERR_NOT_FOUND;
    if (fseek(handle, 0, SEEK_END) != 0) {
        (void)fclose(handle);
        return PW_ERR_VM;
    }
    size = ftell(handle);
    if (size <= 0 || (unsigned long)size > PW_FILE_MAX_BYTES) {
        (void)fclose(handle);
        return size <= 0 ? PW_ERR_TRUNCATED : PW_ERR_LIMIT;
    }
    if (fseek(handle, 0, SEEK_SET) != 0) {
        (void)fclose(handle);
        return PW_ERR_VM;
    }
    bytes = malloc((size_t)size);
    if (!bytes) {
        (void)fclose(handle);
        return PW_ERR_VM;
    }
    read_bytes = fread(bytes, 1u, (size_t)size, handle);
    (void)fclose(handle);
    if (read_bytes != (size_t)size) {
        free(bytes);
        return PW_ERR_TRUNCATED;
    }
    out->bytes = bytes;
    out->size = read_bytes;
    out->handle = bytes;
    if (strlen(path) <= PW_PATH_MAX)
        memcpy(out->path, path, strlen(path) + 1u);
    ++state->opens;
    state->bytes_read += read_bytes;
    return PW_OK;
}

/* Case-insensitive directory scan, used only when the exact open fails. */
static int resolve_case_insensitive(const char *directory, const char *name,
                                    char *out, size_t out_bytes)
{
    DIR *handle = opendir(directory);
    struct dirent *entry;
    int status = PW_ERR_NOT_FOUND;

    if (!handle)
        return PW_ERR_NOT_FOUND;
    while ((entry = readdir(handle)) != NULL) {
        if (!pw_module_name_equal(entry->d_name, name))
            continue;
        status = join(out, out_bytes, directory, entry->d_name);
        break;
    }
    (void)closedir(handle);
    return status;
}

static int provider_open(void *context, const char *canonical_name,
                         PwFileSpan *out)
{
    PwFilePosix *state = context;
    char path[2u * (PW_PATH_MAX + 1u)];
    int status;

    if (!state || !canonical_name || !out)
        return PW_ERR_PRECONDITION;
    status = join(path, sizeof(path), state->directory, canonical_name);
    if (status != PW_OK)
        return status;
    status = pw_file_posix_read(state, path, out);
    if (status != PW_ERR_NOT_FOUND)
        return status;
    status = resolve_case_insensitive(state->directory, canonical_name, path,
                                       sizeof(path));
    if (status != PW_OK)
        return PW_ERR_NOT_FOUND;
    return pw_file_posix_read(state, path, out);
}

static void provider_close(void *context, PwFileSpan *span)
{
    PwFilePosix *state = context;

    if (!span)
        return;
    free(span->handle);
    span->handle = NULL;
    span->bytes = NULL;
    span->size = 0u;
    if (state)
        ++state->closes;
}

int pw_file_posix_provider(PwFilePosix *state, PwFileProvider *provider)
{
    if (!state || !provider)
        return PW_ERR_PRECONDITION;
    provider->context = state;
    provider->open = provider_open;
    provider->close = provider_close;
    return PW_OK;
}
