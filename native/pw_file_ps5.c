/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_file_ps5.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

extern int sceKernelOpen(const char *path, int flags, int mode);
extern int sceKernelClose(int descriptor);
extern int sceKernelStat(const char *path, struct stat *status);

static size_t page_round(size_t bytes)
{
    const long page = sysconf(_SC_PAGESIZE);
    const size_t granularity = page > 0 ? (size_t)page : 4096u;

    if (bytes > (size_t)-1 - granularity)
        return 0u;
    return (bytes + granularity - 1u) & ~(granularity - 1u);
}

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

int pw_file_ps5_init(PwFilePs5 *state, const char *directory)
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

static int remember(PwFilePs5 *state, void *base, size_t bytes)
{
    for (uint32_t index = 0; index < PW_FILE_PS5_MAX_OPEN; ++index) {
        if (state->mappings[index].base == NULL) {
            state->mappings[index].base = base;
            state->mappings[index].bytes = bytes;
            return PW_OK;
        }
    }
    return PW_ERR_LIMIT;
}

static size_t forget(PwFilePs5 *state, void *base)
{
    for (uint32_t index = 0; index < PW_FILE_PS5_MAX_OPEN; ++index) {
        if (state->mappings[index].base == base) {
            const size_t bytes = state->mappings[index].bytes;

            state->mappings[index].base = NULL;
            state->mappings[index].bytes = 0u;
            return bytes;
        }
    }
    return 0u;
}

/* Reads a whole staged file into a private anonymous mapping. */
static int read_file(PwFilePs5 *state, const char *path, PwFileSpan *out)
{
    struct stat status;
    int descriptor;
    size_t bytes;
    size_t mapped_bytes;
    uint8_t *buffer;
    size_t done = 0u;

    memset(out, 0, sizeof(*out));
    if (sceKernelStat(path, &status) != 0)
        return PW_ERR_NOT_FOUND;
    if (status.st_size <= 0)
        return PW_ERR_TRUNCATED;
    if ((unsigned long long)status.st_size > PW_FILE_PS5_MAX_BYTES)
        return PW_ERR_LIMIT;
    bytes = (size_t)status.st_size;
    mapped_bytes = page_round(bytes);
    if (mapped_bytes == 0u)
        return PW_ERR_OVERFLOW;

    descriptor = sceKernelOpen(path, O_RDONLY, 0);
    if (descriptor < 0)
        return PW_ERR_NOT_FOUND;
    buffer = mmap(NULL, mapped_bytes, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED) {
        (void)sceKernelClose(descriptor);
        return PW_ERR_VM;
    }
    while (done < bytes) {
        const ssize_t chunk = read(descriptor, buffer + done, bytes - done);

        if (chunk > 0) {
            done += (size_t)chunk;
            continue;
        }
        if (chunk < 0 && errno == EINTR)
            continue;
        break;
    }
    (void)sceKernelClose(descriptor);
    if (done != bytes) {
        (void)munmap(buffer, mapped_bytes);
        return PW_ERR_TRUNCATED;
    }
    if (remember(state, buffer, mapped_bytes) != PW_OK) {
        (void)munmap(buffer, mapped_bytes);
        return PW_ERR_LIMIT;
    }

    out->bytes = buffer;
    out->size = bytes;
    out->handle = buffer;
    if (strlen(path) <= PW_PATH_MAX)
        memcpy(out->path, path, strlen(path) + 1u);
    ++state->opens;
    state->bytes_read += bytes;
    return PW_OK;
}

static int provider_open(void *context, const char *canonical_name,
                         PwFileSpan *out)
{
    PwFilePs5 *state = context;
    char path[2u * (PW_PATH_MAX + 1u)];
    int status;

    if (!state || !canonical_name || !out)
        return PW_ERR_PRECONDITION;
    status = join(path, sizeof(path), state->directory, canonical_name);
    if (status != PW_OK)
        return status;
    status = read_file(state, path, out);
    if (status != PW_OK)
        ++state->failures;
    return status;
}

static void provider_close(void *context, PwFileSpan *span)
{
    PwFilePs5 *state = context;
    size_t bytes;

    if (!state || !span || !span->handle)
        return;
    bytes = forget(state, span->handle);
    if (bytes != 0u)
        (void)munmap(span->handle, bytes);
    span->handle = NULL;
    span->bytes = NULL;
    span->size = 0u;
    ++state->closes;
}

int pw_file_ps5_provider(PwFilePs5 *state, PwFileProvider *provider)
{
    if (!state || !provider)
        return PW_ERR_PRECONDITION;
    provider->context = state;
    provider->open = provider_open;
    provider->close = provider_close;
    return PW_OK;
}

int pw_file_ps5_smoke(PwFilePs5 *state, const char *name,
                      PwFilePs5Smoke *out)
{
    char path[2u * (PW_PATH_MAX + 1u)];
    struct stat status;
    unsigned char header[2] = {0, 0};
    unsigned char again[2] = {0, 0};
    int descriptor;
    int result;

    if (!state || !name || !out)
        return PW_ERR_PRECONDITION;
    memset(out, 0, sizeof(*out));
    out->open_result = -1;
    out->stat_result = -1;
    out->read_result = -1;
    out->seek_result = -1;
    out->close_result = -1;

    result = join(path, sizeof(path), state->directory, name);
    if (result != PW_OK)
        return result;

    out->stat_result = sceKernelStat(path, &status) == 0 ? 0 : errno;
    if (out->stat_result == 0)
        out->size = (long long)status.st_size;

    descriptor = sceKernelOpen(path, O_RDONLY, 0);
    out->open_result = descriptor >= 0 ? 0 : errno;
    if (descriptor < 0)
        return PW_ERR_NOT_FOUND;

    /* read() on a sceKernelOpen descriptor: measured, not assumed. */
    out->read_result = read(descriptor, header, sizeof(header)) ==
                       (ssize_t)sizeof(header) ? 0 : errno;
    /* lseek() must address the same descriptor namespace. */
    if (lseek(descriptor, 0, SEEK_SET) == 0 &&
        read(descriptor, again, sizeof(again)) == (ssize_t)sizeof(again) &&
        again[0] == header[0] && again[1] == header[1])
        out->seek_result = 0;
    else
        out->seek_result = errno != 0 ? errno : -1;
    out->close_result = sceKernelClose(descriptor) == 0 ? 0 : errno;

    out->first_bytes[0] = header[0];
    out->first_bytes[1] = header[1];
    out->is_pe = header[0] == 'M' && header[1] == 'Z';
    if (out->stat_result != 0 || out->read_result != 0 ||
        out->seek_result != 0 || out->close_result != 0)
        return PW_ERR_VM;
    return out->is_pe ? PW_OK : PW_ERR_NOT_PE;
}
