/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Image sections. See pw_wine_section.h for why the loader needs them and why
 * the description outlives the file handle.
 */
#include "pw_wine_section.h"

#include "pe_image.h"
#include "pe_layout.h"
#include "pw_wine_context.h"
#include "pw_wine_handle.h"
#include "pw_wine_path.h"

#include <string.h>

enum {
    /* The shape ntdll's loader asks for: an image section over a file, mapped
     * executable, with no name and no explicit maximum size. */
    PW_WINE_SECTION_SEC_IMAGE = 0x01000000u,
    /* SECTION_ALL_ACCESS, the only access bits a section can be asked for. */
    PW_WINE_SECTION_ACCESS_MASK = 0x000f001fu,
};

static void put_le16(uint8_t *out, uint32_t offset, uint16_t value)
{
    out[offset + 0u] = (uint8_t)(value & 0xffu);
    out[offset + 1u] = (uint8_t)((value >> 8) & 0xffu);
}

static void put_le32(uint8_t *out, uint32_t offset, uint32_t value)
{
    out[offset + 0u] = (uint8_t)(value & 0xffu);
    out[offset + 1u] = (uint8_t)((value >> 8) & 0xffu);
    out[offset + 2u] = (uint8_t)((value >> 16) & 0xffu);
    out[offset + 3u] = (uint8_t)((value >> 24) & 0xffu);
}

/*
 * NtCreateSection for the one shape a loader uses: an unnamed SEC_IMAGE
 * section over an open file handle, created executable. The image is described
 * from the file's own headers here, once, and the description is what
 * NtQuerySection answers from - the loader asks immediately after creating the
 * section and before it closes the file handle.
 *
 * Every other shape is a real NTSTATUS rather than a fabricated section: a
 * named section, a data section (SEC_COMMIT/SEC_RESERVE and friends) and a
 * protection this run does not install are STATUS_NOT_SUPPORTED, an access mask
 * with bits outside SECTION_ALL_ACCESS is STATUS_ACCESS_DENIED, and a file that
 * is not a PE image is STATUS_INVALID_IMAGE_FORMAT.
 */
int pw_wine_section_create(PwWineCallContext *calls,
                           const PwUnixCallFrame *frame,
                           PwUnixCallAccess guest, void *context,
                           uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle_pointer = frame->args[0];
    const uint32_t desired_access = frame->args[1];
    const uint32_t attributes_pointer = frame->args[2];
    const uint32_t maximum_pointer = frame->args[3];
    const uint32_t protection = frame->args[4];
    const uint32_t allocation_attributes = frame->args[5];
    const uint32_t file_handle = frame->args[6];
    PwNtObject *file = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    PwWineSection *section = NULL;
    PwNtObject section_object;
    uint8_t headers[PW_WINE_SECTION_HEADER_BYTES];
    uint32_t read_bytes = 0u;
    uint64_t maximum = 0u;
    uint32_t handle = 0u;

    if (handle_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    if (attributes_pointer != 0u) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (allocation_attributes != PW_WINE_SECTION_SEC_IMAGE ||
        protection != PW_WINE_SECTION_PAGE_EXECUTE_READ) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if ((desired_access & ~PW_WINE_SECTION_ACCESS_MASK) != 0u) {
        *status = PW_NT_ACCESS_DENIED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (pw_wine_handle_lookup(calls, file_handle, &file, &kind) != PW_OK) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (kind != PW_NT_HANDLE_FILE || file->path[0] == '\0') {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (maximum_pointer != 0u) {
        if (guest(context, maximum_pointer, &maximum, 8u, 0) != PW_OK) {
            *argument_index = 4u;
            return PW_ERR_MALFORMED;
        }
        /* No explicit size, or exactly the file's: the loader's shape. */
        if (maximum != 0u && maximum != file->size) {
            *status = PW_NT_INVALID_PARAMETER;
            calls->report->section_refusals++;
            return PW_OK;
        }
    }
    if (!calls->config->files) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (calls->config->files->read(calls->config->files->context, file->token,
                                   0u, headers, sizeof(headers),
                                   &read_bytes) != PW_WINE_FILE_OK ||
        read_bytes == 0u) {
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_refusals++;
        return PW_OK;
    }
    if (calls->section_count >= PW_WINE_GATE_MAX_SECTIONS) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_refusals++;
        return PW_OK;
    }
    /*
     * The headers are described here and the section data is read on demand
     * when a view is mapped, so this is the header-only parse: the same
     * validation, without requiring the file's bytes to be in this span. It
     * parses straight into the section, which owns the bytes the parse points
     * into, and a failure leaves the entry unused.
     */
    section = &calls->sections[calls->section_count];
    memset(section, 0, sizeof(*section));
    section->file_namespace = file->file_namespace;
    memcpy(section->headers, headers, read_bytes);
    if (pe_image_parse_headers(&section->image, section->headers,
                               read_bytes) != PW_OK) {
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_refusals++;
        return PW_OK;
    }
    memcpy(section->name, file->path, strlen(file->path) + 1u);
    section->file_size = file->size;
    section->protection = protection;
    section->attributes = allocation_attributes;
    /*
     * The handle names the section, not the file: what makes the section
     * alive is its own description, which is why the entry below can outlive
     * the file handle the loader is about to close.
     */
    if (pw_wine_handle_object(section, section->image.size_of_image,
                              section->name, &section_object) != PW_OK ||
        pw_wine_handle_alloc(calls, &section_object, PW_NT_HANDLE_SECTION,
                             &handle) != PW_OK) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_refusals++;
        return PW_OK;
    }
    calls->section_count++;
    if (guest(context, handle_pointer, &handle, 4u, 1) != PW_OK) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    calls->report->section_creates++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * The win32 protections and the dispatcher's permission bits say the same
 * thing about a page, so one conversion each way keeps the two in step: the
 * host mapping gets the protection the guest asked for, and the declared
 * region gets the permissions a later NtProtectVirtualMemory has to report
 * back as the old protection.
 */
static unsigned permissions_from_protect(uint32_t protect)
{
    switch (protect & 0xffu) {
    case 0x01u: return 0u;                                      /* NOACCESS */
    case 0x02u: return PW_X86_READ;                             /* READONLY */
    case 0x04u: case 0x08u:                                     /* READWRITE, WRITECOPY */
        return PW_X86_READ | PW_X86_WRITE;
    case 0x10u: case 0x20u:                                     /* EXECUTE, EXECUTE_READ */
        return PW_X86_READ | PW_X86_EXEC;
    case 0x40u: case 0x80u:                                     /* EXECUTE_READWRITE, _WRITECOPY */
        return PW_X86_READ | PW_X86_WRITE | PW_X86_EXEC;
    default: return 0xffffffffu;
    }
}

static uint32_t protect_from_permissions(unsigned permissions)
{
    const int writable = (permissions & PW_X86_WRITE) != 0u;
    const int executable = (permissions & PW_X86_EXEC) != 0u;

    if ((permissions & (PW_X86_READ | PW_X86_WRITE | PW_X86_EXEC)) == 0u)
        return 0x01u;
    if (executable)
        return writable ? 0x40u : 0x20u;
    return writable ? 0x04u : 0x02u;
}

static unsigned host_protection_from_permissions(unsigned permissions)
{
    unsigned protection = 0u;

    if ((permissions & PW_X86_READ) != 0u)
        protection |= PW_PROT_READ;
    if ((permissions & PW_X86_WRITE) != 0u)
        protection |= PW_PROT_WRITE;
    if ((permissions & PW_X86_EXEC) != 0u)
        protection |= PW_PROT_EXEC;
    return protection;
}

/*
 * Narrows the declared regions so [low, high) carries exactly the permissions
 * the guest just asked for, with the parts before and after it keeping theirs.
 * The guest must never be able to write a page the host still maps read-only:
 * that is a host fault rather than a classified stop, so the two are narrowed
 * together and a table that cannot hold the split refuses the call.
 */
static int apply_declared_permissions(PwX86State *state, uint32_t low,
                                      uint32_t high, unsigned permissions)
{
    PwX86Memory out[PW_X86_MEMORY_REGIONS];
    uint32_t count = 0u;

    for (uint32_t index = 0u; index < state->memory_count; ++index) {
        const PwX86Memory region = state->memory[index];
        const uint64_t region_high = region.high;
        uint32_t span_low;
        uint64_t span_high;

        if (region_high <= low || region.low >= high) {
            if (count == PW_X86_MEMORY_REGIONS)
                return PW_ERR_LIMIT;
            out[count++] = region;
            continue;
        }
        if (region.low < low) {
            if (count == PW_X86_MEMORY_REGIONS)
                return PW_ERR_LIMIT;
            out[count++] = (PwX86Memory){ .low = region.low, .high = low,
                                          .permissions = region.permissions };
        }
        span_low = region.low > low ? region.low : low;
        span_high = region_high < high ? region_high : high;
        if (count == PW_X86_MEMORY_REGIONS)
            return PW_ERR_LIMIT;
        out[count++] = (PwX86Memory){ .low = span_low, .high = span_high,
                                      .permissions = permissions };
        if (region_high > high) {
            if (count == PW_X86_MEMORY_REGIONS)
                return PW_ERR_LIMIT;
            out[count++] = (PwX86Memory){ .low = high, .high = region_high,
                                          .permissions = region.permissions };
        }
    }
    memcpy(state->memory, out, count * sizeof(out[0]));
    state->memory_count = count;
    return PW_OK;
}

/*
 * The permissions the range has now, which is what a protect must report back
 * as the old protection.
 *
 * Windows answers with the protection of the range's *first page*, and this
 * run's page protection is what the guard allows on it - which is the union of
 * every declared region covering that page, not the first region that happens
 * to be listed. The two differ, and the difference is measured: a view is
 * declared as the whole image readable plus the union of its writable sections
 * writable, so its .data page is covered twice, and answering with the first
 * region reported that page as read-only. The loader protects pages while it
 * relocates an image and puts the old protection back afterwards, so it then
 * restored read-only over a page that was writable and the next store into it
 * - the TLS index slot, right after the thread list is walked - was refused by
 * the guard.
 */
static unsigned declared_permissions_at(const PwX86State *state, uint32_t low,
                                        uint32_t high)
{
    const uint64_t page_high =
        (uint64_t)low + PW_WINE_SECTION_PAGE_BYTES;
    const uint64_t first_page_high =
        page_high < (uint64_t)high ? page_high : (uint64_t)high;
    unsigned permissions = 0u;

    for (uint32_t index = 0u; index < state->memory_count; ++index) {
        const PwX86Memory region = state->memory[index];

        if ((uint64_t)region.low <= low &&
            (uint64_t)region.high >= first_page_high)
            permissions |= region.permissions;
    }
    return permissions;
}

/*
 * NtProtectVirtualMemory for the ranges this run has mapped - the NT
 * allocations and the section views it owns - which is what a loader changes
 * when it relocates the image it just mapped: it makes the pages writable,
 * writes, and puts the original protection back.
 *
 * The change is applied to the host mapping and to the dispatcher's view of it
 * together, and the declared regions are split around the range so the guard
 * never allows a write the host would fault on. A range this run did not map
 * is answered with STATUS_INVALID_PARAMETER rather than accepted and ignored,
 * and a protection this bridge cannot install (a guard or no-cache modifier)
 * is STATUS_NOT_SUPPORTED.
 */
int pw_wine_section_protect(PwWineCallContext *calls,
                            const PwUnixCallFrame *frame,
                            PwUnixCallAccess guest, void *context,
                            uint32_t *status, uint32_t *argument_index)
{
    const uint32_t process_handle = frame->args[0];
    const uint32_t base_pointer = frame->args[1];
    const uint32_t size_pointer = frame->args[2];
    const uint32_t new_protect = frame->args[3];
    const uint32_t old_pointer = frame->args[4];
    PwX86State *state = context;
    const PwVmBackend *backend = &calls->vm->base;
    uint32_t base = 0u;
    uint32_t size = 0u;
    uint32_t low = 0u;
    uint32_t high = 0u;
    uint32_t written_base = 0u;
    uint32_t written_size = 0u;
    uint32_t old_protect = 0u;
    unsigned permissions;
    unsigned previous;
    const PwVmRegion *region = NULL;
    uint64_t region_base = 0u;
    uint64_t region_high = 0u;
    int result;

    if (process_handle != 0xffffffffu) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (base_pointer == 0u || size_pointer == 0u ||
        guest(context, base_pointer, &base, 4u, 0) != PW_OK ||
        guest(context, size_pointer, &size, 4u, 0) != PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (size == 0u) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_protect_refusals++;
        return PW_OK;
    }
    permissions = permissions_from_protect(new_protect);
    if (permissions == 0xffffffffu) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_protect_refusals++;
        return PW_OK;
    }
    low = base & ~(PW_WINE_SECTION_PAGE_BYTES - 1u);
    high = (uint32_t)(((uint64_t)base + size + PW_WINE_SECTION_PAGE_BYTES - 1u) &
                      ~(uint64_t)(PW_WINE_SECTION_PAGE_BYTES - 1u));
    if (high <= low) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_protect_refusals++;
        return PW_OK;
    }
    for (uint32_t index = 0u; index < calls->region_count; ++index) {
        const uint64_t candidate = (uint64_t)(uintptr_t)
            calls->regions[index].exec_base;

        if (candidate <= low &&
            candidate + calls->regions[index].bytes >= high) {
            region = &calls->regions[index];
            region_base = candidate;
            region_high = candidate + calls->regions[index].bytes;
            break;
        }
    }
    if (region == NULL) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_protect_refusals++;
        return PW_OK;
    }
    previous = declared_permissions_at(state, low, high);
    result = apply_declared_permissions(state, low, high, permissions);
    if (result != PW_OK) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_protect_refusals++;
        return PW_OK;
    }
    if (backend->protect(backend->context, (PwVmRegion *)region,
                         (size_t)(low - region_base), (size_t)(high - low),
                         host_protection_from_permissions(permissions))
        != PW_OK) {
        (void) apply_declared_permissions(state, low, high, previous);
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_protect_refusals++;
        return PW_OK;
    }
    written_base = low;
    written_size = high - low;
    old_protect = protect_from_permissions(previous);
    if (guest(context, base_pointer, &written_base, 4u, 1) != PW_OK ||
        guest(context, size_pointer, &written_size, 4u, 1) != PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (old_pointer != 0u &&
        guest(context, old_pointer, &old_protect, 4u, 1) != PW_OK) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    (void)region_high;
    calls->report->section_protects++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * The distribution's NLS data, mapped into the guest.
 *
 * NtInitializeNlsFiles is what ntdll's own initialization asks for once
 * (RtlGetLocaleFileMappingAddress, dlls/ntdll/locale.c:605-621) and
 * NtGetNlsSectionPtr is what the locale code asks for the rest of the tables
 * (dlls/ntdll/unix/env.c:2207). Wine reads the file from the Unix side - its
 * own data directory first, the Windows system directory as a fallback - maps
 * it as a read-only SEC_COMMIT section and hands the guest the address and the
 * size; the second call also publishes the section in the \NLS object
 * directory, which is Wine's own cache and invisible to the guest either way.
 *
 * This run serves both out of the runtime namespace it owns, through the same
 * path translation and file service every other file name goes through: the
 * file's bytes are read into a fresh mapping below 4 GiB, page-rounded,
 * declared readable and nothing else, and registered with the run so cleanup
 * gives it back. A distribution that does not carry the file is answered with
 * the failure Wine's own open would produce.
 */
static int map_nls_data(PwWineCallContext *calls, PwX86State *state,
                        const char *name, uint32_t *mapping, uint64_t *bytes)
{
    const PwVmBackend *backend = &calls->vm->base;
    PwVmRegion region;
    uint64_t size = 0u;
    void *token = NULL;
    uint32_t read_bytes = 0u;
    uint32_t base = 0u;

    if (!calls->config->files || !name || name[0] == '\0' ||
        !mapping || !bytes)
        return PW_ERR_NOT_FOUND;
    if (calls->config->files->open(calls->config->files->context,
                                   PW_FILE_RUNTIME, name, &size,
                                   &token) != PW_WINE_FILE_OK)
        return PW_ERR_NOT_FOUND;
    if (size == 0u || size > PW_WINE_NLS_MAX_BYTES ||
        calls->region_count >= PW_WINE_GATE_MAX_CALL_REGIONS ||
        state->memory_count >= PW_X86_MEMORY_REGIONS ||
        backend->reserve_at == NULL || backend->commit == NULL ||
        backend->protect == NULL || backend->release == NULL) {
        calls->config->files->close(calls->config->files->context, token);
        return PW_ERR_LIMIT;
    }
    /*
     * The mapping has to land below 4 GiB, because the guest addresses it with
     * a 32-bit pointer, so it comes from the same window every other guest
     * mapping in this run uses, scanned for a free candidate.
     */
    memset(&region, 0, sizeof(region));
    {
        uint32_t candidate = PW_WINE_GATE_HEAP_BASE;
        int reserved = PW_ERR_VM;

        for (; (uint64_t)candidate + size <= PW_WINE_GATE_HEAP_LIMIT;
             candidate += (uint32_t)backend->page_bytes) {
            if (backend->reserve_at(backend->context, candidate, (size_t)size,
                                    (uint32_t)backend->page_bytes,
                                    &region) == PW_OK) {
                reserved = PW_OK;
                break;
            }
        }
        if (reserved != PW_OK) {
            calls->config->files->close(calls->config->files->context, token);
            return PW_ERR_VM;
        }
    }
    if ((uint64_t)(uintptr_t)region.exec_base + region.bytes >
            0x100000000ull ||
        backend->commit(backend->context, &region, 0u, region.bytes,
                        PW_PROT_READ | PW_PROT_WRITE) != PW_OK) {
        (void)backend->release(backend->context, &region);
        calls->config->files->close(calls->config->files->context, token);
        return PW_ERR_VM;
    }
    base = (uint32_t)(uintptr_t)region.exec_base;
    if (calls->config->files->read(calls->config->files->context, token, 0u,
                                   (void *)(uintptr_t)base, (uint32_t)size,
                                   &read_bytes) != PW_WINE_FILE_OK ||
        read_bytes != (uint32_t)size ||
        backend->protect(backend->context, &region, 0u, region.bytes,
                         PW_PROT_READ) != PW_OK) {
        (void)backend->release(backend->context, &region);
        calls->config->files->close(calls->config->files->context, token);
        return PW_ERR_TRUNCATED;
    }
    calls->config->files->close(calls->config->files->context, token);
    state->memory[state->memory_count++] = (PwX86Memory){
        .low = base,
        .high = (uint64_t)base + region.bytes,
        .permissions = PW_X86_READ,
    };
    calls->regions[calls->region_count] = region;
    calls->region_owned[calls->region_count] = 0u;
    calls->region_count++;
    calls->report->call_regions = calls->region_count;
    *mapping = base;
    *bytes = region.bytes;
    return PW_OK;
}

int pw_wine_section_init_nls_files(PwWineCallContext *calls,
                                   const PwUnixCallFrame *frame,
                                   PwUnixCallAccess guest, void *context,
                                   uint32_t *status, uint32_t *argument_index)
{
    const uint32_t pointer = frame->args[0];
    const uint32_t lcid_pointer = frame->args[1];
    const uint32_t size_pointer = frame->args[2];
    PwX86State *state = context;
    uint32_t lcid = PW_WINE_LOCALE_SYSTEM_LCID;
    uint64_t written_size = 0u;
    uint32_t mapping = 0u;
    char name[PW_NT_HANDLE_PATH_MAX + 1];
    PwFileNamespace file_namespace = PW_FILE_RUNTIME;
    int is_directory = 0;
    uint32_t refused_status = PW_NT_OBJECT_NAME_NOT_FOUND;
    int result;

    if (pointer == 0u || lcid_pointer == 0u || size_pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    /*
     * NtInitializeNlsFiles( void **ptr, LCID *lcid, LARGE_INTEGER *size ):
     * the address of the mapped locale data, the system language id, and the
     * mapping's size. Wine's own implementation writes the language id whether
     * or not the mapping worked (dlls/ntdll/unix/env.c:2247), and this run does
     * the same: the id comes from the locale settings, not from the file.
     */
    {
        uint32_t probe = 0u;
        uint64_t probe_size = 0u;

        if (guest(context, pointer, &probe, 4u, 0) != PW_OK ||
            guest(context, lcid_pointer, &probe, 4u, 0) != PW_OK ||
            guest(context, size_pointer, &probe_size, 8u, 0) != PW_OK) {
            *argument_index = 1u;
            return PW_ERR_MALFORMED;
        }
    }
    if (pw_wine_path_runtime("\\??\\C:\\windows\\system32\\locale.nls", name,
                             sizeof(name), &file_namespace, &is_directory,
                             &refused_status) != PW_OK)
        name[0] = '\0';
    if (is_directory)
        name[0] = '\0';
    result = map_nls_data(calls, state, name, &mapping, &written_size);
    if (result != PW_OK) {
        calls->report->nls_refusals++;
        *status = (result == PW_ERR_NOT_FOUND) ? PW_NT_OBJECT_NAME_NOT_FOUND
                 : (result == PW_ERR_LIMIT) ? PW_NT_NOT_SUPPORTED
                                            : PW_NT_INVALID_IMAGE_FORMAT;
        if (guest(context, lcid_pointer, &lcid, 4u, 1) != PW_OK) {
            *argument_index = 2u;
            return PW_ERR_MALFORMED;
        }
        return PW_OK;
    }
    calls->report->nls_maps++;
    if (guest(context, pointer, &mapping, 4u, 1) != PW_OK ||
        guest(context, size_pointer, &written_size, 8u, 1) != PW_OK ||
        guest(context, lcid_pointer, &lcid, 4u, 1) != PW_OK) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtGetNlsSectionPtr( ULONG type, ULONG id, void *unknown, void **ptr,
 * SIZE_T *size ): the rest of the NLS tables, named by type and id rather than
 * by path (dlls/ntdll/unix/env.c:93 get_nls_file_path, :172
 * get_nls_section_name). Wine's types are the numbers its own locale code uses
 * (dlls/ntdll/locale_private.h:52): 9 sort keys, 10 case map, 11 codepage
 * tables, 12 normalization. The codepage files are c_%03u.nls and the
 * normalization ones follow the form's own name; a file this distribution does
 * not carry is answered with the failure of its open, exactly like Wine's
 * fallback.
 */
int pw_wine_section_get_nls_section_ptr(PwWineCallContext *calls,
                                        const PwUnixCallFrame *frame,
                                        PwUnixCallAccess guest, void *context,
                                        uint32_t *status,
                                        uint32_t *argument_index)
{
    const uint32_t type = frame->args[0];
    const uint32_t id = frame->args[1];
    const uint32_t unknown = frame->args[2];
    const uint32_t pointer = frame->args[3];
    const uint32_t size_pointer = frame->args[4];
    PwX86State *state = context;
    char name[PW_NT_HANDLE_PATH_MAX + 1];
    uint32_t mapping = 0u;
    uint64_t mapping_bytes = 0u;
    const char *file = NULL;
    int result;

    if (pointer == 0u || size_pointer == 0u) {
        *argument_index = 4u;
        return PW_ERR_MALFORMED;
    }
    /* Wine passes NULL here and answers STATUS_INVALID_PARAMETER_1 for a type
     * it does not know; nothing in this run depends on the third argument. */
    (void)unknown;
    switch (type) {
    case PW_WINE_NLS_SORTKEYS:
        if (id != 0u) {
            *status = PW_NT_INVALID_PARAMETER;
            calls->report->nls_refusals++;
            return PW_OK;
        }
        file = "sortdefault.nls";
        break;
    case PW_WINE_NLS_CASEMAP:
        if (id != 0u) {
            *status = PW_NT_UNSUCCESSFUL;
            calls->report->nls_refusals++;
            return PW_OK;
        }
        file = "l_intl.nls";
        break;
    case PW_WINE_NLS_CODEPAGE:
        /*
         * Wine names these files "c_%03u.nls" with the codepage's own decimal
         * value (dlls/ntdll/unix/env.c:103) - four digits for 65001 and three
         * for 437 - so the number is written by hand rather than through
         * stdio, which the gate's own sources do not carry.
         */
        {
            char digits[12];
            unsigned value = id;
            unsigned count = 0u;
            char *out = name;

            *out++ = 'c';
            *out++ = '_';
            if (value == 0u)
                digits[count++] = '0';
            while (value != 0u && count < sizeof(digits)) {
                digits[count++] = (char)('0' + (value % 10u));
                value /= 10u;
            }
            while (count != 0u)
                *out++ = digits[--count];
            *out++ = '.';
            *out++ = 'n';
            *out++ = 'l';
            *out++ = 's';
            *out = '\0';
        }
        file = name;
        break;
    case PW_WINE_NLS_NORMALIZE:
        switch (id) {
        case PW_WINE_NORMALIZATION_C: file = "normnfc.nls"; break;
        case PW_WINE_NORMALIZATION_D: file = "normnfd.nls"; break;
        case PW_WINE_NORMALIZATION_KC: file = "normnfkc.nls"; break;
        case PW_WINE_NORMALIZATION_KD: file = "normnfkd.nls"; break;
        case PW_WINE_NORMALIZATION_IDNA: file = "normidna.nls"; break;
        default:
            *status = PW_NT_OBJECT_NAME_NOT_FOUND;
            calls->report->nls_refusals++;
            return PW_OK;
        }
        break;
    default:
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->nls_refusals++;
        return PW_OK;
    }
    result = map_nls_data(calls, state, file, &mapping, &mapping_bytes);
    if (result != PW_OK) {
        calls->report->nls_refusals++;
        *status = (result == PW_ERR_NOT_FOUND) ? PW_NT_OBJECT_NAME_NOT_FOUND
                                                : PW_NT_NOT_SUPPORTED;
        return PW_OK;
    }
    calls->report->nls_maps++;
    if (guest(context, pointer, &mapping, 4u, 1) != PW_OK ||
        guest(context, size_pointer, &mapping_bytes, 4u, 1) != PW_OK) {
        *argument_index = 4u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtQuerySection. SectionImageInformation is the class the loader asks for and
 * the one is_valid_binary reads: TransferAddress is the image's own base plus
 * its entry point, exactly as wine fills it for a section that is not mapped
 * yet (dlls/ntdll/unix/virtual.c:6596-6619), and Machine is what decides
 * whether the image is one this process can run. SectionBasicInformation is
 * answered too, with a null BaseAddress because nothing is mapped yet.
 */
int pw_wine_section_query(PwWineCallContext *calls,
                          const PwUnixCallFrame *frame,
                          PwUnixCallAccess guest, void *context,
                          uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t information_class = frame->args[1];
    const uint32_t information_pointer = frame->args[2];
    const uint32_t length = frame->args[3];
    const uint32_t result_pointer = frame->args[4];
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    PwWineSection *section = NULL;
    uint8_t block[PW_WINE_SECTION_IMAGE_BYTES];
    uint32_t needed = 0u;
    uint32_t transfer = 0u;
    const uint32_t base_address = 0u;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK ||
        kind != PW_NT_HANDLE_SECTION || object->token == NULL) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    section = object->token;
    if (information_class == PW_WINE_SECTION_IMAGE_INFORMATION) {
        needed = PW_WINE_SECTION_IMAGE_BYTES;
    } else if (information_class == PW_WINE_SECTION_BASIC_INFORMATION) {
        needed = PW_WINE_SECTION_BASIC_BYTES;
    } else {
        *status = PW_NT_INVALID_INFO_CLASS;
        calls->report->section_refusals++;
        return PW_OK;
    }
    calls->report->section_queries++;
    if (result_pointer != 0u &&
        guest(context, result_pointer, &needed, 4u, 1) != PW_OK) {
        *argument_index = 5u;
        return PW_ERR_MALFORMED;
    }
    if (information_pointer == 0u || length < needed) {
        *status = PW_NT_INFO_LENGTH_MISMATCH;
        calls->report->section_refusals++;
        return PW_OK;
    }
    memset(block, 0, sizeof(block));
    if (information_class == PW_WINE_SECTION_BASIC_INFORMATION) {
        put_le32(block, 0u, section->attributes);       /* Attributes */
        put_le32(block, 4u, base_address);              /* BaseAddress */
        put_le32(block, 8u, section->image.size_of_image);  /* Size */
    } else {
        const PeImage *image = &section->image;
        uint8_t contains_code = 0u;

        for (uint32_t index = 0u; index < image->section_count; ++index)
            if ((image->sections[index].characteristics & PE_SCN_MEM_EXECUTE)
                != 0u)
                contains_code = 1u;
        transfer = (uint32_t)image->image_base + image->entry_point;
        put_le32(block, 0u, transfer);                  /* TransferAddress */
        put_le32(block, 8u, image->stack_reserve);      /* MaximumStackSize */
        put_le32(block, 12u, image->stack_commit);     /* CommittedStackSize */
        put_le32(block, 16u, image->subsystem);         /* SubSystemType */
        put_le16(block, 20u, image->subsystem_version_minor);
        put_le16(block, 22u, image->subsystem_version_major);
        put_le16(block, 24u, image->os_version_major);
        put_le16(block, 26u, image->os_version_minor);
        put_le16(block, 28u, image->characteristics);
        put_le16(block, 30u, image->dll_characteristics);
        put_le16(block, 32u, image->machine);
        block[34] = contains_code;
        block[35] = PW_WINE_IMAGE_FLAG_DYNAMICALLY_RELOCATED |
                    PW_WINE_IMAGE_FLAG_BASE_BELOW_4GB;
        put_le32(block, 40u, (uint32_t)section->file_size);
        put_le32(block, 44u, image->checksum);
    }
    if (guest(context, information_pointer, block, needed, 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtMapViewOfSection for the one shape a loader asks for: the section mapped
 * into this process, executable, with no offset into the section and no
 * explicit view size.
 *
 * The image is placed the way a mapper places one - the file's headers where
 * the image begins and each section's raw bytes at its own virtual address,
 * with the alignment gaps left zero and the load-time protections taken from
 * the section table - and nothing is relocated: a SEC_IMAGE view is the image
 * as the file holds it, and relocating it is the loader's own later work
 * through NtProtectVirtualMemory, which is also how it asks for pages it wants
 * to write.
 *
 * The base is the image's preferred one when this run can place it there,
 * because that is what a real process gets and what spares the loader the
 * relocation; otherwise the view goes where the run's own allocator has room
 * and the loader relocates it. Either way the guest is told the base it
 * actually got, and the whole view joins the run's regions so an unmap or a
 * cleanup gives back exactly what was mapped.
 */
/* Appends [low, high) with these permissions to a view's permission map,
 * joining it to the range before it when the two touch and agree, so adjacent
 * pages with the same permissions cost one declared region. The new count
 * comes back, or zero when the map is full - a page whose permissions this run
 * cannot state is a view it refuses rather than one it declares loosely. */
static uint32_t append_permission(PwX86Memory *map, uint32_t count,
                                  uint32_t capacity, uint64_t low,
                                  uint64_t high, unsigned permissions)
{
    if (low >= high)
        return count;
    if (count != 0u && map[count - 1u].high == low &&
        map[count - 1u].permissions == permissions) {
        map[count - 1u].high = high;
        return count;
    }
    if (count >= capacity)
        return 0u;
    map[count].low = low;
    map[count].high = high;
    map[count].permissions = permissions;
    return count + 1u;
}

int pw_wine_section_map_view(PwWineCallContext *calls,
                             const PwUnixCallFrame *frame,
                             PwUnixCallAccess guest, void *context,
                             uint32_t *status, uint32_t *argument_index)
{
    const uint32_t handle = frame->args[0];
    const uint32_t process_handle = frame->args[1];
    const uint32_t base_pointer = frame->args[2];
    const uint32_t zero_bits = frame->args[3];
    const uint32_t commit_size = frame->args[4];
    const uint32_t offset_pointer = frame->args[5];
    const uint32_t size_pointer = frame->args[6];
    const uint32_t inherit_disposition = frame->args[7];
    const uint32_t allocation_type = frame->args[8];
    const uint32_t page_protection = frame->args[9];
    PwX86State *state = context;
    const PwVmBackend *backend = &calls->vm->base;
    PwNtObject *object = NULL;
    unsigned kind = PW_NT_HANDLE_NONE;
    PwWineSection *section = NULL;
    const PeImage *image;
    PwVmRegion region;
    uint32_t base = 0u;
    uint32_t hint = 0u;
    uint32_t view_size = 0u;
    uint32_t bytes = 0u;
    void *span_handle = NULL;
    uint64_t span_size = 0u;
    uint32_t read_bytes = 0u;
    uint32_t header_bytes = 0u;
    int result;

    if (pw_wine_handle_lookup(calls, handle, &object, &kind) != PW_OK ||
        kind != PW_NT_HANDLE_SECTION || object->token == NULL) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    section = object->token;
    image = &section->image;
    if (process_handle != 0xffffffffu) {
        *status = PW_NT_INVALID_HANDLE;
        return PW_OK;
    }
    if (base_pointer == 0u ||
        guest(context, base_pointer, &hint, 4u, 0) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (size_pointer != 0u) {
        if (guest(context, size_pointer, &view_size, 4u, 0) != PW_OK) {
            *argument_index = 7u;
            return PW_ERR_MALFORMED;
        }
        if (view_size != 0u && view_size < image->size_of_image) {
            *status = PW_NT_INVALID_PARAMETER;
            calls->report->section_view_refusals++;
            return PW_OK;
        }
    }
    /* The one shape: no zero bits, no commit size, no offset into the section,
     * no allocation type, and the protection a loader asks for. */
    if (zero_bits != 0u || commit_size != 0u || offset_pointer != 0u ||
        allocation_type != 0u ||
        page_protection != PW_WINE_SECTION_PAGE_EXECUTE_READ) {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    if (inherit_disposition != PW_WINE_SECTION_VIEW_SHARE &&
        inherit_disposition != PW_WINE_SECTION_VIEW_UNMAP) {
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    if (image->size_of_image == 0u ||
        (image->size_of_image & (PW_WINE_SECTION_PAGE_BYTES - 1u)) != 0u) {
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    /*
     * Every section must fit inside the image, and the bytes it claims must
     * exist in the file: the header-only parse could not check the second one,
     * because it never held the file, and this is where they are read.
     */
    for (uint32_t index = 0u; index < image->section_count; ++index) {
        const PeSection *entry = &image->sections[index];
        const uint64_t span = entry->virtual_size > entry->raw_size
            ? entry->virtual_size : entry->raw_size;

        if ((uint64_t)entry->virtual_address + span > image->size_of_image ||
            (entry->raw_size != 0u &&
             (uint64_t)entry->raw_offset + entry->raw_size >
                 section->file_size)) {
            *status = PW_NT_INVALID_IMAGE_FORMAT;
            calls->report->section_view_refusals++;
            return PW_OK;
        }
    }
    if (calls->region_count >= PW_WINE_GATE_MAX_CALL_REGIONS ||
        !calls->config->files || section->name[0] == '\0') {
        *status = PW_NT_NOT_SUPPORTED;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    bytes = image->size_of_image;
    memset(&region, 0, sizeof(region));
    /*
     * The preferred base first: an image placed where it wants to be needs no
     * relocation. When this run cannot place it there the view goes where the
     * allocator has room, and the loader relocates it.
     */
    result = backend->reserve_at(backend->context,
                                 hint != 0u ? hint : (uint32_t)image->image_base,
                                 bytes, (uint32_t)backend->page_bytes, &region);
    if (result != PW_OK) {
        uint32_t candidate = PW_WINE_GATE_HEAP_BASE;

        result = PW_ERR_VM;
        for (; (uint64_t)candidate + bytes <= PW_WINE_GATE_HEAP_LIMIT;
             candidate += (uint32_t)backend->page_bytes) {
            if (backend->reserve_at(backend->context, candidate, bytes,
                                    (uint32_t)backend->page_bytes,
                                    &region) == PW_OK) {
                result = PW_OK;
                break;
            }
        }
    }
    if (result != PW_OK) {
        *status = PW_NT_CONFLICTING_ADDRESSES;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    result = backend->commit(backend->context, &region, 0u, region.bytes,
                             PW_PROT_READ | PW_PROT_WRITE | PW_PROT_EXEC);
    if (result != PW_OK) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_INVALID_PARAMETER;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    base = (uint32_t)(uintptr_t)region.exec_base;
    header_bytes = image->size_of_headers < section->file_size
        ? image->size_of_headers : (uint32_t)section->file_size;
    /*
     * The bytes, straight from the service into the mapping the guest will
     * use: the headers where the image begins, then each section at its own
     * virtual address. A short read is a file that does not hold the image its
     * headers describe, and the whole view goes back.
     */
    if (calls->config->files->open(calls->config->files->context,
                                   section->file_namespace, section->name,
                                   &span_size,
                                   &span_handle) != PW_WINE_FILE_OK) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_OBJECT_NAME_NOT_FOUND;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    result = PW_OK;
    if (span_size < section->file_size ||
        calls->config->files->read(calls->config->files->context, span_handle,
                                   0u, (void *)(uintptr_t)base, header_bytes,
                                   &read_bytes) != PW_WINE_FILE_OK ||
        read_bytes != header_bytes)
        result = PW_ERR_NOT_FOUND;
    for (uint32_t index = 0u;
         result == PW_OK && index < image->section_count; ++index) {
        const PeSection *entry = &image->sections[index];

        if (entry->raw_size == 0u)
            continue;
        if (calls->config->files->read(
                calls->config->files->context, span_handle, entry->raw_offset,
                (void *)(uintptr_t)(base + entry->virtual_address),
                entry->raw_size, &read_bytes) != PW_WINE_FILE_OK ||
            read_bytes != entry->raw_size)
            result = PW_ERR_NOT_FOUND;
    }
    calls->config->files->close(calls->config->files->context, span_handle);
    if (result != PW_OK) {
        (void)backend->release(backend->context, &region);
        *status = PW_NT_INVALID_IMAGE_FORMAT;
        calls->report->section_view_refusals++;
        return PW_OK;
    }
    /*
     * One permission map for both sides of the boundary, at the granularity
     * the two of them share: whole pages.
     *
     * Each page of the view gets what the image's own section table says about
     * it - readable always, plus writable and/or executable when a section
     * overlapping that page says so, which is the union rule the guard itself
     * applies when two sections share a page. The map is then applied to the
     * host mapping through the backend and declared to the dispatcher range
     * for range, unchanged, so the two cannot disagree about what a page
     * allows.
     *
     * Pages and not sections, because a section boundary is where the linker
     * put it and not a page boundary, while the host's protection moves in
     * whole pages: a section-granular map asks the backend to protect at an
     * offset it cannot, which is a refusal this test measures (the fixture's
     * text section ends at 0x1600). And a coarse union instead - one interval
     * spanning every writable section - declares a page writable whenever a
     * writable section lies above it, so the guard allows a store the host
     * mapping refuses: a host fault rather than a classified stop.
     */
    {
        PwX86Memory map[PW_X86_MEMORY_REGIONS];
        uint32_t entries = 0u;
        const uint64_t view_high = (uint64_t)base + bytes;
        const uint64_t page = backend->page_bytes != 0u
            ? backend->page_bytes : PW_WINE_SECTION_PAGE_BYTES;

        for (uint64_t low = base; low < view_high; low += page) {
            const uint64_t high =
                low + page < view_high ? low + page : view_high;
            unsigned permissions = PW_X86_READ;

            for (uint32_t index = 0u; index < image->section_count; ++index) {
                const PeSection *entry = &image->sections[index];
                const uint64_t span = entry->virtual_size > entry->raw_size
                    ? entry->virtual_size : entry->raw_size;
                const uint64_t section_low =
                    (uint64_t)base + entry->virtual_address;
                const uint64_t section_high = section_low + span;

                if (span == 0u || section_high <= low || section_low >= high)
                    continue;
                if ((entry->characteristics & PE_SCN_MEM_EXECUTE) != 0u)
                    permissions |= PW_X86_EXEC;
                if ((entry->characteristics & PE_SCN_MEM_WRITE) != 0u)
                    permissions |= PW_X86_WRITE;
            }
            entries = append_permission(map, entries, PW_X86_MEMORY_REGIONS,
                                        low, high, permissions);
            if (entries == 0u)
                break;
        }
        if (entries == 0u ||
            state->memory_count + entries > PW_X86_MEMORY_REGIONS) {
            (void)backend->release(backend->context, &region);
            *status = PW_NT_INVALID_PARAMETER;
            calls->report->section_view_refusals++;
            return PW_OK;
        }
        for (uint32_t index = 0u; index < entries; ++index) {
            const PwX86Memory *range = &map[index];
            const unsigned protection =
                host_protection_from_permissions(range->permissions);

            if (protection == 0u ||
                backend->protect(backend->context, &region,
                                 (size_t)(range->low - base),
                                 (size_t)(range->high - range->low),
                                 protection) != PW_OK) {
                (void)backend->release(backend->context, &region);
                *status = PW_NT_INVALID_PARAMETER;
                calls->report->section_view_refusals++;
                return PW_OK;
            }
            state->memory[state->memory_count++] = *range;
        }
    }
    calls->regions[calls->region_count] = region;
    calls->region_owned[calls->region_count] = 0u;
    calls->region_count++;
    calls->report->call_regions = calls->region_count;
    calls->report->section_views++;
    /*
     * The view is the section's own record of where its file now lives in the
     * guest, because the loader asks that question next: find_existing_module
     * compares the base of a module it already has with the image it just
     * mapped, address against address, and takes "the same file" as the
     * answer (dlls/ntdll/loader.c:2798, NtAreMappedFilesTheSame).
     */
    section->view_base = base;
    section->view_bytes = bytes;
    if (guest(context, base_pointer, &base, 4u, 1) != PW_OK) {
        *argument_index = 3u;
        return PW_ERR_MALFORMED;
    }
    if (size_pointer != 0u &&
        guest(context, size_pointer, &bytes, 4u, 1) != PW_OK) {
        *argument_index = 7u;
        return PW_ERR_MALFORMED;
    }
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

/*
 * NtQueryDefaultUILanguage and NtQueryDefaultLocale: the two questions a
 * process asks about the locale it is running in, and the run's answer is the
 * one locale it models. Wine answers the first from its user interface locale
 * and the second from the user's or the system's (dlls/ntdll/unix/env.c:2280
 * NtQueryDefaultLocale), both of which come from the prefix's registry; this
 * prefix has no user locale of its own, so both are the language the NLS
 * mapping and every other locale answer already use.
 */
/*
 * The language-id half of the locale questions, which have the same shape:
 * one output pointer, and the language this run models written through it.
 */
static int query_language(PwWineCallContext *calls,
                          const PwUnixCallFrame *frame, PwUnixCallAccess guest,
                          void *context, uint32_t *status,
                          uint32_t *argument_index)
{
    const uint32_t pointer = frame->args[0];
    uint32_t langid = PW_WINE_LOCALE_SYSTEM_LCID;

    if (pointer == 0u) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    if (guest(context, pointer, &langid, PW_WINE_LOCALE_LANGID_BYTES, 1) !=
        PW_OK) {
        *argument_index = 1u;
        return PW_ERR_MALFORMED;
    }
    calls->report->locale_queries++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}

int pw_wine_section_query_default_ui_language(PwWineCallContext *calls,
                                              const PwUnixCallFrame *frame,
                                              PwUnixCallAccess guest,
                                              void *context, uint32_t *status,
                                              uint32_t *argument_index)
{
    return query_language(calls, frame, guest, context, status,
                          argument_index);
}

int pw_wine_section_query_install_ui_language(PwWineCallContext *calls,
                                              const PwUnixCallFrame *frame,
                                              PwUnixCallAccess guest,
                                              void *context, uint32_t *status,
                                              uint32_t *argument_index)
{
    return query_language(calls, frame, guest, context, status,
                          argument_index);
}

int pw_wine_section_query_default_locale(PwWineCallContext *calls,
                                         const PwUnixCallFrame *frame,
                                         PwUnixCallAccess guest, void *context,
                                         uint32_t *status,
                                         uint32_t *argument_index)
{
    const uint32_t user = frame->args[0];
    const uint32_t pointer = frame->args[1];
    uint32_t lcid = user ? PW_WINE_LOCALE_USER_LCID
                         : PW_WINE_LOCALE_SYSTEM_LCID;

    /* Wine takes the boolean as a boolean: any non-zero value is the user's
     * locale, which is how the guest's own TRUE travels. */
    if (pointer == 0u) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    if (guest(context, pointer, &lcid, PW_WINE_LOCALE_LCID_BYTES, 1) != PW_OK) {
        *argument_index = 2u;
        return PW_ERR_MALFORMED;
    }
    calls->report->locale_queries++;
    *status = PW_NT_SUCCESS;
    return PW_OK;
}
