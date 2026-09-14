/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pw_guest_process.h"

#include <string.h>

/* Writes one UTF-16LE string into the page and returns its offset. */
static uint32_t write_wide(uint8_t *page, uint32_t *cursor, const char *ascii)
{
    const uint32_t offset = *cursor;

    while (*ascii != '\0') {
        page[*cursor] = (uint8_t)*ascii++;
        page[*cursor + 1u] = 0u;
        *cursor += 2u;
    }
    page[*cursor] = 0u;
    page[*cursor + 1u] = 0u;
    *cursor += 2u;
    return offset;
}

static void set_unicode_string(uint8_t *page, uint32_t field, uint32_t offset,
                               const char *text)
{
    const uint32_t base = (uint32_t)(uintptr_t)page;
    const uint16_t bytes = (uint16_t)(strlen(text) * 2u);
    const uint32_t buffer = base + offset;

    memcpy(page + field, &bytes, 2u);
    memcpy(page + field + 2u, &bytes, 2u);
    memcpy(page + field + 4u, &buffer, 4u);
}

/*
 * A minimal but populated RTL_USER_PROCESS_PARAMETERS: sizes, the current
 * directory, the DLL and image paths, the command line and an environment
 * block, all as UTF-16LE strings inside the same page. ntdll reads these
 * during loader and heap initialisation, and a zeroed page is what makes it
 * dereference a null Buffer.
 */
static int populate_parameters(uint8_t *page, uint32_t page_bytes,
                               const char *root_module, uint32_t *length_out)
{
    static const char system32[] = "C:\\windows\\system32\\";
    uint32_t cursor = 0x100u;
    char image_path[128];
    uint32_t current_offset;
    uint32_t dll_offset;
    uint32_t image_offset;
    uint32_t command_offset;
    uint32_t environment_offset;

    if (!page || page_bytes < 4096u || !root_module)
        return PW_ERR_PRECONDITION;
    if (strlen(root_module) + sizeof(system32) > sizeof(image_path))
        return PW_ERR_LIMIT;
    memcpy(image_path, system32, sizeof(system32) - 1u);
    memcpy(image_path + sizeof(system32) - 1u, root_module,
           strlen(root_module) + 1u);

    current_offset = write_wide(page, &cursor, "C:\\windows");
    dll_offset = write_wide(page, &cursor, "C:\\windows\\system32");
    image_offset = write_wide(page, &cursor, image_path);
    command_offset = write_wide(page, &cursor, image_path);
    environment_offset = write_wide(page, &cursor, "SystemRoot=C:\\windows");
    page[cursor] = 0u;
    page[cursor + 1u] = 0u;
    cursor += 2u;

    set_unicode_string(page, 0x24u, current_offset, "C:\\windows");
    set_unicode_string(page, 0x30u, dll_offset, "C:\\windows\\system32");
    set_unicode_string(page, 0x38u, image_offset, image_path);
    set_unicode_string(page, 0x40u, command_offset, image_path);
    {
        const uint32_t base = (uint32_t)(uintptr_t)page;
        const uint32_t environment = base + environment_offset;

        memcpy(page + 0x48u, &environment, 4u);
    }
    memcpy(page + 0x00u, &cursor, 4u);      /* MaximumLength */
    memcpy(page + 0x04u, &cursor, 4u);      /* Length */
    if (length_out)
        *length_out = cursor;
    return PW_OK;
}

/*
 * One zeroed page below the 32-bit boundary. A page the caller cannot address
 * is refused before anything is committed, and a page whose commit fails is
 * given straight back, so the unit never leaves a reservation behind.
 */
static int map_page(const PwGuestProcessConfig *config, uint32_t base,
                    PwVmRegion *region, uint32_t *address)
{
    const PwVmBackend *backend = config->backend;
    int status;

    if (!backend || !backend->reserve || !backend->commit)
        return PW_ERR_PRECONDITION;
    status = PW_ERR_VM;
    if ((backend->capabilities & PW_VM_CAP_EXACT_ADDRESS) != 0u)
        status = backend->reserve_at(backend->context, base,
                                     PW_GUEST_PROCESS_PAGE_BYTES,
                                     backend->page_bytes, region);
    if (status != PW_OK)
        status = backend->reserve(backend->context,
                                  PW_GUEST_PROCESS_PAGE_BYTES,
                                  backend->page_bytes, region);
    if (status != PW_OK)
        return status;
    if ((uint64_t)(uintptr_t)region->exec_base + region->bytes >
        0x100000000ull) {
        (void)backend->release(backend->context, region);
        return PW_ERR_UNSUPPORTED;
    }
    status = backend->commit(backend->context, region, 0u, region->bytes,
                             PW_PROT_READ | PW_PROT_WRITE);
    if (status != PW_OK) {
        (void)backend->release(backend->context, region);
        return status;
    }
    memset(region->write_base, 0, region->bytes);
    *address = (uint32_t)(uintptr_t)region->exec_base;
    return PW_OK;
}

static int release_pages(PwGuestProcess *process, const PwVmBackend *backend,
                         uint32_t count)
{
    int status = PW_OK;
    uint32_t kept = 0u;

    process->released = 0u;
    for (uint32_t index = 0u; index < count; ++index) {
        if (backend->release(backend->context, &process->pages[index]) !=
            PW_OK) {
            /*
             * The page is still ours: a failed release must not drop the only
             * record of it, or the mapping leaks and nobody can retry. Keep
             * it in the inventory (compacted, so the array stays dense) and
             * report the failure.
             */
            status = PW_ERR_VM;
            if (kept != index)
                process->pages[kept] = process->pages[index];
            kept++;
        } else {
            process->released++;
        }
    }
    /* What the process still owns after this attempt, not what it once had. */
    process->mapped = kept;
    return status;
}

int pw_guest_process_create(PwGuestProcess *process,
                            const PwGuestProcessConfig *config)
{
    uint32_t stack_base;
    uint32_t stack_bytes;

    if (!process || !config || !config->backend || !config->root_module)
        return PW_ERR_PRECONDITION;
    memset(process, 0, sizeof(*process));
    stack_base = config->stack_base != 0u ? config->stack_base
                                          : PW_GUEST_PROCESS_STACK_BASE;
    stack_bytes = config->stack_bytes != 0u ? config->stack_bytes
                                            : PW_GUEST_PROCESS_PAGE_BYTES;

    if (map_page(config, stack_base, &process->pages[0],
                 &process->layout.stack_base) != PW_OK)
        return PW_ERR_VM;
    process->mapped = 1u;
    process->layout.stack_bytes = (uint32_t)process->pages[0].bytes;
    if (process->layout.stack_bytes < stack_bytes)
        goto failed;
    if (map_page(config, PW_GUEST_PROCESS_TEB_BASE, &process->pages[1],
                 &process->layout.teb_base) != PW_OK)
        goto failed;
    process->mapped = 2u;
    process->layout.teb_bytes = (uint32_t)process->pages[1].bytes;
    if (map_page(config, PW_GUEST_PROCESS_PEB_BASE, &process->pages[2],
                 &process->layout.peb_base) != PW_OK)
        goto failed;
    process->mapped = 3u;
    if (map_page(config, PW_GUEST_PROCESS_PARAMETERS_BASE, &process->pages[3],
                 &process->layout.parameters_base) != PW_OK)
        goto failed;
    process->mapped = 4u;
    process->layout.parameters_bytes = (uint32_t)process->pages[3].bytes;
    if (populate_parameters(process->pages[3].write_base,
                            process->layout.parameters_bytes,
                            config->root_module,
                            &process->layout.parameters_length) != PW_OK)
        goto failed;

    /* The TEB: the documented NT fields ntdll reads through FS, and the
     * dispatcher the unix side would have published in WOW32Reserved. */
    {
        uint8_t *teb = process->pages[1].write_base;
        const uint32_t stack_high =
            process->layout.stack_base + process->layout.stack_bytes;
        const uint32_t self = process->layout.teb_base;
        const uint32_t peb = process->layout.peb_base;
        const uint32_t dispatcher = config->dispatcher_thunk;
        const uint32_t thread_local_storage = 0u;

        memcpy(teb + 0x04u, &stack_high, 4u);           /* StackBase */
        memcpy(teb + 0x08u, &process->layout.stack_base, 4u); /* StackLimit */
        memcpy(teb + 0x18u, &self, 4u);                 /* Self */
        memcpy(teb + 0x2cu, &thread_local_storage, 4u); /* no TLS modules */
        memcpy(teb + 0x30u, &peb, 4u);                  /* PEB */
        if (dispatcher != 0u)
            memcpy(teb + 0xc0u, &dispatcher, 4u);       /* WOW32Reserved */
    }
    /* The PEB: the image base and the parameters the loader reads. */
    {
        uint8_t *peb = process->pages[2].write_base;

        memcpy(peb + 0x08u, &config->image_base, 4u);   /* ImageBaseAddress */
        memcpy(peb + 0x10u, &process->layout.parameters_base, 4u);
    }
    return PW_OK;

failed:
    /* Nothing has been handed to the caller yet, so everything this unit
     * mapped goes back, including a parameters page the caller never saw. */
    (void)release_pages(process, config->backend, process->mapped);
    return PW_ERR_VM;
}

int pw_guest_process_release(PwGuestProcess *process,
                             const PwVmBackend *backend)
{
    uint32_t count;

    if (!process || !backend || !backend->release)
        return PW_ERR_PRECONDITION;
    /*
     * The stack, the TEB and the PEB belong to this unit for the whole run.
     * The parameters page does not: the caller hands it to the guest's own
     * call registry (ntdll replaces it with a copy and releases it), so
     * releasing it here as well would unmap the same block twice.
     */
    count = process->mapped < 3u ? process->mapped : 3u;
    return release_pages(process, backend, count);
}
