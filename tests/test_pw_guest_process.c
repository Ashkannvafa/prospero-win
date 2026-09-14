/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * The guest process state on its own: the stack, the TEB, the PEB and the
 * process parameters the loader reads.
 *
 * The unit maps four pages and fills the documented NT fields, so this test
 * checks the layout rather than the loader: the TEB's StackBase/StackLimit/
 * Self/PEB and the dispatcher the unix side would publish, the PEB's image
 * base and parameters pointer, and a process-parameters structure whose
 * strings live inside its own page and are self-consistent. It also checks the
 * two things the extraction had to get right: a page whose commit fails leaves
 * nothing mapped, and releasing the process gives back exactly the three pages
 * the unit owns - never the parameters page, which belongs to the guest's call
 * registry.
 */
#include "../src/pw_guest_process.h"
#include "../src/pw_vm_posix.h"

#include <assert.h>
#include <string.h>

/* Reads a UTF-16LE string out of the parameters page into ASCII. */
static void read_wide(const uint8_t *page, uint32_t field, char *out,
                      size_t out_bytes)
{
    uint16_t length = 0u;
    uint32_t buffer = 0u;
    size_t index = 0u;

    memcpy(&length, page + field, 2u);
    memcpy(&buffer, page + field + 4u, 4u);
    for (uint32_t unit = 0u; unit < 2u * (length / 2u) && index + 1u < out_bytes;
         unit += 2u) {
        const uint8_t low = *(const uint8_t *)(uintptr_t)(buffer + unit);

        out[index++] = low == 0u ? '?' : (char)low;
    }
    out[index] = '\0';
}

/* A backend whose commit can be made to fail, counting what it handed out. */
typedef struct FaultyBackend {
    PwVmBackend real;
    unsigned fail_commit;
    unsigned commits;
    unsigned releases;
} FaultyBackend;

static int faulty_commit(void *context, const PwVmRegion *region, size_t offset,
                         size_t bytes, unsigned protection)
{
    FaultyBackend *faults = context;

    faults->commits++;
    if (faults->fail_commit)
        return PW_ERR_VM;
    return faults->real.commit(faults->real.context, region, offset, bytes,
                               protection);
}

static int faulty_release(void *context, PwVmRegion *region)
{
    FaultyBackend *faults = context;

    faults->releases++;
    return faults->real.release(faults->real.context, region);
}

static int faulty_reserve(void *context, size_t bytes, size_t alignment,
                          PwVmRegion *out)
{
    FaultyBackend *faults = context;

    return faults->real.reserve(faults->real.context, bytes, alignment, out);
}

static int faulty_reserve_at(void *context, uint64_t address, size_t bytes,
                             size_t alignment, PwVmRegion *out)
{
    FaultyBackend *faults = context;

    return faults->real.reserve_at(faults->real.context, address, bytes,
                                   alignment, out);
}

static int faulty_protect(void *context, const PwVmRegion *region, size_t offset,
                          size_t bytes, unsigned protection)
{
    FaultyBackend *faults = context;

    return faults->real.protect(faults->real.context, region, offset, bytes,
                                protection);
}

static PwVmBackend faulty_backend(FaultyBackend *faults,
                                  const PwVmBackend *real)
{
    faults->real = *real;
    return (PwVmBackend){
        .context = faults,
        .capabilities = real->capabilities,
        .page_bytes = real->page_bytes,
        .reserve = faulty_reserve,
        .commit = faulty_commit,
        .protect = faulty_protect,
        .release = faulty_release,
        .reserve_at = faulty_reserve_at,
    };
}

int main(void)
{
    PwVmBackend real;
    PwVmBackend backend;
    FaultyBackend faults;
    PwGuestProcess process;
    PwGuestProcessConfig config;
    const uint8_t *teb;
    const uint8_t *peb;
    const uint8_t *parameters;
    char text[128];
    uint32_t value = 0u;
    uint32_t environment = 0u;

    assert(pw_vm_posix_backend(&real) == PW_OK);
    assert(real.reserve && real.commit && real.release);
    backend = faulty_backend(&faults, &real);

    memset(&config, 0, sizeof(config));
    config.backend = &backend;
    config.image_base = 0x10000000u;
    config.dispatcher_thunk = 0x10412344u;
    config.root_module = "ntdll.dll";

    /* The layout: four pages at the documented bases. */
    assert(pw_guest_process_create(&process, &config) == PW_OK);
    assert(process.mapped == PW_GUEST_PROCESS_PAGES);
    assert(process.layout.stack_base == PW_GUEST_PROCESS_STACK_BASE);
    assert(process.layout.stack_bytes == PW_GUEST_PROCESS_PAGE_BYTES);
    assert(process.layout.teb_base == PW_GUEST_PROCESS_TEB_BASE);
    assert(process.layout.peb_base == PW_GUEST_PROCESS_PEB_BASE);
    assert(process.layout.parameters_base == PW_GUEST_PROCESS_PARAMETERS_BASE);
    assert(process.layout.parameters_length > 0x100u);

    /* The TEB: the NT fields ntdll reads through FS, and the dispatcher. */
    teb = process.pages[1].write_base;
    memcpy(&value, teb + 0x04u, 4u);
    assert(value == PW_GUEST_PROCESS_STACK_BASE + PW_GUEST_PROCESS_PAGE_BYTES);
    memcpy(&value, teb + 0x08u, 4u);
    assert(value == PW_GUEST_PROCESS_STACK_BASE);
    memcpy(&value, teb + 0x18u, 4u);
    assert(value == PW_GUEST_PROCESS_TEB_BASE);
    memcpy(&value, teb + 0x30u, 4u);
    assert(value == PW_GUEST_PROCESS_PEB_BASE);
    memcpy(&value, teb + 0xc0u, 4u);
    assert(value == config.dispatcher_thunk);
    memcpy(&value, teb + 0x2cu, 4u);
    assert(value == 0u);
    /*
     * The activation context stack: the TEB points at the copy embedded in
     * itself, exactly as the Unix side sets it up for a real i386 thread, and
     * that copy starts empty (no active frame), because a thread with no
     * manifest has none. ntdll dereferences the pointer before it looks at the
     * frame, so an unset field here is a fault, not an empty answer.
     */
    memcpy(&value, teb + PW_GUEST_PROCESS_TEB_ACTIVATION_POINTER, 4u);
    assert(value == PW_GUEST_PROCESS_TEB_BASE +
                     PW_GUEST_PROCESS_TEB_ACTIVATION_STACK);
    for (uint32_t offset = 0u; offset < 0x18u; offset += 4u) {
        memcpy(&value, teb + PW_GUEST_PROCESS_TEB_ACTIVATION_STACK + offset,
               4u);
        assert(value == 0u);
    }

    /* The PEB: the image it is running and the parameters behind it. */
    peb = process.pages[2].write_base;
    memcpy(&value, peb + 0x08u, 4u);
    assert(value == config.image_base);
    memcpy(&value, peb + 0x10u, 4u);
    assert(value == PW_GUEST_PROCESS_PARAMETERS_BASE);

    /* The parameters: self-consistent sizes and strings inside the page. */
    parameters = process.pages[3].write_base;
    memcpy(&value, parameters + 0x00u, 4u);
    assert(value == process.layout.parameters_length);
    memcpy(&value, parameters + 0x04u, 4u);
    assert(value == process.layout.parameters_length);
    read_wide(parameters, 0x24u, text, sizeof(text));
    assert(strcmp(text, "C:\\windows") == 0);
    read_wide(parameters, 0x30u, text, sizeof(text));
    assert(strcmp(text, "C:\\windows\\system32") == 0);
    read_wide(parameters, 0x38u, text, sizeof(text));
    assert(strcmp(text, "C:\\windows\\system32\\ntdll.dll") == 0);
    read_wide(parameters, 0x40u, text, sizeof(text));
    assert(strcmp(text, "C:\\windows\\system32\\ntdll.dll") == 0);
    memcpy(&environment, parameters + 0x48u, 4u);
    assert(environment >= PW_GUEST_PROCESS_PARAMETERS_BASE);
    assert(environment < PW_GUEST_PROCESS_PARAMETERS_BASE +
                         PW_GUEST_PROCESS_PAGE_BYTES);
    {
        /* The environment block is a NUL-terminated UTF-16 string, not a
         * UNICODE_STRING: its field at 0x48 is the pointer itself. */
        const uint8_t *block = (const uint8_t *)(uintptr_t)environment;
        size_t index = 0u;

        while (index + 1u < sizeof(text)) {
            const uint8_t low = block[index * 2u];

            if (low == 0u && block[index * 2u + 1u] == 0u)
                break;
            text[index++] = (char)low;
        }
        text[index] = '\0';
        assert(strcmp(text, "SystemRoot=C:\\windows") == 0);
    }

    /* Releasing gives back the three pages the unit owns, once. */
    assert(pw_guest_process_release(&process, &backend) == PW_OK);
    assert(process.released == 3u && process.mapped == 0u);
    assert(pw_guest_process_release(&process, &backend) == PW_OK);
    assert(process.released == 0u);

    /* A commit that fails leaves nothing mapped: the reservation goes back. */
    {
        const unsigned before = faults.releases;

        faults.fail_commit = 1u;
        assert(pw_guest_process_create(&process, &config) != PW_OK);
        assert(process.mapped == 0u);
        assert(faults.releases == before + 1u);
        faults.fail_commit = 0u;
    }
    return 0;
}
