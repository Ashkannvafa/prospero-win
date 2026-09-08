/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include "../src/pw_map.h"
#include "../src/pw_vm_posix.h"

#include <assert.h>
#include <string.h>

enum {
    ARENA_BYTES = 0x20000u,
    COARSE_PAGE = 0x4000u,          /* a console-class mapping granularity */
    MAX_RECORDS = 16,
};

static uint8_t file_bytes[256 * 1024];
static _Alignas(COARSE_PAGE) uint8_t arena[ARENA_BYTES];
static const uint8_t code[128] = {0x48, 0x31, 0xc0, 0xc3};

/*
 * Test backend over a static arena. Its base address is known before the
 * image is built, so a fixture can declare it as its preferred base and the
 * zero-delta path becomes reachable on the host.
 */
static int arena_reserve(void *context, size_t bytes, size_t alignment,
                         PwVmRegion *out)
{
    (void)context;
    if (bytes > sizeof(arena) || alignment > COARSE_PAGE)
        return PW_ERR_VM;
    out->write_base = arena;
    out->exec_base = arena;
    out->bytes = bytes;
    out->alignment = alignment;
    out->handle = NULL;
    return PW_OK;
}

typedef struct ProtectRecord {
    size_t offset;
    size_t bytes;
    unsigned protection;
} ProtectRecord;

static ProtectRecord records[MAX_RECORDS];
static uint32_t record_count;

static int arena_commit(void *context, const PwVmRegion *region, size_t offset,
                        size_t bytes, unsigned protection)
{
    (void)context;
    if (!pw_vm_region_contains(region, offset, bytes))
        return PW_ERR_PRECONDITION;
    if (record_count < MAX_RECORDS) {
        records[record_count].offset = offset;
        records[record_count].bytes = bytes;
        records[record_count].protection = protection;
    }
    ++record_count;
    return PW_OK;
}

static int arena_release(void *context, PwVmRegion *region)
{
    (void)context;
    region->write_base = NULL;
    region->exec_base = NULL;
    region->bytes = 0u;
    return PW_OK;
}

static void arena_backend(PwVmBackend *backend, size_t page_bytes)
{
    backend->context = NULL;
    backend->capabilities = PW_VM_CAP_PROTECT;
    backend->page_bytes = page_bytes;
    backend->reserve = arena_reserve;
    backend->commit = arena_commit;
    backend->protect = arena_commit;
    backend->release = arena_release;
    record_count = 0u;
    memset(records, 0, sizeof(records));
}

/* Reserves at a fixed high execution alias, to exercise address policy. */
static int high_reserve(void *context, size_t bytes, size_t alignment,
                        PwVmRegion *out)
{
    const int status = arena_reserve(context, bytes, alignment, out);

    if (status != PW_OK)
        return status;
    out->exec_base = (void *)(uintptr_t)0x200000000ull;
    return PW_OK;
}

static size_t build(uint64_t image_base, int pe32plus, int with_relocs,
                    uint32_t bss_bytes)
{
    PeFixtureSpec spec;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = pe32plus;
    spec.image_base = image_base;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.section_count = bss_bytes != 0u ? 3u : 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = code;
    spec.sections[1].data_bytes = 64u;
    if (bss_bytes != 0u) {
        spec.sections[2].name = ".bss";
        spec.sections[2].characteristics = PE_SCN_CNT_UNINITIALIZED_DATA |
                                           PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
        spec.sections[2].virtual_size = bss_bytes;
    }
    spec.entry_point = 0x1000u;
    if (with_relocs) {
        /* A pointer inside .data that names an address in .text. */
        spec.reloc_count = 1u;
        spec.relocs[0].rva = 0x2000u;
        spec.relocs[0].type = pe32plus ? PE_RELOC_DIR64 : PE_RELOC_HIGHLOW;
    }
    return pe_fixture_build(file_bytes, sizeof(file_bytes), &spec);
}

static void test_maps_at_preferred_base(void)
{
    PwVmBackend backend;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    PwMapVerify verify;
    const size_t size = build((uint64_t)(uintptr_t)arena, 1, 1, 0x4000u);

    assert(size != 0u);
    arena_backend(&backend, 0x1000u);
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);
    /* The fixture declared the arena as its preferred base. */
    assert(layout.preferred_base == (uint64_t)(uintptr_t)arena);

    assert(pw_map_image(&mapped, &image, &layout, &backend) == PW_OK);
    assert(mapped.actual_base == (uint64_t)(uintptr_t)arena);
    assert(mapped.relocs.delta == 0u);
    assert(mapped.relocs.applied == 0u);
    assert(mapped.relocs.dir64 == 1u);
    assert(mapped.aliased_exec == 0u);
    assert(mapped.address_bits == 64u);
    assert(mapped.image_bytes == layout.image_bytes);

    /* Headers and every initialised byte are present in the mapping. */
    assert(memcmp(arena, file_bytes, layout.header_bytes) == 0);
    assert(memcmp(arena + 0x1000u, code, sizeof(code)) == 0);

    assert(pw_map_verify(&mapped, &image, &layout, &verify) == PW_OK);
    assert(verify.headers_present == 1u);
    /* .text, .data, .bss and the .reloc section the fixture appends. */
    assert(verify.sections_checked == 4u);
    assert(verify.raw_mismatches == 0u);
    assert(verify.zero_tail_violations == 0u);
    assert(verify.alias_mismatches == 0u);
    /* With no relocation applied the mapping is byte-exact against the file. */
    assert(verify.bytes_compared == sizeof(code) + 64u + 12u);
    assert(verify.checksum != 0u);

    /* The uninitialised section really is zero, not merely unwritten. */
    for (uint32_t index = 0; index < 0x4000u; ++index)
        assert(arena[0x3000u + index] == 0u);

    assert(pw_map_exec_address(&mapped, 0x1000u) ==
           (uint64_t)(uintptr_t)arena + 0x1000u);
    assert(pw_map_exec_address(&mapped, layout.image_bytes) == 0u);
    assert(pw_map_writable(&mapped, 0x1000u, 4u) == arena + 0x1000u);
    assert(pw_map_writable(&mapped, layout.image_bytes, 1u) == NULL);
    assert(pw_map_writable(&mapped, 0u, 0u) == NULL);

    assert(pw_map_release(&mapped, &backend) == PW_OK);
    assert(mapped.region.write_base == NULL);
}

static void test_relocates_when_rebased(void)
{
    PwVmBackend backend;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    PwMapVerify verify;
    const uint64_t preferred = 0x140000000ull;
    const size_t size = build(preferred, 1, 1, 0u);
    uint64_t pointer;

    assert(size != 0u);
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);

    /* Seed the relocation target with a pointer to .text at the old base. */
    {
        size_t offset;
        const uint64_t original = preferred + 0x1000u;

        assert(pe_image_file_offset(&image, 0x2000u, 8u, &offset) == PW_OK);
        memcpy(file_bytes + offset, &original, sizeof(original));
        assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    }

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    assert(pw_map_image(&mapped, &image, &layout, &backend) == PW_OK);
    assert(mapped.actual_base != preferred);
    assert(mapped.relocs.applied == 1u);
    assert(mapped.relocs.dir64 == 1u);

    /*
     * The rebased pointer must name the address the code will actually
     * observe, which is the executable alias, not the write alias.
     */
    memcpy(&pointer, (uint8_t *)mapped.region.write_base + 0x2000u,
           sizeof(pointer));
    assert(pointer == mapped.actual_base + 0x1000u);
    assert(pointer == pw_map_exec_address(&mapped, 0x1000u));

    /* A rebased image is deliberately no longer identical to its file. */
    assert(pw_map_verify(&mapped, &image, &layout, &verify) == PW_OK);
    assert(verify.bytes_compared == 0u);
    assert(verify.raw_mismatches == 0u);
    assert(verify.headers_present == 1u);
    assert(pw_map_release(&mapped, &backend) == PW_OK);
}

static void test_refuses_pe32_above_four_gib(void)
{
    PwVmBackend backend;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    const size_t size = build(0x400000ull, 0, 1, 0u);

    assert(size != 0u);
    arena_backend(&backend, 0x1000u);
    backend.reserve = high_reserve;
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);
    /*
     * A PE32 rebase is expressed as a 32-bit addend, so an image cannot be
     * relocated to an address above 4 GiB. Refuse instead of writing a
     * truncated pointer that would fault far from its cause.
     */
    assert(pw_map_image(&mapped, &image, &layout, &backend) ==
           PW_ERR_UNSUPPORTED);
}

static void test_refuses_rebase_without_relocations(void)
{
    PwVmBackend backend;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    const size_t size = build(0x140000000ull, 1, 0, 0u);

    assert(size != 0u);
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);
    assert(layout.relocatable == 0u);
    assert(pw_vm_posix_backend(&backend) == PW_OK);
    assert(pw_map_image(&mapped, &image, &layout, &backend) ==
           PW_ERR_UNSUPPORTED);
}

/*
 * Found by mutation fuzzing. Some linkers and packers emit fewer than
 * sixteen data directories; when the array stops before the
 * base-relocation slot, the image is well formed and simply unrebaseable.
 * It must be refused as unsupported, not as a mapper precondition failure.
 */
static void test_short_data_directory_is_refused_cleanly(void)
{
    PeFixtureSpec spec;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    PwVmBackend backend;
    size_t size;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 1;
    spec.image_base = 0x140000000ull;
    spec.directory_count = 2u;              /* stops before BASERELOC */
    spec.section_count = 1u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.entry_point = 0x1000u;
    size = pe_fixture_build(file_bytes, sizeof(file_bytes), &spec);

    assert(size != 0u);
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(image.directory_count == 2u);
    assert(pe_image_directory(&image, PE_DIR_BASERELOC) == NULL);
    assert(pe_layout_plan(&layout, &image) == PW_OK);
    assert(layout.relocatable == 0u);

    assert(pw_vm_posix_backend(&backend) == PW_OK);
    assert(pw_map_image(&mapped, &image, &layout, &backend) ==
           PW_ERR_UNSUPPORTED);
}

static void test_protection_at_page_granularity(void)
{
    PwVmBackend backend;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    const size_t size = build((uint64_t)(uintptr_t)arena, 1, 1, 0x1000u);

    assert(size != 0u);
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);

    /* Page size equal to the section alignment keeps sections separated. */
    arena_backend(&backend, 0x1000u);
    assert(pw_map_image(&mapped, &image, &layout, &backend) == PW_OK);
    record_count = 0u;                      /* forget the initial commit */
    assert(pw_map_finalize_protections(&mapped, &layout, &backend) == PW_OK);
    assert(mapped.protections_applied == 1u);
    assert(mapped.protection.pages == layout.image_bytes / 0x1000u);
    assert(mapped.protection.merged_pages == 0u);
    assert(mapped.protection.wx_pages == 0u);
    /*
     * headers r--, .text r-x, .data and .bss rw- coalesced into one run,
     * then the discardable .reloc section r--.
     */
    assert(mapped.protection.protect_calls == 4u);
    assert(records[0].protection == PW_PROT_READ);
    assert(records[1].protection == (PW_PROT_READ | PW_PROT_EXEC));
    assert(records[2].protection == (PW_PROT_READ | PW_PROT_WRITE));
    assert(records[2].bytes == 0x2000u);
    assert(records[3].protection == PW_PROT_READ);

    /* Verification is refused once pages may no longer be readable. */
    PwMapVerify verify;
    assert(pw_map_verify(&mapped, &image, &layout, &verify) == PW_ERR_STATE);
    assert(pw_map_finalize_protections(&mapped, &layout, &backend) ==
           PW_ERR_STATE);
    assert(pw_map_release(&mapped, &backend) == PW_OK);
}

static void test_coarse_pages_merge_protections(void)
{
    PwVmBackend backend;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    const size_t size = build((uint64_t)(uintptr_t)arena, 1, 1, 0x1000u);

    assert(size != 0u);
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);
    assert(layout.section_alignment == 0x1000u);
    assert(layout.image_bytes <= COARSE_PAGE * 2u);

    /*
     * A mapping granularity coarser than the image's section alignment
     * forces several sections onto one protectable page. The union is
     * applied and counted: a page that ends up writable and executable is
     * a measured fact, never a silent one.
     */
    arena_backend(&backend, COARSE_PAGE);
    assert(pw_map_image(&mapped, &image, &layout, &backend) == PW_OK);
    record_count = 0u;
    assert(pw_map_finalize_protections(&mapped, &layout, &backend) == PW_OK);
    assert(mapped.protection.pages == 2u);
    /*
     * The first page carries the headers, .text, .data and .bss at once, so
     * its protection is the union: read, write and execute together.
     */
    assert(mapped.protection.merged_pages == 1u);
    assert(mapped.protection.wx_pages == 1u);
    assert(mapped.protection.protect_calls == 2u);
    assert(records[0].protection ==
           (PW_PROT_READ | PW_PROT_WRITE | PW_PROT_EXEC));
    assert(records[0].bytes == COARSE_PAGE);
    assert(records[1].protection == PW_PROT_READ);
    assert(pw_map_release(&mapped, &backend) == PW_OK);
}

static void test_preconditions(void)
{
    PwVmBackend backend;
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
    const size_t size = build((uint64_t)(uintptr_t)arena, 1, 1, 0u);

    assert(size != 0u);
    arena_backend(&backend, 0x1000u);
    assert(pe_image_parse(&image, file_bytes, size) == PW_OK);
    assert(pe_layout_plan(&layout, &image) == PW_OK);

    assert(pw_map_image(NULL, &image, &layout, &backend) ==
           PW_ERR_PRECONDITION);
    assert(pw_map_image(&mapped, NULL, &layout, &backend) ==
           PW_ERR_PRECONDITION);
    assert(pw_map_image(&mapped, &image, NULL, &backend) ==
           PW_ERR_PRECONDITION);
    assert(pw_map_image(&mapped, &image, &layout, NULL) ==
           PW_ERR_PRECONDITION);

    memset(&mapped, 0, sizeof(mapped));
    assert(pw_map_verify(&mapped, &image, &layout, NULL) ==
           PW_ERR_PRECONDITION);
    /* Nothing mapped yet: verification has no state to inspect. */
    PwMapVerify verify;
    assert(pw_map_verify(&mapped, &image, &layout, &verify) == PW_ERR_STATE);
    assert(pw_map_finalize_protections(&mapped, &layout, &backend) ==
           PW_ERR_STATE);
    /* Releasing something never mapped is a no-op, not an error. */
    assert(pw_map_release(&mapped, &backend) == PW_OK);

    /* A backend without protect cannot install final protections. */
    assert(pw_map_image(&mapped, &image, &layout, &backend) == PW_OK);
    PwVmBackend no_protect = backend;
    no_protect.capabilities = 0u;
    assert(pw_map_finalize_protections(&mapped, &layout, &no_protect) ==
           PW_ERR_UNSUPPORTED);
    assert(pw_map_release(&mapped, &backend) == PW_OK);
}

int main(void)
{
    test_maps_at_preferred_base();
    test_relocates_when_rebased();
    test_refuses_pe32_above_four_gib();
    test_refuses_rebase_without_relocations();
    test_short_data_directory_is_refused_cleanly();
    test_protection_at_page_granularity();
    test_coarse_pages_merge_protections();
    test_preconditions();
    return 0;
}
