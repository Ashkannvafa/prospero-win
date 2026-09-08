/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Host inspector: parse, plan, map, verify and walk the dependency graph of
 * a real Windows binary without committing it.
 *
 * Private game and third-party files are read from a path the operator
 * passes on the command line. Nothing is copied into the repository, and
 * the output is deliberately structural: names, counts, sizes and hashes,
 * never proprietary bytes.
 *
 *   inspect_pe <image> [--dir <search directory>] [--no-map]
 */
#include "../src/pw_file_posix.h"
#include "../src/pw_loader.h"
#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"

#include <stdio.h>
#include <string.h>

static PwLoader loader;

static void print_image(const PeImage *image, const PeLayout *layout)
{
    (void)printf("machine=%s bits=%u dll=%d subsystem=%u sections=%u\n",
                 pe_image_machine_name(image),
                 image->optional_magic == PE_OPT_MAGIC_PE32 ? 32u : 64u,
                 pe_image_is_dll(image), image->subsystem,
                 image->section_count);
    (void)printf("preferred_base=0x%llx image_bytes=%u headers=%u "
                 "entry=0x%x relocatable=%u dynamic_base=%u nx=%u\n",
                 (unsigned long long)layout->preferred_base,
                 layout->image_bytes, layout->header_bytes,
                 layout->entry_point, layout->relocatable,
                 layout->dynamic_base, layout->nx_compat);
    (void)printf("native_execution=%s\n",
                 pe_image_machine_is_native(image) ? "yes"
                                                   : "no (needs translation)");
    for (uint32_t index = 0; index < layout->section_count; ++index) {
        const PeLayoutSection *section = &layout->sections[index];

        (void)printf("  section %-8s rva=0x%08x mapped=%-8u raw=%-8u "
                     "zero=%-8u %s%s%s\n",
                     section->name, section->rva, section->mapped_bytes,
                     section->raw_bytes, section->zero_bytes,
                     pw_protection_name(section->protection),
                     section->derived_protection ? " derived" : "",
                     section->uninitialized ? " bss" : "");
    }
}

static void print_imports(const PeImage *image)
{
    PeImportTable table;
    const int status = pe_import_parse(&table, image);

    if (status != PW_OK) {
        (void)printf("imports unreadable: %s\n", pw_result_name(status));
        return;
    }
    (void)printf("imports modules=%u symbols=%u\n", table.module_count,
                 table.symbol_count);
    for (uint32_t index = 0; index < table.module_count; ++index) {
        const PeImportModule *module = &table.modules[index];
        char canonical[PW_MODULE_NAME_MAX + 1];
        const int canonical_status =
            pw_module_name_canonical(canonical, sizeof(canonical),
                                      module->name);

        (void)printf("  %-24s named=%-4u ordinal=%-4u %s%s\n", module->name,
                     module->named_count, module->ordinal_count,
                     canonical_status == PW_OK && pw_module_is_system(canonical)
                         ? "host" : "local",
                     module->bound ? " bound" : "");
    }
}

int main(int argc, char **argv)
{
    const char *image_path = NULL;
    const char *directory = NULL;
    int map_image = 1;
    PwFilePosix files;
    PwFileProvider provider;
    PwVmBackend backend;
    PwFileSpan span;
    PeImage image;
    PeLayout layout;
    int status;

    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--dir") == 0 && index + 1 < argc)
            directory = argv[++index];
        else if (strcmp(argv[index], "--no-map") == 0)
            map_image = 0;
        else if (!image_path)
            image_path = argv[index];
        else
            image_path = NULL;
    }
    if (!image_path) {
        (void)fprintf(stderr,
                      "usage: inspect_pe <image> [--dir <dir>] [--no-map]\n");
        return 2;
    }

    status = pw_file_posix_init(&files, directory ? directory : ".");
    if (status != PW_OK) {
        (void)fprintf(stderr, "directory rejected: %s\n",
                      pw_result_name(status));
        return 1;
    }
    status = pw_file_posix_read(&files, image_path, &span);
    if (status != PW_OK) {
        (void)fprintf(stderr, "cannot read %s: %s\n", image_path,
                      pw_result_name(status));
        return 1;
    }
    (void)printf("file=%s bytes=%zu\n", image_path, span.size);

    status = pe_image_parse(&image, span.bytes, span.size);
    if (status != PW_OK) {
        (void)fprintf(stderr, "parse failed: %s\n", pw_result_name(status));
        return 1;
    }
    status = pe_layout_plan(&layout, &image);
    if (status != PW_OK) {
        (void)fprintf(stderr, "layout refused: %s\n", pw_result_name(status));
        return 1;
    }
    print_image(&image, &layout);
    print_imports(&image);

    if (!map_image)
        return 0;

    (void)pw_file_posix_provider(&files, &provider);
    (void)pw_vm_posix_backend(&backend);
    status = pw_loader_init(&loader, &provider, &backend);
    if (status != PW_OK) {
        (void)fprintf(stderr, "loader init failed: %s\n",
                      pw_result_name(status));
        return 1;
    }
    status = pw_loader_load(&loader, span.bytes, span.size, "root.exe");
    if (status != PW_OK) {
        (void)fprintf(stderr, "load failed: %s%s%s\n", pw_result_name(status),
                      loader.missing[0] != '\0' ? " missing=" : "",
                      loader.missing);
        return 1;
    }
    (void)printf("graph modules=%u local=%u host=%u depth=%u cycles=%u "
                 "reserved=%llu\n",
                 loader.module_count, loader.local_count, loader.host_count,
                 loader.max_depth, loader.cycle_edges,
                 (unsigned long long)loader.reserved_bytes);
    for (uint32_t index = 0; index < loader.order_count; ++index) {
        const PwModule *module =
            pw_loader_module(&loader, loader.order[index]);

        (void)printf("  %u %-24s %-5s depth=%u base=0x%llx relocs=%u "
                     "checksum=0x%016llx\n",
                     index, module->name, pw_module_kind_name(module->kind),
                     module->depth,
                     (unsigned long long)module->mapped.actual_base,
                     module->mapped.relocs.applied,
                     (unsigned long long)module->verify.checksum);
    }
    status = pw_loader_finalize(&loader);
    if (status != PW_OK) {
        (void)fprintf(stderr, "protections failed: %s\n",
                      pw_result_name(status));
        return 1;
    }
    (void)printf("protections pages=%u merged=%u wx=%u calls=%u\n",
                 pw_loader_module(&loader, 0u)->mapped.protection.pages,
                 pw_loader_module(&loader, 0u)->mapped.protection.merged_pages,
                 pw_loader_module(&loader, 0u)->mapped.protection.wx_pages,
                 pw_loader_module(&loader, 0u)->mapped.protection.protect_calls);
    status = pw_loader_release(&loader);
    if (status != PW_OK) {
        (void)fprintf(stderr, "release failed: %s\n", pw_result_name(status));
        return 1;
    }
    provider.close(provider.context, &span);
    (void)printf("released opens=%u closes=%u\n", files.opens, files.closes);
    return 0;
}
