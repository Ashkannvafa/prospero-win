/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "pe_fixture.h"

#include "../src/pw_tls.h"
#include "../src/pw_vm_posix.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    ARENA_BYTES = 64 * 1024,
    ARENA_BASE = 0x30000000,
    TEB_BYTES = 0x1000,
    TEB_COUNT = 4,
    CALLBACK_TOKEN = 0xf1000000u,
};

/* One byte buffer per module: a PeImage borrows the bytes it was built from,
 * so sharing one buffer would silently re-describe every earlier module. */
enum { IMAGE_SLOTS = 12 };
enum { IMAGE_BYTES = 128 * 1024 };
static uint8_t images[IMAGE_SLOTS][IMAGE_BYTES];
static uint32_t image_slot;
static const uint8_t code[64] = {0xc3};
static const uint8_t data[64] = {0x5a};
static const uint8_t alpha_template[8] = {1, 2, 3, 4, 5, 6, 7, 8};

static PwVmBackend vm;
static PwTlsRuntime runtime;
static PwVmRegion arena;
static PwX86State state;
static PwVmRegion tebs[TEB_COUNT];

/* Guest TEB blocks at their real addresses: the runtime writes FS:[0x2C]
 * into this memory, so a placeholder pointer would prove nothing. */
static uint32_t teb_address(uint32_t index)
{
    return 0x20000000u + index * 0x10000u;
}

typedef struct MappedModule {
    const char *name;
    uint8_t *buffer;            /* the mutable bytes the image borrows */
    PeImage image;
    PeLayout layout;
    PwMappedImage mapped;
} MappedModule;

static MappedModule alpha, beta, gamma;

static size_t build_module(MappedModule *module, uint8_t *buffer,
                           const char *name,
                           uint64_t base, int with_tls, uint32_t zero_fill,
                           const uint8_t *template_data, uint32_t template_bytes,
                           const uint32_t *callbacks, uint32_t callback_count,
                           uint32_t padding_callbacks, int use_rvas)
{
    PeFixtureSpec spec;
    size_t size;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = base;
    spec.entry_point = TEXT_RVA;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = code;
    spec.sections[0].data_bytes = (uint32_t)sizeof(code);
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = data;
    spec.sections[1].data_bytes = (uint32_t)sizeof(data);
    spec.has_tls = with_tls;
    spec.tls.zero_fill = zero_fill;
    spec.tls.template_data = template_data;
    spec.tls.template_bytes = template_bytes;
    spec.tls.callback_count = callback_count;
    spec.tls.padding_callbacks = padding_callbacks;
    spec.tls.use_rvas = use_rvas;
    for (uint32_t index = 0; index < callback_count; ++index)
        spec.tls.callbacks[index] = callbacks[index];
    size = pe_fixture_build(buffer, IMAGE_BYTES, &spec);
    assert(size != 0u);
    memset(module, 0, sizeof(*module));
    module->name = name;
    module->buffer = buffer;
    assert(pe_image_parse(&module->image, buffer, size) == PW_OK);
    assert(pe_layout_plan(&module->layout, &module->image) == PW_OK);
    assert(pw_map_image(&module->mapped, &module->image, &module->layout,
                        &vm) == PW_OK);
    return size;
}

/* Rebuilds one module into `buffer` so a test can patch its TLS directory. */
static size_t rebuild(MappedModule *module, const char *name, uint64_t base,
                      const uint8_t *template_data, uint32_t template_bytes,
                      uint32_t zero_fill, const uint32_t *callbacks,
                      uint32_t callback_count, uint32_t padding_callbacks,
                      int use_rvas, int with_tls)
{
    assert(image_slot < IMAGE_SLOTS);
    /* Each rebuild gets a distinct image base: a fixture image has no
     * relocations, so mapping two copies at one base would have to fail. */
    {
        const uint64_t unique_base =
            base + (uint64_t)image_slot * 0x100000ull;
        uint8_t *bytes = images[image_slot];

        ++image_slot;
        return build_module(module, bytes, name, unique_base, with_tls,
                            zero_fill, template_data, template_bytes, callbacks,
                            callback_count, padding_callbacks, use_rvas);
    }
}

static uint32_t tls_field(const MappedModule *module, uint32_t index)
{
    const PeDataDirectory *entry =
        pe_image_directory(&module->image, PE_DIR_TLS);
    uint32_t value = 0u;
    size_t offset;

    assert(entry != NULL && entry->size >= PE_TLS_DIRECTORY_BYTES);
    assert(pe_image_file_offset(&module->image, entry->virtual_address,
                                PE_TLS_DIRECTORY_BYTES, &offset) == PW_OK);
    memcpy(&value, module->image.bytes + offset + index * 4u, 4u);
    return value;
}

static void patch_tls_field(MappedModule *module, uint32_t index,
                            uint32_t value)
{
    const PeDataDirectory *entry =
        pe_image_directory(&module->image, PE_DIR_TLS);
    size_t offset;

    assert(entry != NULL);
    assert(pe_image_file_offset(&module->image, entry->virtual_address,
                                PE_TLS_DIRECTORY_BYTES, &offset) == PW_OK);
    memcpy(module->buffer + offset + index * 4u, &value, 4u);
}

static void setup_thread(uint32_t thread, uint32_t fs_bytes)
{
    const uint32_t teb = teb_address(thread);

    memset(&state, 0, sizeof(state));
    state.fs_base = teb;
    state.fs_bytes = fs_bytes;
    state.gpr[4] = teb + 0x400u;        /* a guest stack inside the TEB block */
    state.stack_low = teb + 0x100u;
    state.stack_high = teb + fs_bytes;
    state.memory[0].low = teb;
    state.memory[0].high = teb + fs_bytes;
    state.memory[0].permissions = PW_X86_READ | PW_X86_WRITE;
    state.memory_count = 1u;
}

static int test_parse_and_index(void)
{
    PeTlsDirectory directory;

    assert(pe_tls_parse(&directory, &alpha.image) == PW_OK);
    assert(directory.template_bytes == sizeof(alpha_template));
    assert(directory.zero_fill == 8u);
    assert(directory.storage_bytes == 16u);
    assert(directory.callback_count == 2u);
    assert(directory.index_rva != 0u);
    assert(directory.callbacks[0].va >= alpha.image.image_base);

    /* A template-less module with a zero fill and one callback is legal. */
    assert(pe_tls_parse(&directory, &beta.image) == PW_OK);
    assert(directory.template_bytes == 0u);
    assert(directory.template_rva == 0u);
    assert(directory.callback_count == 1u);
    assert(directory.storage_bytes == directory.zero_fill);

    /* No TLS directory at all is "no TLS", not an error. */
    assert(pe_tls_parse(&directory, &gamma.image) == PW_OK);
    assert(directory.directory_rva == 0u);
    assert(directory.callback_count == 0u);
    return 0;
}

static int test_module_registration(void)
{
    uint32_t written = 0xffffffffu;
    void *slot;

    assert(pw_tls_add_module(&runtime, "alpha.dll", &alpha.image,
                             &alpha.mapped) == PW_OK);
    assert(pw_tls_add_module(&runtime, "beta.dll", &beta.image,
                             &beta.mapped) == PW_OK);
    /* A module with no TLS has no index to publish. */
    assert(pw_tls_add_module(&runtime, "gamma.dll", &gamma.image,
                             &gamma.mapped) == PW_ERR_NOT_FOUND);
    assert(pw_tls_add_module(&runtime, "alpha.dll", &alpha.image,
                             &alpha.mapped) == PW_ERR_STATE);
    assert(pw_tls_find_module(&runtime, "alpha.dll") == 0);
    assert(pw_tls_find_module(&runtime, "beta.dll") == 1);
    assert(pw_tls_find_module(&runtime, "gamma.dll") == PW_ERR_NOT_FOUND);

    /* The index is published through the mapped image, not a private copy. */
    {
        const PeTlsDirectory *directory = &runtime.modules[0].directory;

        slot = pw_map_writable(&alpha.mapped, directory->index_rva, 4u);
        assert(slot != NULL);
        memcpy(&written, slot, 4u);
        assert(written == 0u);
        slot = pw_map_writable(&beta.mapped, runtime.modules[1].directory.index_rva,
                               4u);
        assert(slot != NULL);
        memcpy(&written, slot, 4u);
        assert(written == 1u);
        assert(runtime.modules[0].index_slot ==
               (uint32_t)alpha.mapped.actual_base + directory->index_rva);
    }
    assert(runtime.index_writes == 2u);
    assert(pw_tls_validate(&runtime) == PW_OK);
    return 0;
}

static int test_two_threads(void)
{
    uint32_t first = 0u;
    uint32_t second = 0u;
    uint32_t guest = 0u;
    uint32_t array = 0u;
    uint8_t stored[16];

    setup_thread(0, 0x1000u);
    assert(pw_tls_thread_attach(&runtime, 0u, teb_address(0u), &state) == PW_OK);
    setup_thread(1, 0x1000u);
    assert(pw_tls_thread_attach(&runtime, 1u, teb_address(1u), &state) == PW_OK);
    assert(runtime.thread_count == 2u);

    /* Same module index, different storage per thread. */
    assert(pw_tls_slot(&runtime, 0u, 0u, &first) == PW_OK);
    assert(pw_tls_slot(&runtime, 1u, 0u, &second) == PW_OK);
    assert(first != second);
    assert(pw_tls_slot(&runtime, 0u, 1u, &first) == PW_OK);
    assert(pw_tls_slot(&runtime, 1u, 1u, &second) == PW_OK);
    assert(first != second);

    /* The guest's own lookup through FS:[0x2C] agrees with the owner. */
    {
        setup_thread(1, 0x1000u);
        assert(pw_tls_guest_slot(&runtime, 1u, &state, 0u, &guest) == PW_OK);
        assert(pw_tls_slot(&runtime, 1u, 0u, &second) == PW_OK);
        assert(guest == second);
        /* A state that does not belong to this thread's TEB is refused. */
        state.fs_base = 0x20090000u;
        assert(pw_tls_guest_slot(&runtime, 1u, &state, 0u, &guest) ==
               PW_ERR_STATE);
        state.fs_base = 0x20010000u;
        memcpy(&array, (const void *)(uintptr_t)(teb_address(1u) +
                                                 PW_TLS_TEB_ARRAY_OFFSET), 4u);
        assert(array == runtime.threads[1].array);
    }

    /* Template bytes followed by exactly zero_fill zeros. */
    memcpy(stored, (const void *)(uintptr_t)second, sizeof(stored));
    assert(memcmp(stored, alpha_template, sizeof(alpha_template)) == 0);
    for (size_t index = sizeof(alpha_template); index < sizeof(stored); ++index)
        assert(stored[index] == 0u);

    /* The template-less module's storage is all zero fill. */
    assert(pw_tls_slot(&runtime, 0u, 1u, &first) == PW_OK);
    memset(stored, 0xff, sizeof(stored));
    memcpy(stored, (const void *)(uintptr_t)first,
           runtime.modules[1].storage_bytes);
    for (uint32_t index = 0; index < runtime.modules[1].storage_bytes; ++index)
        assert(stored[index] == 0u);
    assert(pw_tls_validate(&runtime) == PW_OK);
    return 0;
}

static int test_detach_releases_and_reuses(void)
{
    const uint32_t first_offset = runtime.threads[0].offset;
    const uint32_t first_bytes = runtime.threads[0].bytes;
    const uint32_t used = runtime.arena_used;
    uint32_t array = 0xffffffffu;
    uint32_t slot = 0u;

    setup_thread(0, 0x1000u);
    assert(pw_tls_thread_detach(&runtime, 0u, &state) == PW_OK);
    assert(runtime.storages_released == 1u);
    assert(runtime.arena_used == used - first_bytes);
    /* The TEB no longer points at a released array. */
    memcpy(&array, (const void *)(uintptr_t)(teb_address(0u) +
                                             PW_TLS_TEB_ARRAY_OFFSET), 4u);
    assert(array == 0u);
    assert(pw_tls_slot(&runtime, 0u, 0u, &slot) == PW_ERR_STATE);
    assert(pw_tls_thread_detach(&runtime, 0u, &state) == PW_ERR_STATE);

    /* Re-attaching reuses the same block and re-zeroes it first. */
    setup_thread(2, 0x1000u);
    assert(pw_tls_thread_attach(&runtime, 0u, teb_address(2u), &state) == PW_OK);
    assert(runtime.threads[0].offset == first_offset);
    assert(pw_tls_slot(&runtime, 0u, 0u, &slot) == PW_OK);
    assert(memcmp((const void *)(uintptr_t)slot, alpha_template,
                  sizeof(alpha_template)) == 0);

    assert(pw_tls_thread_detach(&runtime, 0u, &state) == PW_OK);
    setup_thread(1, 0x1000u);
    assert(pw_tls_thread_detach(&runtime, 1u, &state) == PW_OK);
    assert(runtime.thread_count == 0u);
    assert(runtime.arena_used == 0u);
    assert(runtime.storages_released == 3u);
    assert(pw_tls_validate(&runtime) == PW_OK);
    return 0;
}

static void run_callback(PwGuestCallback *frame, uint32_t *esp_saved)
{
    /* stdcall: the callee pops its three arguments and the token, so the
     * guest returns with the stack exactly where the callback found it. */
    state.gpr[4] = *esp_saved;
    state.eip = CALLBACK_TOKEN;
    uint64_t result = 0u;

    if (pw_guest_callback_leave(frame, 0u, &result) != PW_OK) {
        fprintf(stderr, "callback leave failed: esp=%08x saved=%08x eip=%08x "
                        "token=%08x active=%u ebx=%08x/%08x\n",
                state.gpr[4], frame->saved_gpr[4], state.eip,
                frame->return_token, frame->active, state.gpr[3],
                frame->saved_gpr[3]);
        assert(0);
    }
}

static int test_callback_order(void)
{
    PwGuestCallback frame = {0};
    uint32_t address = 0u;
    uint32_t argument = 0u;
    uint32_t order[5];
    uint32_t count = 0u;
    uint32_t esp_saved;
    const PwTlsPhase phases[4] = {
        PW_TLS_PROCESS_ATTACH, PW_TLS_THREAD_ATTACH,
        PW_TLS_THREAD_DETACH, PW_TLS_PROCESS_DETACH,
    };
    const uint32_t expected_reason[4] = {1u, 2u, 3u, 0u};

    setup_thread(3, 0x1000u);
    assert(pw_tls_thread_attach(&runtime, 3u, teb_address(3u), &state) == PW_OK);
    for (unsigned phase = 0; phase < 4u; ++phase) {
        assert(pw_tls_callback_plan(&runtime, 3u, phases[phase]) == PW_OK);
        count = 0u;
        while (pw_tls_callback_next(&runtime, &state, &frame, CALLBACK_TOKEN,
                                    &address, &argument) == PW_OK) {
            assert(count < 5u);
            assert(argument == expected_reason[phase]);
            order[count++] = address;
            esp_saved = state.gpr[4] + 16u;
            {
                uint32_t words[4];

                memcpy(words, (const void *)(uintptr_t)state.gpr[4], 16u);
                /* [esp] is the reserved return token; the three stdcall
                 * arguments follow it: hmodule, reason, reserved. */
                assert(words[0] == CALLBACK_TOKEN);
                assert(words[1] == (uint32_t)alpha.image.image_base ||
                       words[1] == (uint32_t)beta.image.image_base);
                assert(words[2] == expected_reason[phase]);
                assert(words[3] == 0u);
            }
            run_callback(&frame, &esp_saved);
        }
        assert(count == 3u);
        if (phases[phase] == PW_TLS_PROCESS_ATTACH ||
            phases[phase] == PW_TLS_THREAD_ATTACH) {
            assert(order[0] == (uint32_t)alpha.image.image_base + TEXT_RVA);
            assert(order[1] == (uint32_t)alpha.image.image_base + TEXT_RVA + 4u);
            assert(order[2] == (uint32_t)beta.image.image_base + TEXT_RVA + 8u);
        } else {
            assert(order[0] == (uint32_t)beta.image.image_base + TEXT_RVA + 8u);
            assert(order[1] == (uint32_t)alpha.image.image_base + TEXT_RVA + 4u);
            assert(order[2] == (uint32_t)alpha.image.image_base + TEXT_RVA);
        }
    }
    /* An exhausted plan is not an error to ignore: it is the end marker. */
    assert(pw_tls_callback_next(&runtime, &state, &frame, CALLBACK_TOKEN,
                                &address, &argument) == PW_ERR_STATE);
    assert(runtime.callbacks_scheduled == 12u);

    /* A failing attach callback rolls the thread back completely. */
    assert(pw_tls_callback_plan(&runtime, 3u, PW_TLS_THREAD_ATTACH) == PW_OK);
    assert(pw_tls_callback_next(&runtime, &state, &frame, CALLBACK_TOKEN,
                                &address, &argument) == PW_OK);
    assert(pw_tls_callback_failed(&runtime, &state, PW_ERR_STATE) ==
           PW_ERR_STATE);
    assert(runtime.rollbacks == 1u);
    assert(runtime.threads[3].used == 0u);
    assert(runtime.arena_used == 0u);
    {
        uint32_t array = 0xffffffffu;

        memcpy(&array, (const void *)(uintptr_t)(teb_address(3u) +
                                                 PW_TLS_TEB_ARRAY_OFFSET), 4u);
        assert(array == 0u);
    }
    assert(pw_tls_validate(&runtime) == PW_OK);
    return 0;
}

static int test_malformed_directories(void)
{
    PeTlsDirectory directory;
    uint32_t callbacks[3] = {TEXT_RVA, TEXT_RVA + 4u, TEXT_RVA + 8u};
    uint32_t many[PE_FIXTURE_MAX_TLS_CALLBACKS];
    MappedModule malformed;

    /* Guest pointers stored as file offsets must be rejected. */
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, alpha_template,
                   sizeof(alpha_template), 4u, callbacks, 1u, 0u, 1, 1) != 0u);
    assert(pe_tls_parse(&directory, &malformed.image) == PW_ERR_MALFORMED);

    /* End below start. */
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, alpha_template,
                   sizeof(alpha_template), 4u, callbacks, 1u, 0u, 0, 1) != 0u);
    {
        const uint32_t start = tls_field(&malformed, 0u);

        patch_tls_field(&malformed, 1u, start - 4u);
        assert(pe_tls_parse(&directory, &malformed.image) == PW_ERR_MALFORMED);
    }

    /* A callback outside an executable section. */
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, alpha_template,
                   sizeof(alpha_template), 4u, callbacks, 1u, 0u, 0, 1) != 0u);
    {
        uint32_t bad = DATA_RVA;

        pe_image_parse(&malformed.image, malformed.image.bytes,
                       malformed.image.size);
        {
            const PeDataDirectory *entry =
                pe_image_directory(&malformed.image, PE_DIR_TLS);
            size_t offset;

            assert(pe_image_file_offset(&malformed.image,
                                        entry->virtual_address,
                                        PE_TLS_DIRECTORY_BYTES, &offset) ==
                   PW_OK);
            /* AddressOfCallBacks points at the array; rewrite the first
             * entry to a data RVA. */
            {
                uint32_t callbacks_va = 0u;

                memcpy(&callbacks_va, malformed.image.bytes + offset + 12u, 4u);
                assert(callbacks_va >= malformed.image.image_base);
                {
                    const uint32_t callbacks_rva =
                        callbacks_va - (uint32_t)malformed.image.image_base;
                    size_t array_offset;

                    assert(pe_image_file_offset(&malformed.image, callbacks_rva,
                                                4u, &array_offset) == PW_OK);
                    bad += (uint32_t)malformed.image.image_base;
                    memcpy(malformed.buffer + array_offset, &bad, 4u);
                }
            }
        }
        assert(pe_tls_parse(&directory, &malformed.image) == PW_ERR_MALFORMED);
    }

    /* An array that never terminates within the bound. */
    for (uint32_t index = 0; index < PE_FIXTURE_MAX_TLS_CALLBACKS; ++index)
        many[index] = TEXT_RVA + (index % 2u) * 4u;
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, NULL, 0u, 4u, many,
                   PE_TLS_MAX_CALLBACKS, 1u, 0, 1) != 0u);
    assert(pe_tls_parse(&directory, &malformed.image) == PW_ERR_LIMIT);

    /* Unaligned index and callback pointers. */
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, NULL, 0u, 4u, callbacks,
                   1u, 0u, 0, 1) != 0u);
    {
        const uint32_t index_va = tls_field(&malformed, 2u);

        patch_tls_field(&malformed, 2u, index_va + 2u);
        assert(pe_tls_parse(&directory, &malformed.image) ==
               PW_ERR_MALFORMED);
    }
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, NULL, 0u, 4u, callbacks,
                   1u, 0u, 0, 1) != 0u);
    {
        const uint32_t callbacks_va = tls_field(&malformed, 3u);

        patch_tls_field(&malformed, 3u, callbacks_va + 2u);
        assert(pe_tls_parse(&directory, &malformed.image) ==
               PW_ERR_MALFORMED);
    }

    /* A missing index pointer is malformed, and an oversized fill is a
     * bound, not a silent allocation. */
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, NULL, 0u, 4u, callbacks,
                   1u, 0u, 0, 1) != 0u);
    patch_tls_field(&malformed, 2u, 0u);
    assert(pe_tls_parse(&directory, &malformed.image) == PW_ERR_MALFORMED);
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, NULL, 0u,
                   PE_TLS_MAX_ZERO_FILL + 1u, callbacks, 1u, 0u, 0, 1) != 0u);
    assert(pe_tls_parse(&directory, &malformed.image) == PW_ERR_LIMIT);
    assert(rebuild(&malformed, "bad.dll", 0x12000000u, NULL, 0u, 4u, NULL, 0u,
                   0u, 0, 1) != 0u);
    assert(pe_tls_parse(&directory, &malformed.image) == PW_OK);
    assert(directory.callback_count == 0u);
    return 0;
}

int main(void)
{
    uint32_t callbacks[3] = {TEXT_RVA, TEXT_RVA + 4u, TEXT_RVA + 8u};

    assert(pw_vm_posix_backend(&vm) == PW_OK);
    assert(vm.reserve_at(NULL, ARENA_BASE, ARENA_BYTES, vm.page_bytes,
                         &arena) == PW_OK);
    assert(vm.commit(NULL, &arena, 0u, ARENA_BYTES,
                     PW_PROT_READ | PW_PROT_WRITE) == PW_OK);
    for (uint32_t index = 0; index < TEB_COUNT; ++index) {
        assert(vm.reserve_at(NULL, teb_address(index), TEB_BYTES,
                             vm.page_bytes, &tebs[index]) == PW_OK);
        assert(vm.commit(NULL, &tebs[index], 0u, TEB_BYTES,
                         PW_PROT_READ | PW_PROT_WRITE) == PW_OK);
    }

    (void)rebuild(&alpha, "alpha.dll", 0x11000000u, alpha_template,
                  sizeof(alpha_template), 8u, callbacks, 2u, 0u, 0, 1);
    (void)rebuild(&beta, "beta.dll", 0x11100000u, NULL, 0u, 4u,
                  callbacks + 2u, 1u, 0u, 0, 1);
    (void)rebuild(&gamma, "gamma.dll", 0x11200000u, NULL, 0u, 0u, NULL, 0u, 0u,
                  0, 0);

    assert(pw_tls_runtime_init(&runtime, &vm, &arena) == PW_OK);
    assert(pw_tls_runtime_init(NULL, &vm, &arena) == PW_ERR_PRECONDITION);
    assert(pw_tls_runtime_init(&runtime, &vm, NULL) == PW_ERR_PRECONDITION);
    assert(pw_tls_runtime_init(&runtime, &vm, &arena) == PW_OK);

    test_parse_and_index();
    test_module_registration();
    test_two_threads();
    test_detach_releases_and_reuses();
    test_callback_order();
    test_malformed_directories();

    for (uint32_t index = 0; index < TEB_COUNT; ++index)
        assert(vm.release(NULL, &tebs[index]) == PW_OK);
    assert(vm.release(NULL, &arena) == PW_OK);
    assert(pw_map_release(&alpha.mapped, &vm) == PW_OK);
    assert(pw_map_release(&beta.mapped, &vm) == PW_OK);
    assert(pw_map_release(&gamma.mapped, &vm) == PW_OK);
    return 0;
}
