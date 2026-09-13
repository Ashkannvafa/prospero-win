/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the NT file service behind the Unix-call bridge.
 *
 * One synthetic module plays the part of a Wine loader: it builds a
 * UNICODE_STRING and an OBJECT_ATTRIBUTES for "C:\windows\system32\test.dll"
 * in its own data section, calls NtOpenFile, reads the file through
 * NtReadFile into a guest buffer and closes the handle with NtClose. The
 * service is an in-memory stub, so nothing here needs a real file, and the
 * test checks exactly what a guest would see: the handle, the IO status
 * blocks, the bytes, and the refusal of a path that tries to escape the
 * runtime directory.
 */
#include "pe_fixture.h"

#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_wine_gate.h"

#include <assert.h>
#include <string.h>

enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    IMAGE_BASE = 0x11000000,
    SLOT_RVA = DATA_RVA,                    /* __wine_syscall_dispatcher */
    NAME_TEXT_RVA = DATA_RVA + 0x40,        /* the first path, UTF-16 */
    NAME_RVA = DATA_RVA + 0x80,             /* its UNICODE_STRING header */
    ATTRIBUTES_RVA = DATA_RVA + 0x90,       /* OBJECT_ATTRIBUTES */
    HANDLE_RVA = DATA_RVA + 0xB0,
    IO_RVA = DATA_RVA + 0xB4,
    RESULT_RVA = DATA_RVA + 0xB8,           /* NTSTATUS of the first open */
    CLOSE_RESULT_RVA = DATA_RVA + 0xBC,
    BUFFER_RVA = DATA_RVA + 0xC0,
    ESCAPE_TEXT_RVA = DATA_RVA + 0x100,     /* the escaping path, UTF-16 */
    ESCAPE_RVA = DATA_RVA + 0x150,          /* its UNICODE_STRING header */
    ESCAPE_ATTRIBUTES_RVA = DATA_RVA + 0x160,
    ESCAPE_HANDLE_RVA = DATA_RVA + 0x190,
    ESCAPE_IO_RVA = DATA_RVA + 0x194,
    THUNK_RVA = TEXT_RVA + 0x80,
    STUB_OPEN_RVA = TEXT_RVA + 0x90,
    STUB_READ_RVA = TEXT_RVA + 0xA0,
    STUB_CLOSE_RVA = TEXT_RVA + 0xB0,
    CALLER_RVA = TEXT_RVA,
    FILE_BYTES = 16,
};

static const uint8_t file_contents[FILE_BYTES] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
};

static uint8_t image[64 * 1024];
static uint8_t text[512];
static uint32_t text_bytes;
static uint8_t data[0x400];
static PeFixtureReloc relocs[32];
static uint32_t reloc_count;

static void emit_byte(uint8_t value)
{
    assert(text_bytes < sizeof(text));
    text[text_bytes++] = value;
}

static void emit_u32(uint32_t value)
{
    emit_byte((uint8_t)(value & 0xffu));
    emit_byte((uint8_t)((value >> 8) & 0xffu));
    emit_byte((uint8_t)((value >> 16) & 0xffu));
    emit_byte((uint8_t)((value >> 24) & 0xffu));
}

static void emit_absolute(uint32_t rva)
{
    relocs[reloc_count].rva = TEXT_RVA + text_bytes;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
    emit_u32(IMAGE_BASE + rva);
}

static void emit_push_absolute(uint32_t rva)
{
    emit_byte(0x68);
    emit_absolute(rva);
}

static void emit_push_imm8(uint8_t value)
{
    emit_byte(0x6a);
    emit_byte(value);
}

static void emit_push_imm32(uint32_t value)
{
    emit_byte(0x68);
    emit_u32(value);
}

static void emit_call(uint32_t target_rva)
{
    const uint32_t next = TEXT_RVA + text_bytes + 5u;

    emit_byte(0xe8);
    emit_u32(target_rva - next);
}

/* "mov [disp32], eax", used to keep handles and results. */
static void emit_store_eax(uint32_t rva)
{
    emit_byte(0xa3);
    emit_absolute(rva);
}

static void emit_stub(uint32_t index, uint32_t id, uint16_t arg_bytes)
{
    while (text_bytes < (uint32_t)index - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xb8);
    emit_u32(id);
    emit_byte(0xba);
    emit_absolute(THUNK_RVA);
    emit_byte(0xff); emit_byte(0xd2);
    emit_byte(0xc2);
    emit_byte((uint8_t)(arg_bytes & 0xffu));
    emit_byte((uint8_t)((arg_bytes >> 8) & 0xffu));
    emit_byte(0x90);
}

/* A UNICODE_STRING header at `header` pointing at the text stored at
 * `text_offset`, both inside the module's data section. */
static void put_unicode_string(uint32_t header, uint32_t text_offset,
                               const char *text_ascii)
{
    const uint16_t length = (uint16_t)(strlen(text_ascii) * 2u);
    const uint32_t buffer = IMAGE_BASE + text_offset;
    uint32_t index = 0u;

    /* Callers pass RVAs; the fixture buffer starts at the section's base. */
    header -= DATA_RVA;
    text_offset -= DATA_RVA;
    while (text_ascii[index] != '\0') {
        data[text_offset + index * 2u] = (uint8_t)text_ascii[index];
        data[text_offset + index * 2u + 1u] = 0u;
        ++index;
    }
    data[text_offset + index * 2u] = 0u;
    data[text_offset + index * 2u + 1u] = 0u;
    memcpy(data + header, &length, 2u);
    memcpy(data + header + 2u, &length, 2u);
    memcpy(data + header + 4u, &buffer, 4u);
}

static size_t build_module(void)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));
    /* UNICODE_STRINGs for the two names, then the OBJECT_ATTRIBUTES that
     * point at them (ObjectName is the third dword). */
    put_unicode_string(NAME_RVA, NAME_TEXT_RVA,
                       "C:\\windows\\system32\\test.dll");
    put_unicode_string(ESCAPE_RVA, ESCAPE_TEXT_RVA,
                       "C:\\windows\\system32\\..\\..\\etc");
    {
        const uint32_t name_pointer = IMAGE_BASE + NAME_RVA;
        const uint32_t escape_pointer = IMAGE_BASE + ESCAPE_RVA;
        const uint32_t length = 24u;

        /* The data array holds one section, so RVA minus its base. */
        memcpy(data + (ATTRIBUTES_RVA - DATA_RVA), &length, 4u);
        memcpy(data + (ATTRIBUTES_RVA - DATA_RVA) + 8u, &name_pointer, 4u);
        memcpy(data + (ESCAPE_ATTRIBUTES_RVA - DATA_RVA), &length, 4u);
        memcpy(data + (ESCAPE_ATTRIBUTES_RVA - DATA_RVA) + 8u,
               &escape_pointer, 4u);
    }

    /* The caller: open, read, close, then try the escaping path. */
    emit_push_imm8(0x00);                 /* OpenOptions */
    emit_push_imm8(0x00);                 /* ShareAccess */
    emit_push_absolute(IO_RVA);           /* IoStatusBlock */
    emit_push_absolute(ATTRIBUTES_RVA);   /* ObjectAttributes */
    emit_push_imm32(0x00100000u);         /* DesiredAccess: FILE_READ_DATA */
    emit_push_absolute(HANDLE_RVA);       /* FileHandle */
    emit_call(STUB_OPEN_RVA);
    emit_store_eax(RESULT_RVA);           /* keep the open status */

    emit_push_imm8(0x00);                 /* Key */
    emit_push_imm8(0x00);                 /* ByteOffset (NULL) */
    emit_push_imm32(FILE_BYTES);          /* Length */
    emit_push_absolute(BUFFER_RVA);       /* Buffer */
    emit_push_absolute(IO_RVA);           /* IoStatusBlock */
    emit_push_imm8(0x00);                 /* ApcContext */
    emit_push_imm8(0x00);                 /* ApcRoutine */
    emit_push_imm8(0x00);                 /* Event */
    emit_byte(0xa1);                      /* mov eax, [HANDLE_RVA] */
    emit_absolute(HANDLE_RVA);
    emit_byte(0x50);                      /* push eax */
    emit_call(STUB_READ_RVA);
    emit_store_eax(IO_RVA + 4u);

    emit_byte(0xa1);
    emit_absolute(HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);
    emit_store_eax(CLOSE_RESULT_RVA);

    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_absolute(ESCAPE_IO_RVA);
    emit_push_absolute(ESCAPE_ATTRIBUTES_RVA);
    emit_push_imm32(0x00100000u);
    emit_push_absolute(ESCAPE_HANDLE_RVA);
    emit_call(STUB_OPEN_RVA);
    emit_store_eax(ESCAPE_IO_RVA);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_OPEN_RVA, 0x0033u, 24u);     /* NtOpenFile */
    emit_stub(STUB_READ_RVA, 0x0006u, 36u);     /* NtReadFile */
    emit_stub(STUB_CLOSE_RVA, 0x000fu, 4u);     /* NtClose */
    emit_byte(0xc3);

    /*
     * The pointers stored inside the data section need their own base
     * relocations, exactly like a real image: without them the guest would
     * hand the gate a preferred-base address that is not mapped.
     */
    relocs[reloc_count].rva = NAME_RVA + 4u;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
    relocs[reloc_count].rva = ATTRIBUTES_RVA + 8u;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
    relocs[reloc_count].rva = ESCAPE_RVA + 4u;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
    relocs[reloc_count].rva = ESCAPE_ATTRIBUTES_RVA + 8u;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;

    memset(&spec, 0, sizeof(spec));
    spec.pe32plus = 0;
    spec.dll = 1;
    spec.image_base = IMAGE_BASE;
    spec.dll_characteristics = PE_DLLCHAR_DYNAMIC_BASE | PE_DLLCHAR_NX_COMPAT;
    spec.entry_point = CALLER_RVA;
    spec.section_count = 2u;
    spec.sections[0].name = ".text";
    spec.sections[0].characteristics =
        PE_SCN_CNT_CODE | PE_SCN_MEM_READ | PE_SCN_MEM_EXECUTE;
    spec.sections[0].data = text;
    spec.sections[0].data_bytes = text_bytes;
    spec.sections[1].name = ".data";
    spec.sections[1].characteristics =
        PE_SCN_CNT_INITIALIZED_DATA | PE_SCN_MEM_READ | PE_SCN_MEM_WRITE;
    spec.sections[1].data = data;
    spec.sections[1].data_bytes = (uint32_t)sizeof(data);
    spec.export_base = 1u;
    spec.export_module_name = "ntdll.dll";
    spec.export_count = 2u;
    spec.exports[0].name = "__wine_syscall_dispatcher";
    spec.exports[0].ordinal = 1u;
    spec.exports[0].rva = SLOT_RVA;
    spec.exports[1].name = "TestEntry";
    spec.exports[1].ordinal = 2u;
    spec.exports[1].rva = CALLER_RVA;
    spec.reloc_count = reloc_count;
    for (uint32_t index = 0; index < reloc_count; ++index)
        spec.relocs[index] = relocs[index];
    return pe_fixture_build(image, sizeof(image), &spec);
}

/* An in-memory file service: nothing touches a real file system. */
typedef struct FakeFile {
    uint64_t size;
    uint8_t bytes[FILE_BYTES];
    uint32_t reads;
    uint32_t closes;
} FakeFile;

static FakeFile *last_open;
static uint32_t open_calls;
static char last_name[PW_WINE_GATE_MAX_PATH + 1];

static PwWineFileStatus fake_open(void *context, const char *name,
                                  uint64_t *size, void **token)
{
    FakeFile *file = context;

    open_calls++;
    memcpy(last_name, name, strlen(name) + 1u);
    if (strcmp(name, "test.dll") != 0)
        return PW_WINE_FILE_NOT_FOUND;
    file->size = FILE_BYTES;
    memcpy(file->bytes, file_contents, FILE_BYTES);
    last_open = file;
    *size = file->size;
    *token = file;
    return PW_WINE_FILE_OK;
}

static PwWineFileStatus fake_read(void *context, void *token, uint64_t offset,
                                  void *bytes, uint32_t size,
                                  uint32_t *read_bytes)
{
    FakeFile *file = token;
    uint32_t available;

    (void)context;
    if (!file)
        return PW_WINE_FILE_ERROR;
    file->reads++;
    if (offset >= file->size) {
        *read_bytes = 0u;
        return PW_WINE_FILE_OK;
    }
    available = (uint32_t)(file->size - offset);
    if (size > available)
        size = available;
    memcpy(bytes, file->bytes + offset, size);
    *read_bytes = size;
    return PW_WINE_FILE_OK;
}

static void fake_close(void *context, void *token)
{
    FakeFile *file = token;

    (void)context;
    if (file)
        file->closes++;
}

static PwFileSpan span;

static int fake_provider_open(void *context, const char *canonical_name,
                              PwFileSpan *out)
{
    (void)context;
    if (!pw_module_name_equal(canonical_name, "ntdll.dll"))
        return PW_ERR_NOT_FOUND;
    *out = span;
    return PW_OK;
}

static void fake_provider_close(void *context, PwFileSpan *closed)
{
    (void)context;
    (void)closed;
}

static int fake_provider_namespace(void *context, PwFileNamespace file_namespace,
                                   const char *canonical_name, PwFileSpan *out)
{
    (void)file_namespace;
    return fake_provider_open(context, canonical_name, out);
}

int main(void)
{
    const PwFileProvider provider = {
        .context = NULL, .open = fake_provider_open,
        .close = fake_provider_close, .open_namespace = fake_provider_namespace,
    };
    PwWineFileService files = {
        .context = NULL, .open = fake_open, .read = fake_read,
        .close = fake_close,
    };
    PwWineGateConfig config;
    PwWineGateReport report;
    PwVmBackend vm;
    const char *modules[] = {"ntdll.dll"};
    FakeFile file;
    const size_t size = build_module();

    assert(size != 0u);
    memset(&file, 0, sizeof(file));
    files.context = &file;
    span.bytes = image;
    span.size = size;
    span.handle = NULL;
    memset(span.path, 0, sizeof(span.path));
    assert(pw_vm_posix_backend(&vm) == PW_OK);

    memset(&config, 0, sizeof(config));
    config.provider = &provider;
    config.backend = &vm;
    config.files = &files;
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntry";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;

    /* The run services the three file calls and then stops somewhere the
     * guest has to deal with; what matters here is what the guest saw. */
    (void)pw_wine_gate_run(&config, &report);
    assert(report.files_configured == 1u);
    assert(report.calls_serviced == 4u);     /* open, read, close, refused open */
    assert(report.file_opens == 1u);
    assert(report.file_reads == 1u);
    assert(report.file_bytes == FILE_BYTES);
    assert(report.file_closes == 1u);
    assert(report.file_refusals == 1u);      /* the escaping path */
    /*
     * The escaping path is refused by the gate's path translation, so the
     * platform service is never asked to open it at all: that is the
     * property under test, not merely that the open failed.
     */
    assert(open_calls == 1u);
    assert(strcmp(last_name, "test.dll") == 0);
    assert(file.reads == 1u && file.closes == 1u);
    assert(report.calls.records >= 4u);
    assert(report.calls.sequence[0].id == 0x0033u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[1].id == 0x0006u);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[2].id == 0x000fu);
    assert(report.calls.sequence[2].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[3].id == 0x0033u);
    assert(report.calls.sequence[3].status == PW_NT_OBJECT_NAME_NOT_FOUND);
    /* Every one of them was a handled call, not a refusal of the bridge. */
    assert(report.calls.handled == 4u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);
    assert(report.last_file[0] != '\0');
    return 0;
}
