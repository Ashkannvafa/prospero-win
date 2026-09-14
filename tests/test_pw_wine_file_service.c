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
#include "../src/pw_wine_runner.h"

#include <assert.h>
#include <string.h>

/* The run's own workspace; two of these are independent. */
static PwWineRunner test_runner;

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
    DIRECTORY_TEXT_RVA = DATA_RVA + 0x1C0,  /* "C:\windows\system32" */
    DIRECTORY_RVA = DATA_RVA + 0x200,       /* its UNICODE_STRING header */
    DIRECTORY_ATTRIBUTES_RVA = DATA_RVA + 0x210,
    DIRECTORY_HANDLE_RVA = DATA_RVA + 0x230,
    DIRECTORY_IO_RVA = DATA_RVA + 0x234,
    INFO_RVA = DATA_RVA + 0x240,            /* FileStandardInformation */
    INFO_IO_RVA = DATA_RVA + 0x260,
    DEVICE_INFO_RVA = DATA_RVA + 0x270,     /* FILE_FS_DEVICE_INFORMATION */
    VOLUME_IO_RVA = DATA_RVA + 0x280,
    VOLUME_RESULT_RVA = DATA_RVA + 0x290,
    FSCTL_IO_RVA = DATA_RVA + 0x2A0,        /* IoStatusBlock of the FSCTL */
    OBJECTID_RVA = DATA_RVA + 0x2B0,        /* FILE_OBJECTID_BUFFER (64) */
    FSCTL_RESULT_RVA = DATA_RVA + 0x300,    /* four FSCTL statuses */
    ID_COPY_RVA = DATA_RVA + 0x310,         /* ObjectId the guest read back */
    FSCTL_LEN_RVA = DATA_RVA + 0x314,       /* Information it read back */
    APPLICATION_TEXT_RVA = DATA_RVA + 0x320, /* "C:\test.dll", UTF-16 */
    APPLICATION_RVA = DATA_RVA + 0x360,     /* its UNICODE_STRING header */
    APPLICATION_ATTRIBUTES_RVA = DATA_RVA + 0x370,
    APPLICATION_HANDLE_RVA = DATA_RVA + 0x390,
    APPLICATION_IO_RVA = DATA_RVA + 0x394,
    APPLICATION_RESULT_RVA = DATA_RVA + 0x398,
    /* The caller's own code runs to roughly 0x200 bytes, so the thunk table
     * starts clear of it: the block below is only reached if the caller's code
     * collides with it, which is not something a fixture should hide. */
    THUNK_RVA = TEXT_RVA + 0x300,
    STUB_OPEN_RVA = TEXT_RVA + 0x310,
    STUB_READ_RVA = TEXT_RVA + 0x320,
    STUB_CLOSE_RVA = TEXT_RVA + 0x330,
    STUB_VOLUME_RVA = TEXT_RVA + 0x340,     /* NtQueryVolumeInformationFile */
    STUB_INFO_RVA = TEXT_RVA + 0x350,       /* NtQueryInformationFile */
    STUB_ATTRS_RVA = TEXT_RVA + 0x360,      /* NtQueryAttributesFile: no handler */
    STUB_FSCTL_RVA = TEXT_RVA + 0x370,      /* NtFsControlFile */
    CALLER_RVA = TEXT_RVA,
    FILE_BYTES = 16,
    FILE_OBJECTID_BYTES = 64u,
    FSCTL_GET_OBJECT_ID = 0x0009009cu,
};

static const uint8_t file_contents[FILE_BYTES] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
};

static uint8_t image[64 * 1024];
static uint8_t text[1024];
static uint32_t text_bytes;
static uint8_t data[0x400];
static PeFixtureReloc relocs[80];
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
    assert(reloc_count < sizeof(relocs) / sizeof(relocs[0]));
    relocs[reloc_count].rva = TEXT_RVA + text_bytes;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
    emit_u32(IMAGE_BASE + rva);
}

/* A pointer stored inside the data section: it needs its own base relocation
 * exactly like the absolute operands the code section emits. */
static void emit_data_reloc(uint32_t rva)
{
    assert(reloc_count < sizeof(relocs) / sizeof(relocs[0]));
    relocs[reloc_count].rva = rva;
    relocs[reloc_count].type = PE_RELOC_HIGHLOW;
    reloc_count++;
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
    put_unicode_string(DIRECTORY_RVA, DIRECTORY_TEXT_RVA,
                       "C:\\windows\\system32");
    /*
     * The same component name, asked for from the other root. The guest names
     * it with a path of its own, so the namespace the service is handed has
     * to come from the path the guest wrote and not from the service.
     */
    put_unicode_string(APPLICATION_RVA, APPLICATION_TEXT_RVA,
                       "C:\\test.dll");
    {
        const uint32_t name_pointer = IMAGE_BASE + NAME_RVA;
        const uint32_t escape_pointer = IMAGE_BASE + ESCAPE_RVA;
        const uint32_t length = 24u;
        const uint32_t application_pointer = IMAGE_BASE + APPLICATION_RVA;

        /* The data array holds one section, so RVA minus its base. */
        memcpy(data + (ATTRIBUTES_RVA - DATA_RVA), &length, 4u);
        memcpy(data + (ATTRIBUTES_RVA - DATA_RVA) + 8u, &name_pointer, 4u);
        memcpy(data + (ESCAPE_ATTRIBUTES_RVA - DATA_RVA), &length, 4u);
        memcpy(data + (ESCAPE_ATTRIBUTES_RVA - DATA_RVA) + 8u,
               &escape_pointer, 4u);
        memcpy(data + (APPLICATION_ATTRIBUTES_RVA - DATA_RVA), &length, 4u);
        memcpy(data + (APPLICATION_ATTRIBUTES_RVA - DATA_RVA) + 8u,
               &application_pointer, 4u);
        {
            const uint32_t directory_pointer = IMAGE_BASE + DIRECTORY_RVA;

            memcpy(data + (DIRECTORY_ATTRIBUTES_RVA - DATA_RVA), &length, 4u);
            memcpy(data + (DIRECTORY_ATTRIBUTES_RVA - DATA_RVA) + 8u,
                   &directory_pointer, 4u);
        }
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

    /*
     * The file's identity, which the loader asks for before it decides
     * whether it has already mapped this file. The id and the length the
     * guest reads back out of its own buffers travel as arguments of calls
     * that are refused before they look at them, so the transcript - not this
     * test - carries what the guest actually saw.
     */
    emit_push_imm8(0x00);                 /* OutputBufferLength slot */
    emit_push_imm32(FILE_OBJECTID_BYTES); /* OutputBuffer length */
    emit_push_absolute(OBJECTID_RVA);     /* OutputBuffer */
    emit_push_imm8(0x00);                 /* InputBufferLength */
    emit_push_imm8(0x00);                 /* InputBuffer */
    emit_push_imm32(FSCTL_GET_OBJECT_ID); /* FsControlCode */
    emit_push_absolute(FSCTL_IO_RVA);     /* IoStatusBlock */
    emit_push_imm8(0x00);                 /* ApcContext */
    emit_push_imm8(0x00);                 /* ApcRoutine */
    emit_push_imm8(0x00);                 /* Event */
    emit_byte(0xa1);                      /* mov eax, [HANDLE_RVA] */
    emit_absolute(HANDLE_RVA);
    emit_byte(0x50);                      /* push eax */
    emit_call(STUB_FSCTL_RVA);
    emit_store_eax(FSCTL_RESULT_RVA);
    emit_byte(0xa1);                      /* the ObjectId the gate wrote */
    emit_absolute(OBJECTID_RVA);
    emit_store_eax(ID_COPY_RVA);
    emit_byte(0xa1);                      /* and the length it reported */
    emit_absolute(FSCTL_IO_RVA + 4u);
    emit_store_eax(FSCTL_LEN_RVA);

    /* A buffer that cannot hold a FILE_OBJECTID_BUFFER. */
    emit_push_imm8(0x00);
    emit_push_imm32(16u);
    emit_push_absolute(OBJECTID_RVA);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm32(FSCTL_GET_OBJECT_ID);
    emit_push_absolute(FSCTL_IO_RVA);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_byte(0xa1);
    emit_absolute(HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_FSCTL_RVA);
    emit_store_eax(FSCTL_RESULT_RVA + 4u);

    /* A control code this bridge does not answer, carrying the id the guest
     * just read as its output buffer. */
    emit_push_imm8(0x00);
    emit_push_imm32(FILE_OBJECTID_BYTES);
    emit_byte(0xa1);                      /* mov eax, [ID_COPY_RVA] */
    emit_absolute(ID_COPY_RVA);
    emit_byte(0x50);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm32(0x0000deadu);         /* FsControlCode: not ours */
    emit_push_absolute(FSCTL_IO_RVA);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_byte(0xa1);
    emit_absolute(HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_FSCTL_RVA);
    emit_store_eax(FSCTL_RESULT_RVA + 8u);

    /* The length the guest read back, as the control code of one more
     * refused call, so the transcript shows the io status it saw. */
    emit_push_imm8(0x00);
    emit_push_imm32(FILE_OBJECTID_BYTES);
    emit_push_absolute(OBJECTID_RVA);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_byte(0xa1);                      /* mov eax, [FSCTL_LEN_RVA] */
    emit_absolute(FSCTL_LEN_RVA);
    emit_byte(0x50);
    emit_push_absolute(FSCTL_IO_RVA);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_byte(0xa1);
    emit_absolute(HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_FSCTL_RVA);
    emit_store_eax(FSCTL_RESULT_RVA + 12u);

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

    /*
     * The Windows directory itself: the open must succeed as a gate-owned
     * object, FileStandardInformation must report Directory = 1, and
     * NtQueryVolumeInformationFile must answer FileFsDeviceInformation
     * without claiming removable media. The two answers are then read back
     * out of the guest buffers and handed to a call with no handler, so the
     * transcript - not this test - shows what the guest actually saw.
     */
    emit_push_imm8(0x00);                 /* OpenOptions */
    emit_push_imm8(0x00);                 /* ShareAccess */
    emit_push_absolute(DIRECTORY_IO_RVA);
    emit_push_absolute(DIRECTORY_ATTRIBUTES_RVA);
    emit_push_imm32(0x00100000u);         /* FILE_READ_DATA */
    emit_push_absolute(DIRECTORY_HANDLE_RVA);
    emit_call(STUB_OPEN_RVA);
    emit_store_eax(VOLUME_RESULT_RVA);

    emit_push_imm8(0x05);                 /* FileStandardInformation */
    emit_push_imm32(24u);                 /* Length */
    emit_push_absolute(INFO_RVA);         /* FileInformation */
    emit_push_absolute(INFO_IO_RVA);      /* IoStatusBlock */
    emit_byte(0xa1);                      /* mov eax, [DIRECTORY_HANDLE_RVA] */
    emit_absolute(DIRECTORY_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_INFO_RVA);

    emit_push_imm8(0x04);                 /* FileFsDeviceInformation */
    emit_push_imm32(8u);                  /* Length */
    emit_push_absolute(DEVICE_INFO_RVA);  /* FsInformation */
    emit_push_absolute(VOLUME_IO_RVA);    /* IoStatusBlock */
    emit_byte(0xa1);                      /* mov eax, [DIRECTORY_HANDLE_RVA] */
    emit_absolute(DIRECTORY_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_VOLUME_RVA);
    emit_store_eax(VOLUME_RESULT_RVA + 4u);

    emit_byte(0xa1);                      /* mov eax, [DIRECTORY_HANDLE_RVA] */
    emit_absolute(DIRECTORY_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);
    emit_store_eax(VOLUME_RESULT_RVA + 8u);

    /*
     * The application's own directory: the same component name the service
     * already answered from the runtime's root, now named on a path the guest
     * wrote as "C:\test.dll". What the service is asked for is a pair - the
     * canonical name and the root it belongs to - so a run that lost the
     * namespace would open the runtime's file here instead.
     */
    emit_push_imm8(0x00);                 /* OpenOptions */
    emit_push_imm8(0x00);                 /* ShareAccess */
    emit_push_absolute(APPLICATION_IO_RVA);
    emit_push_absolute(APPLICATION_ATTRIBUTES_RVA);
    emit_push_imm32(0x00100000u);         /* FILE_READ_DATA */
    emit_push_absolute(APPLICATION_HANDLE_RVA);
    emit_call(STUB_OPEN_RVA);
    emit_store_eax(APPLICATION_RESULT_RVA);

    emit_byte(0xa1);                      /* mov eax, [APPLICATION_HANDLE] */
    emit_absolute(APPLICATION_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);
    emit_store_eax(APPLICATION_RESULT_RVA + 4u);

    emit_byte(0xa1);                      /* mov eax, [DEVICE_INFO_RVA] */
    emit_absolute(DEVICE_INFO_RVA);
    emit_byte(0x50);                      /* push DeviceType (second arg) */
    emit_byte(0x0f);emit_byte(0xb6);emit_byte(0x05);
    emit_absolute(INFO_RVA + 21u);        /* movzx eax, byte [Info+21] */
    emit_byte(0x50);                      /* push Directory (first arg) */
    emit_call(STUB_ATTRS_RVA);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_OPEN_RVA, 0x0033u, 24u);     /* NtOpenFile */
    emit_stub(STUB_READ_RVA, 0x0006u, 36u);     /* NtReadFile */
    emit_stub(STUB_CLOSE_RVA, 0x000fu, 4u);     /* NtClose */
    emit_stub(STUB_VOLUME_RVA, 0x0049u, 20u);   /* NtQueryVolumeInformationFile */
    emit_stub(STUB_INFO_RVA, 0x0011u, 20u);     /* NtQueryInformationFile */
    emit_stub(STUB_ATTRS_RVA, 0x003du, 8u);     /* NtQueryAttributesFile */
    emit_stub(STUB_FSCTL_RVA, 0x0039u, 40u);    /* NtFsControlFile */
    emit_byte(0xc3);

    /*
     * The pointers stored inside the data section need their own base
     * relocations, exactly like a real image: without them the guest would
     * hand the gate a preferred-base address that is not mapped.
     */
    emit_data_reloc(NAME_RVA + 4u);
    emit_data_reloc(ATTRIBUTES_RVA + 8u);
    emit_data_reloc(ESCAPE_RVA + 4u);
    emit_data_reloc(ESCAPE_ATTRIBUTES_RVA + 8u);
    emit_data_reloc(DIRECTORY_RVA + 4u);
    emit_data_reloc(DIRECTORY_ATTRIBUTES_RVA + 8u);
    emit_data_reloc(APPLICATION_RVA + 4u);
    emit_data_reloc(APPLICATION_ATTRIBUTES_RVA + 8u);

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
/* The namespace each open named: the service never decides it for itself. */
static PwFileNamespace open_namespaces[4];

static PwWineFileStatus fake_open(void *context, PwFileNamespace file_namespace,
                                  const char *name, uint64_t *size,
                                  void **token)
{
    FakeFile *file = context;

    open_calls++;
    if (open_calls <= sizeof(open_namespaces) / sizeof(open_namespaces[0]))
        open_namespaces[open_calls - 1u] = file_namespace;
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
    pw_wine_runner_init(&test_runner);
    config.runner = &test_runner;
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
    /* open, read, four NtFsControlFile calls, close, refused open, directory
     * open, directory query, directory volume query, directory close, then the
     * application's own open and its close */
    assert(report.calls_serviced == 14u);
    /* the runtime DLL, the directory, and the application's file */
    assert(report.file_opens == 3u);
    assert(report.file_directories == 1u);
    assert(report.file_reads == 1u);
    assert(report.file_bytes == FILE_BYTES);
    /* Every handle was closed by the guest, so cleanup released none. */
    assert(report.file_closes == 3u);
    assert(report.file_handles == 0u);
    /* The escaping path, the FSCTL with a buffer that cannot hold the answer,
     * and the two FSCTL calls with control codes this bridge does not answer. */
    assert(report.file_refusals == 4u);
    /*
     * The escaping path is refused by the gate's path translation, so the
     * platform service is never asked to open it at all: that is the
     * property under test, not merely that the open failed.
     */
    /*
     * The two opens the service answered, and the root each one belongs to:
     * "C:\windows\system32\test.dll" is the runtime distribution's file and
     * "C:\test.dll" is the application's own, so the first is asked for in
     * PW_FILE_RUNTIME and the second in PW_FILE_APPLICATION. A run that lost
     * the namespace would ask the runtime's root twice, and one that fell back
     * would ask the application's twice.
     */
    assert(open_calls == 2u);
    assert(strcmp(last_name, "test.dll") == 0);
    assert(open_namespaces[0] == PW_FILE_RUNTIME);
    assert(open_namespaces[1] == PW_FILE_APPLICATION);
    assert(file.reads == 1u && file.closes == 2u);
    assert(report.calls.records >= 4u);
    assert(report.calls.sequence[0].id == 0x0033u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[1].id == 0x0006u);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    {
        uint32_t closes = 0u, refused_opens = 0u;

        for (uint32_t index = 0; index < report.calls.records; ++index) {
            const PwUnixCallRecord *record = &report.calls.sequence[index];

            if (record->id == 0x000fu && record->status == PW_NT_SUCCESS)
                closes++;
            if (record->id == 0x0033u &&
                record->status == PW_NT_OBJECT_NAME_NOT_FOUND)
                refused_opens++;
        }
        /* One close each for the DLL, the directory and the application's. */
        assert(closes == 3u);
        assert(refused_opens == 1u);
    }
    /*
     * The file's identity. The id the gate answers with is a function of the
     * canonical name the service resolved - here "test.dll" - so two handles
     * to the same file answer with the same id, which is the property the
     * loader's deduplication compares. The statuses are the four shapes the
     * call can take, and the last two records carry the id and the length the
     * guest read out of its own buffer, so the answer can only be right if it
     * really landed in guest memory.
     */
    {
        PwSha256 hash;
        uint8_t digest[PW_SHA256_BYTES];
        uint32_t expected_id = 0u;
        const PwUnixCallRecord *fsctl[4];
        uint32_t found = 0u;

        pw_sha256_init(&hash);
        pw_sha256_update(&hash, "test.dll", strlen("test.dll"));
        pw_sha256_final(&hash, digest);
        memcpy(&expected_id, digest, 4u);
        for (uint32_t index = 0; index < report.calls.records; ++index) {
            const PwUnixCallRecord *record = &report.calls.sequence[index];

            if (record->id != 0x0039u)
                continue;
            assert(found < 4u);
            fsctl[found++] = record;
        }
        assert(found == 4u);
        assert(report.file_fs_controls == 1u);
        assert(fsctl[0]->status == PW_NT_SUCCESS);
        assert(fsctl[1]->status == PW_NT_BUFFER_TOO_SMALL);
        assert(fsctl[2]->status == PW_NT_INVALID_DEVICE_REQUEST);
        assert(fsctl[3]->status == PW_NT_INVALID_DEVICE_REQUEST);
        assert(fsctl[0]->args[5] == FSCTL_GET_OBJECT_ID);
        assert(fsctl[2]->args[8] == expected_id);   /* read by the guest */
        assert(fsctl[3]->args[5] == FILE_OBJECTID_BYTES);
    }
    /* Every one of them was a handled call, not a refusal of the bridge. */
    /*
     * The directory case: NtOpenFile("C:\windows\system32") succeeds as a
     * gate-owned directory object, FileStandardInformation reports
     * Directory = 1 and NtQueryVolumeInformationFile answers
     * FileFsDeviceInformation. The guest reads both answers back and passes
     * them to a call with no handler, so the recorded arguments are the
     * values the guest actually loaded out of its own buffers.
     */
    {
        uint32_t directory_queries = 0u;
        uint32_t volume_queries = 0u;
        const PwUnixCallRecord *last = NULL;

        for (uint32_t index = 0; index < report.calls.records; ++index) {
            const PwUnixCallRecord *record = &report.calls.sequence[index];

            if (record->id == 0x0011u && record->status == PW_NT_SUCCESS)
                directory_queries++;
            if (record->id == 0x0049u && record->status == PW_NT_SUCCESS)
                volume_queries++;
            last = record;
        }
        assert(directory_queries == 1u);
        assert(volume_queries == 1u);
        assert(last != NULL && last->id == 0x003du);
        assert(last->outcome == PW_UNIX_CALL_UNIMPLEMENTED);
        assert(last->args[0] == 1u);        /* Directory = 1, read by the guest */
        assert(last->args[1] == 8u);        /* FILE_DEVICE_DISK_FILE_SYSTEM */
    }
    assert(report.calls.handled >= 6u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);
    assert(report.last_file[0] != '\0');
    return 0;
}
