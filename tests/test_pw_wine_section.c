/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the image-section service behind the Unix-call
 * bridge.
 *
 * One synthetic module plays the part of ntdll's own loader: it opens a file
 * through the runtime namespace, creates a SEC_IMAGE section over that file
 * handle, asks the section what image it holds - which is the question
 * is_valid_binary answers - then closes the file handle and asks again, because
 * that is what the loader does: the section, not the file handle, is what a
 * view is mapped from (dlls/ntdll/loader.c:2696-2745).
 *
 * The values the guest reads out of the answers travel as arguments of calls
 * that are refused before they look at them, so the transcript carries what the
 * guest actually saw rather than what this test hopes it saw.
 */
#include "pe_fixture.h"

#include "../src/pe_image.h"
#include "../src/pw_module_name.h"
#include "../src/pw_vm_posix.h"
#include "../src/pw_wine_gate.h"
#include "../src/pw_wine_runner.h"
#include "../src/pw_wine_section.h"

#include <assert.h>
#include <string.h>

/* The run's own workspace; two of these are independent. */
static PwWineRunner test_runner;

enum {
    TEXT_RVA = 0x1000,
    DATA_RVA = 0x2000,
    IMAGE_BASE = 0x11000000,
    SLOT_RVA = DATA_RVA,                    /* __wine_syscall_dispatcher */
    NAME_RVA = DATA_RVA + 0x100,            /* UNICODE_STRING of the file */
    NAME_TEXT_RVA = DATA_RVA + 0x110,
    ATTRS_RVA = DATA_RVA + 0x150,           /* OBJECT_ATTRIBUTES */
    FILE_IO_RVA = DATA_RVA + 0x170,
    FILE_HANDLE_RVA = DATA_RVA + 0x180,
    MAXSIZE_RVA = DATA_RVA + 0x188,         /* LARGE_INTEGER: no explicit size */
    SECTION_HANDLE_RVA = DATA_RVA + 0x190,
    IMAGE_INFO_RVA = DATA_RVA + 0x1A0,      /* SECTION_IMAGE_INFORMATION */
    BASIC_INFO_RVA = DATA_RVA + 0x1E0,      /* SECTION_BASIC_INFORMATION */
    STATUS_RVA = DATA_RVA + 0x200,          /* eleven statuses */
    MACHINE_COPY_RVA = DATA_RVA + 0x238,    /* Machine the guest read */
    FILESIZE_COPY_RVA = DATA_RVA + 0x23C,   /* ImageFileSize it read */
    SIZE_COPY_RVA = DATA_RVA + 0x240,       /* BasicInformation.Size */
    VIEW_BASE_RVA = DATA_RVA + 0x244,       /* the base the view was mapped at */
    VIEW_SIZE_RVA = DATA_RVA + 0x248,       /* the view size it reported */
    MAPPED_HEAD_RVA = DATA_RVA + 0x24C,     /* the image's first bytes, read at
                                             * the base the gate returned */
    PROTECT_BASE_RVA = DATA_RVA + 0x250,    /* the range NtProtectVirtualMemory
                                             * is called on */
    PROTECT_SIZE_RVA = DATA_RVA + 0x254,
    OLD_PROTECT_RVA = DATA_RVA + 0x258,     /* what it reports back */
    OLD_FIRST_RVA = DATA_RVA + 0x25C,       /* the first one, kept for the
                                             * transcript */
    MARKER_RVA = DATA_RVA + 0x260,          /* what the guest wrote and read */
    PROTECT_STATUS_RVA = DATA_RVA + 0x400,  /* the four protect/query statuses */
    NLS_PTR_RVA = DATA_RVA + 0x420,         /* NtInitializeNlsFiles outputs */
    NLS_LCID_RVA = DATA_RVA + 0x424,
    NLS_SIZE_RVA = DATA_RVA + 0x428,        /* LARGE_INTEGER */
    NLS_STATUS_RVA = DATA_RVA + 0x430,
    NLS_LCID_COPY_RVA = DATA_RVA + 0x434,
    NLS_HEAD_RVA = DATA_RVA + 0x438,        /* the file's first dword, as read */
    LOCALE_LANGID_RVA = DATA_RVA + 0x440,   /* NtQueryDefaultUILanguage */
    LOCALE_LCID_RVA = DATA_RVA + 0x444,     /* NtQueryDefaultLocale */
    LOCALE_INSTALL_RVA = DATA_RVA + 0x448,  /* NtQueryInstallUILanguage */
    LOCALE_PTR_RVA = DATA_RVA + 0x44C,      /* NtGetNlsSectionPtr outputs */
    LOCALE_SIZE_RVA = DATA_RVA + 0x450,
    LOCALE_STATUS_RVA = DATA_RVA + 0x460,   /* five statuses */
    LOCALE_HEAD_RVA = DATA_RVA + 0x474,
    DIRECTORY_RVA = DATA_RVA + 0x280,       /* UNICODE_STRING of a directory */
    DIRECTORY_TEXT_RVA = DATA_RVA + 0x290,
    DIRECTORY_ATTRS_RVA = DATA_RVA + 0x2D0,
    DIRECTORY_HANDLE_RVA = DATA_RVA + 0x2F0,
    /* The caller's own code runs up to here; the thunk table and the stubs
     * live past it, so a caller that grew into them would be a fixture that no
     * longer proves what it says. */
    THUNK_RVA = TEXT_RVA + 0x400,
    STUB_OPEN_RVA = TEXT_RVA + 0x410,       /* NtOpenFile, 0x33 */
    STUB_CREATE_RVA = TEXT_RVA + 0x420,     /* NtCreateSection, 0x4a */
    STUB_QUERY_RVA = TEXT_RVA + 0x430,      /* NtQuerySection, 0x51 */
    STUB_CLOSE_RVA = TEXT_RVA + 0x440,      /* NtClose, 0x0f */
    STUB_ATTRS_RVA = TEXT_RVA + 0x450,      /* NtQueryAttributesFile: none */
    STUB_MAP_RVA = TEXT_RVA + 0x460,        /* NtMapViewOfSection, 0x28 */
    STUB_PROTECT_RVA = TEXT_RVA + 0x470,    /* NtProtectVirtualMemory, 0x50 */
    STUB_NLS_RVA = TEXT_RVA + 0x480,        /* NtInitializeNlsFiles, 0xa4 */
    STUB_LANGID_RVA = TEXT_RVA + 0x490,     /* NtQueryDefaultUILanguage, 0x44 */
    STUB_LCID_RVA = TEXT_RVA + 0x4A0,       /* NtQueryDefaultLocale, 0x15 */
    STUB_INSTALL_RVA = TEXT_RVA + 0x4B0,    /* NtQueryInstallUILanguage, 0xc7 */
    STUB_NLSSEC_RVA = TEXT_RVA + 0x4C0,     /* NtGetNlsSectionPtr, 0xa1 */
    CALLER_RVA = TEXT_RVA,
    /* The shapes and classes the guest asks with. */
    SECTION_IMAGE_INFORMATION = 1u,
    SECTION_BASIC_INFORMATION = 0u,
    UNKNOWN_INFORMATION_CLASS = 9u,
    /* Wine's NLS section types (dlls/ntdll/locale_private.h:52). */
    NLS_CASEMAP = 10u,
    IMAGE_INFORMATION_BYTES = 48u,
    SHORT_BUFFER_BYTES = 32u,
    BASIC_INFORMATION_BYTES = 12u,
    SEC_IMAGE = 0x01000000u,
    SEC_COMMIT = 0x08000000u,
    PAGE_EXECUTE_READ = 0x20u,
    PAGE_READWRITE = 0x04u,
    PAGE_READONLY = 0x02u,
    VIEW_PAGE_BYTES = 0x1000u,
    MARKER_WRITTEN = 0x5a5a5a5au,
    MARKER_REFUSED = 0x11111111u,
    SECTION_ALL_ACCESS = 0x000f000du,
    FILE_READ_DATA = 0x00100000u,
    CURRENTLY_OPEN_FILE = 0x100u,           /* not a handle this run issued */
};

static uint8_t image[64 * 1024];
static uint8_t text[2048];
static uint32_t text_bytes;
static uint8_t data[0x800];
static PeFixtureReloc relocs[128];
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

static void emit_load_eax(uint32_t rva)
{
    emit_byte(0xa1);
    emit_absolute(rva);
}

static void emit_store_eax(uint32_t rva)
{
    emit_byte(0xa3);
    emit_absolute(rva);
}

static void emit_push_eax(void)
{
    emit_byte(0x50);
}

/* "mov dword [abs], imm32" */
static void emit_store_imm32(uint32_t rva, uint32_t value)
{
    emit_byte(0xc7); emit_byte(0x05);
    emit_absolute(rva);
    emit_u32(value);
}

/* "add eax, imm32" */
static void emit_add_eax_imm32(uint32_t value)
{
    emit_byte(0x05);
    emit_u32(value);
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

/* NtOpenFile(name, FILE_READ_DATA, attributes, io, 0, 0) into a handle. */
static void emit_open(uint32_t attributes_rva, uint32_t handle_rva,
                      uint32_t io_rva, uint32_t status_rva)
{
    emit_push_imm8(0x00);                 /* OpenOptions */
    emit_push_imm8(0x00);                 /* ShareAccess */
    emit_push_absolute(io_rva);           /* IoStatusBlock */
    emit_push_absolute(attributes_rva);   /* ObjectAttributes */
    emit_push_imm32(FILE_READ_DATA);      /* DesiredAccess */
    emit_push_absolute(handle_rva);       /* FileHandle */
    emit_call(STUB_OPEN_RVA);
    emit_store_eax(status_rva);
}

/* NtCreateSection over a file handle, with the shape under test. */
static void emit_create(uint32_t file_handle_rva, uint32_t section_handle_rva,
                        uint32_t allocation_attributes, uint32_t status_rva)
{
    emit_byte(0xa1);                      /* mov eax, [file handle] */
    emit_absolute(file_handle_rva);
    emit_push_eax();                      /* FileHandle */
    emit_push_imm32(allocation_attributes);/* AllocationAttributes */
    emit_push_imm32(PAGE_EXECUTE_READ);   /* PageProtection */
    emit_push_absolute(MAXSIZE_RVA);      /* MaximumSize */
    emit_push_imm8(0x00);                 /* ObjectAttributes: unnamed */
    emit_push_imm32(SECTION_ALL_ACCESS);  /* DesiredAccess */
    emit_push_absolute(section_handle_rva);
    emit_call(STUB_CREATE_RVA);
    emit_store_eax(status_rva);
}

/* NtQuerySection(section, class, buffer, length, NULL) with the section handle
 * taken from a slot. */
/* NtMapViewOfSection(section, -1, &base, 0, 0, NULL, &size, ViewShare, 0,
 * PAGE_EXECUTE_READ), which is the shape the loader asks with. */
static void emit_map_view(uint32_t section_handle_rva, uint32_t status_rva)
{
    emit_push_imm32(PAGE_EXECUTE_READ);       /* Win32Protect */
    emit_push_imm8(0x00);                     /* AllocationType */
    emit_push_imm8(0x01);                     /* InheritDisposition: ViewShare */
    emit_push_absolute(VIEW_SIZE_RVA);        /* ViewSize */
    emit_push_imm8(0x00);                     /* SectionOffset */
    emit_push_imm8(0x00);                     /* CommitSize */
    emit_push_imm8(0x00);                     /* ZeroBits */
    emit_push_absolute(VIEW_BASE_RVA);        /* BaseAddress */
    emit_push_imm8(0xff);                     /* this process */
    emit_load_eax(section_handle_rva);
    emit_push_eax();
    emit_call(STUB_MAP_RVA);
    emit_store_eax(status_rva);
}

static void emit_query(uint32_t section_handle_rva, uint32_t class_id,
                       uint32_t buffer_rva, uint32_t length, uint32_t status_rva)
{
    emit_push_imm8(0x00);                 /* ReturnLength: not wanted */
    emit_push_imm32(length);
    emit_push_absolute(buffer_rva);
    emit_push_imm8((uint8_t)class_id);
    emit_load_eax(section_handle_rva);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(status_rva);
}

static size_t build_module(void)
{
    PeFixtureSpec spec;
    /*
     * The module's file is the application's own, named as a component of C:.
     * That is the path whose namespace has to survive from the open to the
     * mapping: the view is mapped from a section that re-opens the file by the
     * pair (name, root), because the loader has closed its own file handle by
     * then. A run that lost the root asked the runtime for an application
     * module, and the loader ended with STATUS_DLL_NOT_FOUND.
     */
    static const char file_path[] = "C:\\test.dll";
    static const char directory[] = "C:\\windows\\system32";

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));

    /* The two names, their UNICODE_STRING headers and the attributes. */
    {
        /* The attributes name the UNICODE_STRING headers; those headers point
         * at the text that follows them. */
        const uint32_t name_header = IMAGE_BASE + NAME_RVA;
        const uint32_t name_text = IMAGE_BASE + NAME_TEXT_RVA;
        const uint32_t directory_header = IMAGE_BASE + DIRECTORY_RVA;
        const uint32_t directory_text = IMAGE_BASE + DIRECTORY_TEXT_RVA;
        const uint32_t length = (uint32_t)(strlen(file_path) * 2u);
        const uint32_t directory_length = (uint32_t)(strlen(directory) * 2u);

        for (uint32_t index = 0u; index <= strlen(file_path); ++index)
            data[(NAME_TEXT_RVA - DATA_RVA) + index * 2u] =
                (uint8_t)file_path[index];
        for (uint32_t index = 0u; index <= strlen(directory); ++index)
            data[(DIRECTORY_TEXT_RVA - DATA_RVA) + index * 2u] =
                (uint8_t)directory[index];
        memcpy(data + (NAME_RVA - DATA_RVA), &length, 2u);
        memcpy(data + (NAME_RVA - DATA_RVA) + 2u, &length, 2u);
        memcpy(data + (NAME_RVA - DATA_RVA) + 4u, &name_text, 4u);
        memcpy(data + (DIRECTORY_RVA - DATA_RVA), &directory_length, 2u);
        memcpy(data + (DIRECTORY_RVA - DATA_RVA) + 2u, &directory_length, 2u);
        memcpy(data + (DIRECTORY_RVA - DATA_RVA) + 4u, &directory_text, 4u);
        memcpy(data + (ATTRS_RVA - DATA_RVA), &(uint32_t){ 24u }, 4u);
        memcpy(data + (ATTRS_RVA - DATA_RVA) + 8u, &name_header, 4u);
        memcpy(data + (DIRECTORY_ATTRS_RVA - DATA_RVA), &(uint32_t){ 24u }, 4u);
        memcpy(data + (DIRECTORY_ATTRS_RVA - DATA_RVA) + 8u,
               &directory_header, 4u);
    }

    /* The guest: open, create, ask, ask again after the file handle is gone. */
    emit_open(ATTRS_RVA, FILE_HANDLE_RVA, FILE_IO_RVA, STATUS_RVA + 0u);
    emit_create(FILE_HANDLE_RVA, SECTION_HANDLE_RVA, SEC_IMAGE, STATUS_RVA + 4u);
    emit_query(SECTION_HANDLE_RVA, SECTION_IMAGE_INFORMATION, IMAGE_INFO_RVA,
               IMAGE_INFORMATION_BYTES, STATUS_RVA + 8u);
    emit_byte(0x0f); emit_byte(0xb7); emit_byte(0x05);   /* movzx eax, word */
    emit_absolute(IMAGE_INFO_RVA + 32u);                 /* [Machine] */
    emit_store_eax(MACHINE_COPY_RVA);
    emit_load_eax(IMAGE_INFO_RVA + 40u);      /* ImageFileSize */
    emit_store_eax(FILESIZE_COPY_RVA);
    /* A buffer that cannot hold the answer. */
    emit_query(SECTION_HANDLE_RVA, SECTION_IMAGE_INFORMATION, IMAGE_INFO_RVA,
               SHORT_BUFFER_BYTES, STATUS_RVA + 12u);
    /* A class no section answers. */
    emit_query(SECTION_HANDLE_RVA, UNKNOWN_INFORMATION_CLASS, IMAGE_INFO_RVA,
               IMAGE_INFORMATION_BYTES, STATUS_RVA + 16u);
    /* The basic information, which the guest reads the size out of. */
    emit_query(SECTION_HANDLE_RVA, SECTION_BASIC_INFORMATION, BASIC_INFO_RVA,
               BASIC_INFORMATION_BYTES, STATUS_RVA + 20u);
    emit_load_eax(BASIC_INFO_RVA + 8u);       /* Size */
    emit_store_eax(SIZE_COPY_RVA);
    /* A data section, which this bridge does not serve. */
    emit_create(FILE_HANDLE_RVA, SECTION_HANDLE_RVA, SEC_COMMIT,
                STATUS_RVA + 24u);
    /* A directory is not a file object to make a section from. */
    emit_open(DIRECTORY_ATTRS_RVA, DIRECTORY_HANDLE_RVA, FILE_IO_RVA,
              STATUS_RVA + 28u);
    emit_create(DIRECTORY_HANDLE_RVA, SECTION_HANDLE_RVA, SEC_IMAGE,
                STATUS_RVA + 32u);
    /* Now close the file handle and ask the section again: what a view is
     * mapped from is the section, not the handle it was created from. */
    emit_load_eax(FILE_HANDLE_RVA);
    emit_push_eax();
    emit_call(STUB_CLOSE_RVA);
    emit_store_eax(STATUS_RVA + 36u);
    emit_query(SECTION_HANDLE_RVA, SECTION_IMAGE_INFORMATION, IMAGE_INFO_RVA,
               IMAGE_INFORMATION_BYTES, STATUS_RVA + 40u);
    /* A handle that is not a section: the size the guest read, so the
     * transcript shows the value it saw. */
    emit_load_eax(SIZE_COPY_RVA);
    emit_push_imm8(0x00);                     /* ReturnLength */
    emit_push_imm32(IMAGE_INFORMATION_BYTES);
    emit_push_absolute(IMAGE_INFO_RVA);
    emit_push_imm8((uint8_t)SECTION_IMAGE_INFORMATION);
    emit_push_eax();                          /* the value as a handle */
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(STATUS_RVA + 44u);
    /*
     * The view: mapped where this run can place it, holding the image the file
     * holds. The guest reads the image's first bytes *at the base the gate
     * returned*, so the transcript carries proof that the mapping is the file.
     */
    emit_map_view(SECTION_HANDLE_RVA, STATUS_RVA + 48u);
    emit_load_eax(VIEW_BASE_RVA);
    emit_byte(0x8b); emit_byte(0x00);         /* mov eax, [eax] */
    emit_store_eax(MAPPED_HEAD_RVA);
    /* The view size the guest read, and the image's own first bytes read at the
     * base the gate returned, on a query refused before it looks at either. */
    emit_load_eax(MAPPED_HEAD_RVA);
    emit_push_eax();
    emit_load_eax(VIEW_SIZE_RVA);
    emit_push_eax();
    emit_push_imm8((uint8_t)UNKNOWN_INFORMATION_CLASS);
    emit_load_eax(SECTION_HANDLE_RVA);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(STATUS_RVA + 52u);
    /*
     * The protection a loader changes while it relocates: the range it mapped
     * goes writable, the guest writes through it and reads its own write back,
     * and then the original protection goes on again. The two old protections
     * the gate reports are carried out by later calls, and the run ends on the
     * write that must now be refused - the page is read-only again, on the host
     * mapping and in the dispatcher's view of it at once.
     */
    emit_store_imm32(PROTECT_SIZE_RVA, VIEW_PAGE_BYTES);
    emit_load_eax(VIEW_BASE_RVA);
    emit_add_eax_imm32(VIEW_PAGE_BYTES);
    emit_store_eax(PROTECT_BASE_RVA);
    emit_push_absolute(OLD_PROTECT_RVA);
    emit_push_imm8(PAGE_READWRITE);
    emit_push_absolute(PROTECT_SIZE_RVA);
    emit_push_absolute(PROTECT_BASE_RVA);
    emit_push_imm8(0xff);
    emit_call(STUB_PROTECT_RVA);
    emit_store_eax(PROTECT_STATUS_RVA + 0u);
    emit_load_eax(OLD_PROTECT_RVA);
    emit_store_eax(OLD_FIRST_RVA);
    /* Through the new writable page: write, then read the same place back. */
    emit_load_eax(PROTECT_BASE_RVA);
    emit_byte(0xc7); emit_byte(0x00);             /* mov dword [eax], imm32 */
    emit_u32(MARKER_WRITTEN);
    emit_byte(0x8b); emit_byte(0x00);             /* mov eax, [eax] */
    emit_store_eax(MARKER_RVA);
    /* Put the loader's protection back. */
    emit_push_absolute(OLD_PROTECT_RVA);
    emit_push_imm8(PAGE_EXECUTE_READ);
    emit_push_absolute(PROTECT_SIZE_RVA);
    emit_push_absolute(PROTECT_BASE_RVA);
    emit_push_imm8(0xff);
    emit_call(STUB_PROTECT_RVA);
    emit_store_eax(PROTECT_STATUS_RVA + 4u);
    /* Carry the marker and the first old protection out on a refused class. */
    emit_load_eax(OLD_FIRST_RVA);
    emit_push_eax();                              /* length argument */
    emit_load_eax(MARKER_RVA);
    emit_push_eax();                              /* information pointer */
    emit_push_imm8((uint8_t)UNKNOWN_INFORMATION_CLASS);
    emit_load_eax(SECTION_HANDLE_RVA);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(PROTECT_STATUS_RVA + 8u);
    /* And the second old protection, which must say the first one took, with
     * the base the view was mapped at beside it. */
    emit_load_eax(VIEW_BASE_RVA);
    emit_push_eax();
    emit_load_eax(OLD_PROTECT_RVA);
    emit_push_eax();
    emit_push_imm8((uint8_t)UNKNOWN_INFORMATION_CLASS);
    emit_load_eax(SECTION_HANDLE_RVA);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(PROTECT_STATUS_RVA + 12u);
    /*
     * ntdll's NLS initialization: the runtime namespace is asked for its own
     * locale.nls the way Wine asks, and the file service here does carry it, so
     * the answer is the mapping itself: the address of the file's own bytes,
     * the mapping's size and the system language id. The guest reads the first
     * dword through the address it was given - which can only be the file's
     * bytes if the mapping really landed in its own memory - and carries both
     * that value and the language id out below.
     */
    emit_push_absolute(NLS_SIZE_RVA);
    emit_push_absolute(NLS_LCID_RVA);
    emit_push_absolute(NLS_PTR_RVA);
    emit_call(STUB_NLS_RVA);
    emit_store_eax(NLS_STATUS_RVA);
    emit_load_eax(NLS_LCID_RVA);
    emit_store_eax(NLS_LCID_COPY_RVA);
    emit_load_eax(NLS_PTR_RVA);
    emit_byte(0x8b); emit_byte(0x00);             /* mov eax, [eax] */
    emit_store_eax(NLS_HEAD_RVA);
    emit_push_imm8(0x00);                         /* ReturnLength: not wanted */
    emit_load_eax(NLS_LCID_COPY_RVA);
    emit_push_eax();                              /* length argument */
    emit_load_eax(NLS_PTR_RVA);
    emit_push_eax();                              /* information pointer: the base */
    emit_push_imm8((uint8_t)UNKNOWN_INFORMATION_CLASS);
    emit_load_eax(SECTION_HANDLE_RVA);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(NLS_STATUS_RVA + 4u);
    emit_push_imm8(0x00);                         /* ReturnLength: not wanted */
    emit_load_eax(NLS_HEAD_RVA);
    emit_push_eax();                              /* length: the first dword */
    emit_push_absolute(NLS_SIZE_RVA);             /* information pointer: the size */
    emit_push_imm8((uint8_t)UNKNOWN_INFORMATION_CLASS);
    emit_load_eax(SECTION_HANDLE_RVA);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(NLS_STATUS_RVA + 8u);

    /*
     * The locale questions and the case-map section. This run models one
     * locale, so all three questions answer with the same language id the NLS
     * mapping reports, and NtGetNlsSectionPtr maps the case map's own file
     * (type 10, l_intl.nls) the way it maps locale.nls. The guest reads the
     * mapped file's first dword through the address it was given, and its
     * language id travels out through the refused query below.
     */
    emit_push_absolute(LOCALE_LANGID_RVA);
    emit_call(STUB_LANGID_RVA);
    emit_store_eax(LOCALE_STATUS_RVA);
    emit_push_absolute(LOCALE_LCID_RVA);
    emit_push_imm8(1);                            /* the user's locale */
    emit_call(STUB_LCID_RVA);
    emit_store_eax(LOCALE_STATUS_RVA + 4u);
    emit_push_absolute(LOCALE_INSTALL_RVA);
    emit_call(STUB_INSTALL_RVA);
    emit_store_eax(LOCALE_STATUS_RVA + 8u);
    emit_push_absolute(LOCALE_SIZE_RVA);
    emit_push_absolute(LOCALE_PTR_RVA);
    emit_push_imm8(0);                            /* unknown */
    emit_push_imm8(0);                            /* id: the case map has one */
    emit_push_imm8((uint8_t)NLS_CASEMAP);         /* type 10 */
    emit_call(STUB_NLSSEC_RVA);
    emit_store_eax(LOCALE_STATUS_RVA + 12u);
    emit_load_eax(LOCALE_PTR_RVA);
    emit_byte(0x8b); emit_byte(0x00);             /* mov eax, [eax] */
    emit_store_eax(LOCALE_HEAD_RVA);
    emit_push_imm8(0x00);                         /* ReturnLength */
    emit_load_eax(LOCALE_HEAD_RVA);
    emit_push_eax();                              /* length: the first dword */
    emit_push_absolute(LOCALE_PTR_RVA);
    emit_push_imm8((uint8_t)UNKNOWN_INFORMATION_CLASS);
    emit_load_eax(SECTION_HANDLE_RVA);
    emit_push_eax();
    emit_call(STUB_QUERY_RVA);
    emit_store_eax(LOCALE_STATUS_RVA + 16u);

    /* The write that must now be refused: the page is read-only again. */
    emit_load_eax(PROTECT_BASE_RVA);
    emit_byte(0xc7); emit_byte(0x00);             /* mov dword [eax], imm32 */
    emit_u32(MARKER_REFUSED);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_OPEN_RVA, 0x0033u, 24u);     /* NtOpenFile */
    emit_stub(STUB_CREATE_RVA, 0x004au, 28u);   /* NtCreateSection */
    emit_stub(STUB_QUERY_RVA, 0x0051u, 20u);    /* NtQuerySection */
    emit_stub(STUB_CLOSE_RVA, 0x000fu, 4u);     /* NtClose */
    emit_stub(STUB_ATTRS_RVA, 0x003du, 8u);     /* NtQueryAttributesFile */
    emit_stub(STUB_MAP_RVA, 0x0028u, 40u);      /* NtMapViewOfSection */
    emit_stub(STUB_PROTECT_RVA, 0x0050u, 20u);  /* NtProtectVirtualMemory */
    emit_stub(STUB_NLS_RVA, 0x00a4u, 12u);
    emit_stub(STUB_LANGID_RVA, 0x0044u, 4u);
    emit_stub(STUB_LCID_RVA, 0x0015u, 8u);
    emit_stub(STUB_INSTALL_RVA, 0x00c7u, 4u);
    emit_stub(STUB_NLSSEC_RVA, 0x00a1u, 20u);      /* NtInitializeNlsFiles */
    emit_byte(0xc3);

    emit_data_reloc(NAME_RVA + 4u);
    emit_data_reloc(ATTRS_RVA + 8u);
    emit_data_reloc(DIRECTORY_RVA + 4u);
    emit_data_reloc(DIRECTORY_ATTRS_RVA + 8u);

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

/* The service the section reads the file's headers through: it serves the
 * fixture's own image bytes as "test.dll" and nothing else. */
typedef struct FakeFile {
    char last_name[64];                     /* what the service was asked for */
    PwFileNamespace last_namespace;         /* and which root it belongs to */
    uint32_t runtime_opens;                 /* opens that named the runtime root */
    uint32_t application_opens;             /* opens that named the app root */
    uint32_t library_seen;                  /* the run asked for its own DLL */
    uint32_t opens;
    uint32_t reads;
    uint32_t closes;
    uint64_t size;
    uint8_t bytes[64 * 1024];
} FakeFile;

static PwWineFileStatus fake_open(void *context, PwFileNamespace file_namespace,
                                  const char *name, uint64_t *size,
                                  void **token)
{
    FakeFile *file = context;

    file->opens++;
    file->last_namespace = file_namespace;
    if (file_namespace == PW_FILE_RUNTIME)
        file->runtime_opens++;
    else if (file_namespace == PW_FILE_APPLICATION)
        file->application_opens++;
    memcpy(file->last_name, name, strlen(name) + 1u);
    if (strcmp(name, "l_intl.nls") == 0) {
        /* The case map's own data file, which the locale code asks for by
         * type rather than by path. */
        *size = 4u;
        *token = file;
        return PW_WINE_FILE_OK;
    }
    if (strcmp(name, "locale.nls") == 0) {
        /* The distribution carries the NLS data, which is the case this bridge
         * answers with a status rather than a mapping. */
        *size = 4u;
        *token = file;
        return PW_WINE_FILE_OK;
    }
    /* The module is the application's own file and it is only there: a service
     * asked for it in the runtime's root deliberately answers that it does not
     * have it, which is what this distribution does with a name it does not
     * carry. */
    if (strcmp(name, "test.dll") != 0 ||
        file_namespace != PW_FILE_APPLICATION)
        return PW_WINE_FILE_NOT_FOUND;
    file->library_seen = 1u;
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

static const PwUnixCallRecord *record_with(const PwWineGateReport *report,
                                           uint32_t index)
{
    assert(index < report->calls.records);
    return &report->calls.sequence[index];
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
    FakeFile file;
    const char *modules[] = {"ntdll.dll"};
    const size_t size = build_module();
    PeImage expected;

    assert(size != 0u);
    /* The file the section describes is this fixture's own image, so the
     * expected answers come out of the same bytes the parser reads. */
    assert(pe_image_parse(&expected, image, size) == PW_OK);
    memset(&file, 0, sizeof(file));
    files.context = &file;
    file.size = size;
    memcpy(file.bytes, image, size);
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

    (void)pw_wine_gate_run(&config, &report);

    /* The section was described once and asked four times, and of the
     * refusals four are answers the section service gives (the short buffer,
     * the unknown class, the data section, and the unknown class the guest
     * uses to carry the view size) while the handle that names a directory
     * rather than a file is refused by the handle table. The view itself was
     * mapped once, with no refusal. */
    assert(report.section_creates == 1u);
    assert(report.section_queries == 4u);
    /* The short buffer, the unknown class, the data section and the five
     * unknown-class queries the guest uses to carry values out. */
    assert(report.section_refusals == 9u);
    assert(report.section_views == 1u);
    assert(report.section_view_refusals == 0u);
    assert(report.calls.handled >= 10u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);

    /* The sequence, in the order the guest issued it. */
    assert(record_with(&report, 0u)->id == 0x0033u);
    assert(record_with(&report, 0u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 1u)->id == 0x004au);
    assert(record_with(&report, 1u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 2u)->id == 0x0051u);
    assert(record_with(&report, 2u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 3u)->id == 0x0051u);
    assert(record_with(&report, 3u)->status == PW_NT_INFO_LENGTH_MISMATCH);
    assert(record_with(&report, 4u)->id == 0x0051u);
    assert(record_with(&report, 4u)->status == PW_NT_INVALID_INFO_CLASS);
    assert(record_with(&report, 5u)->id == 0x0051u);
    assert(record_with(&report, 5u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 6u)->id == 0x004au);
    assert(record_with(&report, 6u)->status == PW_NT_NOT_SUPPORTED);
    assert(record_with(&report, 7u)->id == 0x0033u);
    assert(record_with(&report, 8u)->id == 0x004au);
    assert(record_with(&report, 8u)->status == PW_NT_INVALID_HANDLE);
    assert(record_with(&report, 9u)->id == 0x000fu);
    assert(record_with(&report, 9u)->status == PW_NT_SUCCESS);
    /* The section still answers once the file handle it was created from is
     * closed, which is what the loader relies on. */
    assert(record_with(&report, 10u)->id == 0x0051u);
    assert(record_with(&report, 10u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 11u)->id == 0x0051u);
    assert(record_with(&report, 11u)->status == PW_NT_INVALID_HANDLE);
    /* A value the guest read, used as a handle by a call that never looks at
     * the buffer: the size the section reported. */
    assert(record_with(&report, 11u)->args[0] == expected.size_of_image);

    /* The view was mapped, and the guest read the image's own first bytes at
     * the base the gate returned: the query refused before it looked at them
     * carries both, so the mapped image is the file. */
    assert(record_with(&report, 12u)->id == 0x0028u);
    assert(record_with(&report, 12u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 13u)->id == 0x0051u);
    assert(record_with(&report, 13u)->status == PW_NT_INVALID_INFO_CLASS);
    assert(record_with(&report, 13u)->args[2] == expected.size_of_image);
    {
        uint32_t head = 0u;

        memcpy(&head, image, 4u);
        assert(record_with(&report, 13u)->args[3] == head);
    }
    /*
     * The relocation's own sequence: the range goes writable, the guest writes
     * through it and reads its own write back, and the loader's protection goes
     * on again - each protect reporting the protection it replaced, which is
     * the model the dispatcher keeps with the host mapping.
     */
    assert(record_with(&report, 14u)->id == 0x0050u);
    assert(record_with(&report, 14u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 15u)->id == 0x0050u);
    assert(record_with(&report, 15u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 16u)->id == 0x0051u);
    assert(record_with(&report, 16u)->args[2] == MARKER_WRITTEN);
    assert(record_with(&report, 16u)->args[3] == PAGE_READONLY);
    assert(record_with(&report, 17u)->id == 0x0051u);
    assert(record_with(&report, 17u)->args[2] == PAGE_READWRITE);
    assert(record_with(&report, 17u)->args[3] != 0u);
    assert((record_with(&report, 17u)->args[3] & 0xfffu) == 0u);
    /*
     * ntdll's NLS initialization: the distribution carries locale.nls, so the
     * call answers with the file mapped into this process - the address, the
     * size and the system language id. The guest reads the file's first dword
     * through the address it was given, and both that value and the language id
     * travel into the refused queries below, so the mapping can only be right
     * if it really landed in the guest's own memory with the file's bytes in
     * it.
     */
    assert(record_with(&report, 18u)->id == 0x00a4u);
    assert(record_with(&report, 18u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 19u)->id == 0x0051u);
    assert(record_with(&report, 19u)->status == PW_NT_INVALID_INFO_CLASS);
    assert(record_with(&report, 19u)->args[3] == 0x0409u);
    assert(record_with(&report, 19u)->args[2] != 0u);
    assert(record_with(&report, 20u)->id == 0x0051u);
    assert(record_with(&report, 20u)->args[2] ==
           report.modules[0].base + NLS_SIZE_RVA);
    {
        uint32_t head = 0u;

        memcpy(&head, image, 4u);
        /* The size the gate wrote: one page, because the file is four bytes. */
        assert(record_with(&report, 20u)->args[3] == head);
    }
    /* Two mappings in the end: locale.nls here and the case map below. */
    assert(report.nls_maps == 2u);
    assert(report.nls_refusals == 0u);
    /*
     * The locale questions and the case-map section: three questions with one
     * answer each (the id this run models), and NtGetNlsSectionPtr mapping
     * l_intl.nls the same way the NLS call maps locale.nls. The guest read the
     * mapped file's first dword through the address it was handed and carried
     * it out, so the mapping is the file's bytes in its own memory.
     */
    assert(record_with(&report, 21u)->id == 0x0044u);
    assert(record_with(&report, 21u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 22u)->id == 0x0015u);
    assert(record_with(&report, 22u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 23u)->id == 0x00c7u);
    assert(record_with(&report, 23u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 24u)->id == 0x00a1u);
    assert(record_with(&report, 24u)->status == PW_NT_SUCCESS);
    assert(record_with(&report, 25u)->id == 0x0051u);
    assert(record_with(&report, 25u)->args[2] ==
           report.modules[0].base + LOCALE_PTR_RVA - 0);
    {
        uint32_t head = 0u;

        memcpy(&head, image, 4u);
        assert(record_with(&report, 25u)->args[3] == head);
    }
    assert(report.locale_queries == 3u);
    /*
     * And the run ends on the write that must be refused now: the page is
     * read-only again in the host mapping and in the dispatcher's view of it
     * together, so this is the guard's own classified stop at the page the
     * guest protected and restored - not a host fault.
     */
    assert(report.stop == PW_WINE_STOP_MEMORY_BOUNDS);
    assert(report.fault_address ==
           record_with(&report, 17u)->args[3] + VIEW_PAGE_BYTES);
    assert(report.fault_write == 1u);
    assert(report.section_protects == 2u);
    assert(report.section_protect_refusals == 0u);
    /* The service was asked for the file twice - once by the loader's open and
     * once when the view was mapped, because the section re-opens the file by
     * the name it carries - and the section read it once to describe the image
     * and once more for the headers plus every section that has bytes on disk
     * when it placed the view. */
    /* Four opens: the loader's, the section re-opening the file by name when
     * the view is mapped, and the two NLS files the run asks the namespace for
     * (locale.nls for the locale mapping and l_intl.nls for the case map). */
    assert(file.opens == 4u);
    /* The section's own reads (the headers plus every section with bytes on
     * disk, twice: once to describe the image and once to place the view) and
     * the one read that fills the NLS mapping with the file's bytes. */
    assert(file.reads == 2u + expected.section_count + 2u);
    /* The section resolved its file through the service by the canonical name
     * the file handle carried, and the last thing the namespace was asked for
     * was the NLS data the run needs at this point of the boot. */
    assert(file.library_seen == 1u);
    /* The last name the namespace was asked for is the case map's own file:
     * the locale code asks for it after the locale tables are in place. */
    assert(strcmp(file.last_name, "l_intl.nls") == 0);
    /*
     * Where each open came from: the module's own file is the application's
     * (its path names a component of C:), and the section re-opens that same
     * file by name when it maps the view - so two of the four opens are the
     * application's and two, the NLS data, are the runtime's. A run that lost
     * the root with the loader's file handle would ask the runtime for
     * test.dll, the service would answer that it does not have it, and the
     * mapping would fail before any of this.
     */
    assert(file.application_opens == 2u);
    assert(file.runtime_opens == 2u);
    assert(file.last_namespace == PW_FILE_RUNTIME);
    /* The DLL file and the gate-owned Windows directory. */
    assert(report.file_opens == 2u);
    return 0;
}
