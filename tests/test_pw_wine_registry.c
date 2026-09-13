/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Self-contained proof of the registry side of the Unix-call bridge, and of
 * the one system-information class ntdll initialization asks for.
 *
 * One synthetic module plays the part of a Wine loader: it asks for the Wine
 * version the way version_init does, opens the Session Manager key the way
 * load_global_options does, queries a value that exists, one that does not,
 * one that does not fit the buffer it offers, then opens the registry root
 * and a key relative to it, and finally hands what it read back to a call
 * with no handler. The service is an in-memory profile, so nothing here needs
 * a registry - and the assertions are about what the guest itself saw.
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
    VERSION_BUFFER_RVA = DATA_RVA + 0x100,  /* 256-byte guest buffer */
    VERSION_RET_RVA = DATA_RVA + 0x220,
    SYSINFO_STATUS_RVA = DATA_RVA + 0x224,
    SESSION_TEXT_RVA = DATA_RVA + 0x240,
    SESSION_RVA = DATA_RVA + 0x300,         /* its UNICODE_STRING header */
    SESSION_ATTRS_RVA = DATA_RVA + 0x310,
    SESSION_HANDLE_RVA = DATA_RVA + 0x330,
    GLOBALFLAG_TEXT_RVA = DATA_RVA + 0x340,
    GLOBALFLAG_RVA = DATA_RVA + 0x360,
    MISSING_TEXT_RVA = DATA_RVA + 0x370,
    MISSING_RVA = DATA_RVA + 0x3A0,
    BADNAME_TEXT_RVA = DATA_RVA + 0x3B0,
    BADNAME_RVA = DATA_RVA + 0x3E0,
    VALUE_BUFFER_RVA = DATA_RVA + 0x3F0,    /* 64-byte guest buffer */
    VALUE_RET_RVA = DATA_RVA + 0x440,
    QUERY_STATUS_RVA = DATA_RVA + 0x450,
    GLOBALFLAG_COPY_RVA = DATA_RVA + 0x480,
    MACHINE_TEXT_RVA = DATA_RVA + 0x490,
    MACHINE_RVA = DATA_RVA + 0x4C0,
    MACHINE_ATTRS_RVA = DATA_RVA + 0x4D0,
    MACHINE_HANDLE_RVA = DATA_RVA + 0x4F0,
    WINE_TEXT_RVA = DATA_RVA + 0x500,
    WINE_RVA = DATA_RVA + 0x520,
    WINE_ATTRS_RVA = DATA_RVA + 0x530,      /* RootDirectory is filled at run time */
    WINE_HANDLE_RVA = DATA_RVA + 0x550,
    VERSION_VALUE_TEXT_RVA = DATA_RVA + 0x560,
    VERSION_VALUE_RVA = DATA_RVA + 0x580,
    DEVICE_TEXT_RVA = DATA_RVA + 0x590,
    DEVICE_RVA = DATA_RVA + 0x5D0,
    DEVICE_ATTRS_RVA = DATA_RVA + 0x5E0,
    DEVICE_HANDLE_RVA = DATA_RVA + 0x600,
    TRAVERSAL_TEXT_RVA = DATA_RVA + 0x610,
    TRAVERSAL_RVA = DATA_RVA + 0x650,
    TRAVERSAL_ATTRS_RVA = DATA_RVA + 0x660,
    TRAVERSAL_HANDLE_RVA = DATA_RVA + 0x680,
    STOP_RESULT_RVA = DATA_RVA + 0x690,
    USER_TEXT_RVA = DATA_RVA + 0x6A0,
    USER_RVA = DATA_RVA + 0x6F0,
    USER_ATTRS_RVA = DATA_RVA + 0x700,
    USER_HANDLE_RVA = DATA_RVA + 0x720,
    TOKEN_BUFFER_RVA = DATA_RVA + 0x730,    /* 96-byte token answer buffer */
    TOKEN_RET_RVA = DATA_RVA + 0x790,
    TOKEN_STATUS_RVA = DATA_RVA + 0x7A0,    /* four statuses */
    SID_VALUE_RVA = DATA_RVA + 0x7B0,       /* the SID subauthority read back */
    DISPOSITION_RVA = DATA_RVA + 0x7C0,
    CREATE_STATUS_RVA = DATA_RVA + 0x7D0,
    THUNK_RVA = TEXT_RVA + 0x800,
    STUB_SYSINFO_RVA = TEXT_RVA + 0x810,
    STUB_OPENKEY_RVA = TEXT_RVA + 0x820,
    STUB_QUERYVALUE_RVA = TEXT_RVA + 0x830,
    STUB_CLOSE_RVA = TEXT_RVA + 0x840,
    STUB_TOKEN_RVA = TEXT_RVA + 0x850,
    STUB_CREATE_RVA = TEXT_RVA + 0x860,
    STUB_STOP_RVA = TEXT_RVA + 0x870,
    CALLER_RVA = TEXT_RVA,
    KEY_VALUE_PARTIAL_INFORMATION = 2u,
};

/*
 * The data layout is hand-written, so each region is checked against the next
 * one: a string that grows into a header, or a store that lands inside a
 * string, is a compile error rather than a strange failure in the guest.
 */
_Static_assert(VERSION_BUFFER_RVA + 0x100u <= VERSION_RET_RVA,
               "version buffer overlaps its result slot");
_Static_assert(VERSION_RET_RVA + 8u <= SESSION_TEXT_RVA,
               "version results overlap the session key text");
_Static_assert(SESSION_TEXT_RVA + 136u <= SESSION_RVA,
               "session key text overlaps its UNICODE_STRING");
_Static_assert(SESSION_RVA + 32u <= SESSION_HANDLE_RVA,
               "session key header overlaps its handle slot");
_Static_assert(GLOBALFLAG_TEXT_RVA + 24u <= GLOBALFLAG_RVA,
               "GlobalFlag text overlaps its UNICODE_STRING");
_Static_assert(MISSING_TEXT_RVA + 36u <= MISSING_RVA,
               "missing-value text overlaps its UNICODE_STRING");
_Static_assert(BADNAME_TEXT_RVA + 18u <= BADNAME_RVA,
               "bad-name text overlaps its UNICODE_STRING");
_Static_assert(VALUE_BUFFER_RVA + 64u <= VALUE_RET_RVA,
               "value buffer overlaps its result slot");
_Static_assert(QUERY_STATUS_RVA + 48u <= GLOBALFLAG_COPY_RVA,
               "status slots overlap the copied value");
_Static_assert(GLOBALFLAG_COPY_RVA + 4u <= MACHINE_TEXT_RVA,
               "copied value overlaps the registry root text");
_Static_assert(MACHINE_TEXT_RVA + 36u <= MACHINE_RVA,
               "registry root text overlaps its UNICODE_STRING");
_Static_assert(MACHINE_RVA + 32u <= MACHINE_HANDLE_RVA,
               "registry root header overlaps its handle slot");
_Static_assert(WINE_TEXT_RVA + 28u <= WINE_RVA,
               "relative key text overlaps its UNICODE_STRING");
_Static_assert(WINE_RVA + 32u <= WINE_HANDLE_RVA,
               "relative key header overlaps its handle slot");
_Static_assert(VERSION_VALUE_TEXT_RVA + 16u <= VERSION_VALUE_RVA,
               "Version text overlaps its UNICODE_STRING");
_Static_assert(DEVICE_TEXT_RVA + 50u <= DEVICE_RVA,
               "device path text overlaps its UNICODE_STRING");
_Static_assert(DEVICE_RVA + 32u <= DEVICE_HANDLE_RVA,
               "device path header overlaps its handle slot");
_Static_assert(TRAVERSAL_TEXT_RVA + 52u <= TRAVERSAL_RVA,
               "traversal path text overlaps its UNICODE_STRING");
_Static_assert(TRAVERSAL_HANDLE_RVA + 4u <= STOP_RESULT_RVA,
               "traversal handle overlaps the stop result slot");
_Static_assert(USER_TEXT_RVA + 72u <= USER_RVA,
               "user key text overlaps its UNICODE_STRING");
_Static_assert(USER_RVA + 32u <= USER_HANDLE_RVA,
               "user key header overlaps its handle slot");
_Static_assert(TOKEN_BUFFER_RVA + 0x60u <= TOKEN_RET_RVA,
               "token buffer overlaps its result slot");
_Static_assert(TOKEN_RET_RVA + 16u <= TOKEN_STATUS_RVA,
               "token result overlaps its status slots");
_Static_assert(TOKEN_STATUS_RVA + 16u <= SID_VALUE_RVA,
               "token status slots overlap the SID value");
_Static_assert(SID_VALUE_RVA + 16u <= DISPOSITION_RVA,
               "SID value overlaps the disposition slot");
_Static_assert(DISPOSITION_RVA + 16u <= CREATE_STATUS_RVA,
               "disposition overlaps the create status");

/* The version block the host hands the gate: four NUL-terminated strings in
 * Wine's own layout. The test checks the guest reads the first one. */
static const char test_version_info[] = "9.0\0wine-9.0\0Test\01.0\0";

static uint8_t image[64 * 1024];
static uint8_t text[4096];
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

/* A UNICODE_STRING header at `header` pointing at the UTF-16 text at
 * `text_offset`; both are RVAs inside the module's data section. */
static void put_unicode_string(uint32_t header, uint32_t text_offset,
                               const char *text_ascii)
{
    const uint16_t length = (uint16_t)(strlen(text_ascii) * 2u);
    const uint32_t buffer = IMAGE_BASE + text_offset;
    uint32_t index = 0u;

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

static void put_attributes(uint32_t attributes, uint32_t name_header)
{
    const uint32_t length = 24u;
    const uint32_t name_pointer = IMAGE_BASE + name_header;

    memcpy(data + (attributes - DATA_RVA), &length, 4u);
    memcpy(data + (attributes - DATA_RVA) + 8u, &name_pointer, 4u);
}

/* NtOpenKey(&handle, KEY_QUERY_VALUE, &attributes) */
static void emit_open_key(uint32_t attributes_rva, uint32_t handle_rva,
                          uint32_t status_rva)
{
    emit_push_absolute(attributes_rva);
    emit_push_imm8(0x01);
    emit_push_absolute(handle_rva);
    emit_call(STUB_OPENKEY_RVA);
    emit_store_eax(status_rva);
}

/* NtQueryValueKey(handle, &name, class, buffer, length, &result_length) */
static void emit_query_value(uint32_t handle_rva, uint32_t name_rva,
                             uint32_t length, uint32_t class_value,
                             uint32_t status_rva)
{
    emit_push_absolute(VALUE_RET_RVA);
    emit_push_imm32(length);
    emit_push_absolute(VALUE_BUFFER_RVA);
    emit_push_imm8((uint8_t)class_value);
    emit_push_absolute(name_rva);
    emit_load_eax(handle_rva);
    emit_byte(0x50);
    emit_call(STUB_QUERYVALUE_RVA);
    emit_store_eax(status_rva);
}

static size_t build_module(void)
{
    PeFixtureSpec spec;

    text_bytes = 0u;
    reloc_count = 0u;
    memset(data, 0, sizeof(data));
    put_unicode_string(SESSION_RVA, SESSION_TEXT_RVA,
                       "\\Registry\\Machine\\System\\CurrentControlSet"
                       "\\Control\\Session Manager");
    put_unicode_string(GLOBALFLAG_RVA, GLOBALFLAG_TEXT_RVA, "GlobalFlag");
    put_unicode_string(MISSING_RVA, MISSING_TEXT_RVA, "SafeDllSearchMode");
    put_unicode_string(BADNAME_RVA, BADNAME_TEXT_RVA, "Bad\\Name");
    put_unicode_string(MACHINE_RVA, MACHINE_TEXT_RVA, "\\Registry\\Machine");
    put_unicode_string(WINE_RVA, WINE_TEXT_RVA, "Software\\Wine");
    put_unicode_string(VERSION_VALUE_RVA, VERSION_VALUE_TEXT_RVA, "Version");
    put_unicode_string(DEVICE_RVA, DEVICE_TEXT_RVA,
                       "\\Device\\HarddiskVolume0\\X");
    put_unicode_string(TRAVERSAL_RVA, TRAVERSAL_TEXT_RVA,
                       "\\Registry\\Machine\\..\\..\\X");
    put_unicode_string(USER_RVA, USER_TEXT_RVA,
                       "\\Registry\\User\\S-1-5-21-1-2-3-12074");
    put_attributes(SESSION_ATTRS_RVA, SESSION_RVA);
    put_attributes(MACHINE_ATTRS_RVA, MACHINE_RVA);
    put_attributes(WINE_ATTRS_RVA, WINE_RVA);   /* RootDirectory set below */
    put_attributes(DEVICE_ATTRS_RVA, DEVICE_RVA);
    put_attributes(TRAVERSAL_ATTRS_RVA, TRAVERSAL_RVA);
    put_attributes(USER_ATTRS_RVA, USER_RVA);

    /* The loader's first question: which Wine is this. */
    emit_push_absolute(VERSION_RET_RVA);
    emit_push_imm32(0x100u);
    emit_push_absolute(VERSION_BUFFER_RVA);
    emit_push_imm32(1000u);                  /* SystemWineVersionInformation */
    emit_call(STUB_SYSINFO_RVA);
    emit_store_eax(SYSINFO_STATUS_RVA);

    /*
     * The token: RtlFormatCurrentUserKeyPath asks for TokenUser before it can
     * format the user key path, then reads the SID the gate wrote after the
     * descriptor. A buffer that cannot hold the answer, a class with no
     * meaning here and a handle that is not a token are all real NTSTATUS
     * values.
     */
    emit_push_absolute(TOKEN_RET_RVA);
    emit_push_imm32(0x50u);
    emit_push_absolute(TOKEN_BUFFER_RVA);
    emit_push_imm8(1);
    emit_push_imm32(0xfffffffau);           /* GetCurrentThreadEffectiveToken */
    emit_call(STUB_TOKEN_RVA);
    emit_store_eax(TOKEN_STATUS_RVA);
    /* The SID's subauthority count is 5, so its last subauthority - the 1000
     * of S-1-5-21-0-0-0-1000 - is at SID+8+16, and the SID itself starts
     * after the 8-byte TOKEN_USER descriptor. */
    emit_load_eax(TOKEN_BUFFER_RVA + 8u + 8u + 16u);
    emit_store_eax(SID_VALUE_RVA);
    emit_push_absolute(TOKEN_RET_RVA);
    emit_push_imm32(8u);
    emit_push_absolute(TOKEN_BUFFER_RVA);
    emit_push_imm8(1);
    emit_push_imm32(0xfffffffau);
    emit_call(STUB_TOKEN_RVA);
    emit_store_eax(TOKEN_STATUS_RVA + 4u);
    emit_push_absolute(TOKEN_RET_RVA);
    emit_push_imm32(0x50u);
    emit_push_absolute(TOKEN_BUFFER_RVA);
    emit_push_imm8(2);                      /* a class the gate does not answer */
    emit_push_imm32(0xfffffffau);
    emit_call(STUB_TOKEN_RVA);
    emit_store_eax(TOKEN_STATUS_RVA + 8u);
    emit_push_absolute(TOKEN_RET_RVA);
    emit_push_imm32(0x50u);
    emit_push_absolute(TOKEN_BUFFER_RVA);
    emit_push_imm8(1);
    emit_push_imm32(0x00001234u);           /* not a token handle */
    emit_call(STUB_TOKEN_RVA);
    emit_store_eax(TOKEN_STATUS_RVA + 12u);

    /* load_global_options: the Session Manager key, then its two options. */
    emit_open_key(SESSION_ATTRS_RVA, SESSION_HANDLE_RVA, QUERY_STATUS_RVA);
    emit_query_value(SESSION_HANDLE_RVA, GLOBALFLAG_RVA, 32u,
                     KEY_VALUE_PARTIAL_INFORMATION, QUERY_STATUS_RVA + 4u);
    /* Keep the value itself - KEY_VALUE_PARTIAL_INFORMATION::Data starts
     * after the 12-byte fixed part - for the stop call to prove later. */
    emit_load_eax(VALUE_BUFFER_RVA + 12u);
    emit_store_eax(GLOBALFLAG_COPY_RVA);
    emit_query_value(SESSION_HANDLE_RVA, MISSING_RVA, 32u,
                     KEY_VALUE_PARTIAL_INFORMATION, QUERY_STATUS_RVA + 8u);
    emit_query_value(SESSION_HANDLE_RVA, GLOBALFLAG_RVA, 8u,
                     KEY_VALUE_PARTIAL_INFORMATION, QUERY_STATUS_RVA + 12u);
    emit_query_value(SESSION_HANDLE_RVA, GLOBALFLAG_RVA, 14u,
                     KEY_VALUE_PARTIAL_INFORMATION, QUERY_STATUS_RVA + 16u);

    /* version_init: the registry root, then HKCU\Software\Wine relative to a
     * key handle, which is the shape RtlOpenCurrentUser produces. */
    emit_open_key(MACHINE_ATTRS_RVA, MACHINE_HANDLE_RVA,
                  QUERY_STATUS_RVA + 20u);
    emit_load_eax(MACHINE_HANDLE_RVA);
    emit_store_eax(WINE_ATTRS_RVA + 4u);     /* RootDirectory */
    emit_open_key(WINE_ATTRS_RVA, WINE_HANDLE_RVA, QUERY_STATUS_RVA + 24u);
    emit_query_value(WINE_HANDLE_RVA, VERSION_VALUE_RVA, 32u,
                     KEY_VALUE_PARTIAL_INFORMATION, QUERY_STATUS_RVA + 28u);
    /* A class this bridge does not answer, and a value name that is not a
     * name: both are refusals with a real NTSTATUS, not silences. */
    emit_query_value(SESSION_HANDLE_RVA, GLOBALFLAG_RVA, 32u, 0u,
                     QUERY_STATUS_RVA + 32u);
    emit_query_value(SESSION_HANDLE_RVA, BADNAME_RVA, 32u,
                     KEY_VALUE_PARTIAL_INFORMATION, QUERY_STATUS_RVA + 36u);
    /* Paths outside the namespace, and a traversal inside it. */
    emit_open_key(DEVICE_ATTRS_RVA, DEVICE_HANDLE_RVA, QUERY_STATUS_RVA + 40u);
    emit_open_key(TRAVERSAL_ATTRS_RVA, TRAVERSAL_HANDLE_RVA,
                  QUERY_STATUS_RVA + 44u);

    /*
     * NtCreateKey for the user hive root, which is the call
     * RtlOpenCurrentUser makes once it has formatted the SID into the path.
     * The disposition reports that the key already existed.
     */
    emit_push_absolute(DISPOSITION_RVA);
    emit_push_imm8(0x00);                    /* CreateOptions */
    emit_push_imm8(0x00);                    /* Class (NULL) */
    emit_push_imm8(0x00);                    /* TitleIndex */
    emit_push_absolute(USER_ATTRS_RVA);
    emit_push_imm32(0x000f003fu);            /* KEY_ALL_ACCESS */
    emit_push_absolute(USER_HANDLE_RVA);
    emit_call(STUB_CREATE_RVA);
    emit_store_eax(CREATE_STATUS_RVA);

    /* Every key handle the run opened is closed again. */
    emit_load_eax(SESSION_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);
    emit_load_eax(MACHINE_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);
    emit_load_eax(WINE_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);
    emit_load_eax(USER_HANDLE_RVA);
    emit_byte(0x50);
    emit_call(STUB_CLOSE_RVA);

    /*
     * A call with no handler stops the run, and its arguments are the values
     * the guest read out of its own memory: the value the profile declared,
     * the length the value query reported, and the first four bytes of the
     * Wine version block the gate wrote.
     */
    emit_push_imm8(0x00);                     /* arg 5 */
    emit_push_imm8(0x00);                     /* arg 4 */
    emit_push_imm8(0x00);                     /* arg 3 */
    emit_load_eax(DISPOSITION_RVA);
    emit_byte(0x50);                          /* arg 2 */
    emit_load_eax(SID_VALUE_RVA);
    emit_byte(0x50);                          /* arg 1 */
    emit_call(STUB_STOP_RVA);
    emit_store_eax(STOP_RESULT_RVA);

    while (text_bytes < THUNK_RVA - TEXT_RVA)
        emit_byte(0x90);
    emit_byte(0xff); emit_byte(0x25);
    emit_absolute(SLOT_RVA);
    emit_stub(STUB_SYSINFO_RVA, 0x0036u, 16u);   /* NtQuerySystemInformation */
    emit_stub(STUB_OPENKEY_RVA, 0x0012u, 12u);   /* NtOpenKey */
    emit_stub(STUB_QUERYVALUE_RVA, 0x0017u, 24u);/* NtQueryValueKey */
    emit_stub(STUB_CLOSE_RVA, 0x000fu, 4u);      /* NtClose */
    emit_stub(STUB_TOKEN_RVA, 0x0021u, 20u);     /* NtQueryInformationToken */
    emit_stub(STUB_CREATE_RVA, 0x001du, 28u);    /* NtCreateKey */
    emit_stub(STUB_STOP_RVA, 0x0019u, 20u);      /* NtQueryInformationProcess */
    emit_byte(0xc3);

    /* Pointers stored inside the data section need their own base
     * relocations, exactly like a real image. */
    emit_data_reloc(SESSION_RVA + 4u);
    emit_data_reloc(SESSION_ATTRS_RVA + 8u);
    emit_data_reloc(GLOBALFLAG_RVA + 4u);
    emit_data_reloc(MISSING_RVA + 4u);
    emit_data_reloc(BADNAME_RVA + 4u);
    emit_data_reloc(MACHINE_RVA + 4u);
    emit_data_reloc(MACHINE_ATTRS_RVA + 8u);
    emit_data_reloc(WINE_RVA + 4u);
    emit_data_reloc(WINE_ATTRS_RVA + 8u);
    emit_data_reloc(VERSION_VALUE_RVA + 4u);
    emit_data_reloc(DEVICE_RVA + 4u);
    emit_data_reloc(DEVICE_ATTRS_RVA + 8u);
    emit_data_reloc(TRAVERSAL_RVA + 4u);
    emit_data_reloc(TRAVERSAL_ATTRS_RVA + 8u);
    emit_data_reloc(USER_RVA + 4u);
    emit_data_reloc(USER_ATTRS_RVA + 8u);

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

/*
 * The host service this test supplies. It declares three keys - the Session
 * Manager key with a dword value, the registry root with none, and
 * HKCU\Software\Wine with a string value - and nothing else, so the guest's
 * not-found paths are real too.
 */
typedef struct FakeValue {
    const char *name;
    uint32_t type;
    const void *bytes;
    uint32_t size;
} FakeValue;

typedef struct FakeKey {
    const char *path;
    const FakeValue *values;
    uint32_t value_count;
} FakeKey;

static const uint32_t fake_global_flag = 42u;      /* 0x2a */
static const uint16_t fake_version[6] = {
    'w', 'i', 'n', '1', '0', 0u,
};

static const FakeValue session_values[] = {
    { "globalflag", 4u, &fake_global_flag, sizeof(fake_global_flag) },
};

static const FakeValue wine_values[] = {
    { "version", 1u, fake_version, sizeof(fake_version) },
};

static const FakeKey fake_keys[] = {
    {
        "\\registry\\machine\\system\\currentcontrolset\\control\\session "
        "manager",
        session_values,
        sizeof(session_values) / sizeof(session_values[0]),
    },
    { "\\registry\\machine", NULL, 0u },
    {
        "\\registry\\machine\\software\\wine",
        wine_values,
        sizeof(wine_values) / sizeof(wine_values[0]),
    },
    { "\\registry\\user\\s-1-5-21-1-2-3-12074", NULL, 0u },
};

static uint32_t fake_opens;
static uint32_t fake_closes;
static char fake_paths[8][PW_WINE_GATE_MAX_PATH + 1];

static PwWineRegistryStatus fake_registry_open(void *context, const char *path,
                                               void **token)
{
    (void)context;
    if (fake_opens < sizeof(fake_paths) / sizeof(fake_paths[0]))
        memcpy(fake_paths[fake_opens], path, strlen(path) + 1u);
    fake_opens++;
    for (unsigned index = 0;
         index < sizeof(fake_keys) / sizeof(fake_keys[0]); ++index) {
        if (strcmp(fake_keys[index].path, path) != 0)
            continue;
        *token = (void *)(uintptr_t)&fake_keys[index];
        return PW_WINE_REGISTRY_OK;
    }
    return PW_WINE_REGISTRY_NOT_FOUND;
}

static PwWineRegistryStatus fake_registry_query(void *context, void *token,
                                                const char *value,
                                                uint32_t *type,
                                                const void **bytes,
                                                uint32_t *size)
{
    const FakeKey *key = token;

    (void)context;
    if (!key)
        return PW_WINE_REGISTRY_ERROR;
    for (uint32_t index = 0; index < key->value_count; ++index) {
        if (strcmp(key->values[index].name, value) != 0)
            continue;
        *type = key->values[index].type;
        *bytes = key->values[index].bytes;
        *size = key->values[index].size;
        return PW_WINE_REGISTRY_OK;
    }
    return PW_WINE_REGISTRY_NOT_FOUND;
}

static PwWineRegistryStatus fake_registry_create(void *context,
                                                 const char *path,
                                                 void **token,
                                                 uint32_t *created)
{
    const PwWineRegistryStatus status =
        fake_registry_open(context, path, token);

    if (status == PW_WINE_REGISTRY_OK)
        *created = 0u;
    return status;
}

static void fake_registry_close(void *context, void *token)
{
    (void)context;
    (void)token;
    fake_closes++;
}

/*
 * The token the host declares for this test: S-1-5-21-1-2-3-12074. The last
 * subauthority is deliberately not one Wine would choose, because the guest
 * reads it back and the stop call reports it: the value can only be right if
 * the SID came from the host service.
 */
static const uint8_t test_user_sid[] = {
    0x01, 0x05,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x15, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00,
    0x2a, 0x2f, 0x00, 0x00,
};

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
    const PwWineRegistryService registry = {
        .context = NULL, .open = fake_registry_open,
        .query = fake_registry_query, .create = fake_registry_create,
        .close = fake_registry_close,
    };
    PwWineGateConfig config;
    PwWineGateReport report;
    PwVmBackend vm;
    const char *modules[] = {"ntdll.dll"};
    const size_t size = build_module();

    assert(size != 0u);
    assert(sizeof(test_version_info) == 22u);
    span.bytes = image;
    span.size = size;
    span.handle = NULL;
    memset(span.path, 0, sizeof(span.path));
    assert(pw_vm_posix_backend(&vm) == PW_OK);

    memset(&config, 0, sizeof(config));
    config.provider = &provider;
    config.backend = &vm;
    config.registry = &registry;
    config.wine_version_info = test_version_info;
    config.wine_version_info_bytes = (uint32_t)sizeof(test_version_info);
    config.token_user_sid = test_user_sid;
    config.token_user_sid_bytes = (uint32_t)sizeof(test_user_sid);
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntry";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;

    (void)pw_wine_gate_run(&config, &report);
    assert(report.registry_configured == 1u);
    assert(report.stop == PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED);
    assert(report.observed_syscall_id == 0x0019u);
    assert(report.calls.records == 23u);
    assert(report.calls.handled == 22u);
    assert(report.calls.unimplemented == 1u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);
    assert(report.calls_serviced == 22u);

    /* The Wine version: the guest asked for the one class ntdll initializes
     * from, and the gate answered with the host's block. */
    assert(report.calls.sequence[0].id == 0x0036u);
    assert(report.calls.sequence[0].args[0] == 1000u);
    assert(report.calls.sequence[0].args[2] == 0x100u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);

    /* The token: the host's SID for the current-token pseudo-handles, with
     * the layout, the required length and the NTSTATUS values NT uses. */
    /* Two of the four token calls name the class this bridge answers; the
     * other two are refused before the query is counted. */
    assert(report.token_queries == 2u);
    assert(report.calls.sequence[1].id == 0x0021u);
    assert(report.calls.sequence[1].args[0] == 0xfffffffau);
    assert(report.calls.sequence[1].args[1] == 1u);
    assert(report.calls.sequence[1].args[3] == 0x50u);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[2].status == PW_NT_BUFFER_TOO_SMALL);
    assert(report.calls.sequence[3].status == PW_NT_INVALID_INFO_CLASS);
    assert(report.calls.sequence[4].status == PW_NT_INVALID_HANDLE);

    /* The registry keys: opened, resolved and counted. */
    assert(report.key_opens == 3u);
    assert(report.calls.sequence[5].id == 0x0012u);
    assert(report.calls.sequence[5].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[10].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[11].status == PW_NT_SUCCESS);
    /* The relative open resolved against the key it was given: the third path
     * the service was asked about is the composed one. */
    assert(fake_opens == 4u);
    assert(strcmp(fake_paths[2], "\\registry\\machine\\software\\wine") == 0);
    /* The last key the gate recorded is the canonical one it handed the
     * service for the create; the refused traversal before it is counted in
     * key_refusals. */
    assert(strcmp(report.last_key,
                  "\\registry\\user\\s-1-5-21-1-2-3-12074") == 0);

    /* The values: one found, one absent, one that does not fit, twice. */
    assert(report.key_queries == 5u);
    assert(report.key_values == 4u);
    assert(report.key_refusals == 5u);
    assert(report.calls.sequence[6].id == 0x0017u);
    assert(report.calls.sequence[6].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[7].status == PW_NT_OBJECT_NAME_NOT_FOUND);
    assert(report.calls.sequence[8].status == PW_NT_BUFFER_TOO_SMALL);
    assert(report.calls.sequence[9].status == PW_NT_BUFFER_OVERFLOW);
    assert(report.calls.sequence[12].status == PW_NT_SUCCESS);
    /* An information class with no meaning here, a value name that is not a
     * name, a path outside the namespace and a traversal inside it. */
    assert(report.calls.sequence[13].status == PW_NT_INVALID_INFO_CLASS);
    assert(report.calls.sequence[14].status == PW_NT_OBJECT_NAME_INVALID);
    assert(report.calls.sequence[15].status == PW_NT_OBJECT_NAME_INVALID);
    assert(report.calls.sequence[16].status == PW_NT_OBJECT_NAME_INVALID);
    /* A refused open never reached the platform service: three opens did. */
    assert(report.calls.sequence[15].id == 0x0012u);

    /* NtCreateKey is create-or-open: the user hive root exists in the profile,
     * so the gate opens it and reports REG_OPENED_EXISTING_KEY. */
    assert(report.key_creates == 1u);
    assert(report.calls.sequence[17].id == 0x001du);
    assert(report.calls.sequence[17].status == PW_NT_SUCCESS);
    /* The create asked the service about the user hive root as well. */
    assert(fake_opens == 4u);
    assert(strcmp(fake_paths[3],
                  "\\registry\\user\\s-1-5-21-1-2-3-12074") == 0);

    /* Every key handle was closed by the guest, through the service. */
    assert(fake_closes == 4u);
    assert(report.file_closes == 4u);
    assert(report.file_handles == 0u);

    /*
     * The stop call's arguments are the values the guest loaded out of its own
     * memory: the SID's last subauthority as the host declared it (12074), and
     * the disposition the create reported (REG_OPENED_EXISTING_KEY).
     */
    assert(report.calls.sequence[22].id == 0x0019u);
    assert(report.calls.sequence[22].outcome == PW_UNIX_CALL_UNIMPLEMENTED);
    assert(report.calls.sequence[22].args[0] == 12074u);
    assert(report.calls.sequence[22].args[1] == 2u);
    return 0;
}
