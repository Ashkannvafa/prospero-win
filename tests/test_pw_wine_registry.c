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
    THUNK_RVA = TEXT_RVA + 0x800,
    STUB_SYSINFO_RVA = TEXT_RVA + 0x810,
    STUB_OPENKEY_RVA = TEXT_RVA + 0x820,
    STUB_QUERYVALUE_RVA = TEXT_RVA + 0x830,
    STUB_CLOSE_RVA = TEXT_RVA + 0x840,
    STUB_STOP_RVA = TEXT_RVA + 0x850,
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
    put_attributes(SESSION_ATTRS_RVA, SESSION_RVA);
    put_attributes(MACHINE_ATTRS_RVA, MACHINE_RVA);
    put_attributes(WINE_ATTRS_RVA, WINE_RVA);   /* RootDirectory set below */
    put_attributes(DEVICE_ATTRS_RVA, DEVICE_RVA);
    put_attributes(TRAVERSAL_ATTRS_RVA, TRAVERSAL_RVA);

    /* The loader's first question: which Wine is this. */
    emit_push_absolute(VERSION_RET_RVA);
    emit_push_imm32(0x100u);
    emit_push_absolute(VERSION_BUFFER_RVA);
    emit_push_imm32(1000u);                  /* SystemWineVersionInformation */
    emit_call(STUB_SYSINFO_RVA);
    emit_store_eax(SYSINFO_STATUS_RVA);

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

    /*
     * A call with no handler stops the run, and its arguments are the values
     * the guest read out of its own memory: the value the profile declared,
     * the length the value query reported, and the first four bytes of the
     * Wine version block the gate wrote.
     */
    emit_push_imm8(0x00);
    emit_push_imm8(0x00);
    emit_load_eax(VERSION_BUFFER_RVA);
    emit_byte(0x50);
    emit_load_eax(VALUE_RET_RVA);
    emit_byte(0x50);
    emit_load_eax(GLOBALFLAG_COPY_RVA);
    emit_byte(0x50);
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
    emit_stub(STUB_STOP_RVA, 0x0021u, 20u);      /* NtQueryInformationToken */
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
};

static uint32_t fake_opens;
static uint32_t fake_closes;
static char fake_last_path[PW_WINE_GATE_MAX_PATH + 1];

static PwWineRegistryStatus fake_registry_open(void *context, const char *path,
                                               void **token)
{
    (void)context;
    fake_opens++;
    memcpy(fake_last_path, path, strlen(path) + 1u);
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

static void fake_registry_close(void *context, void *token)
{
    (void)context;
    (void)token;
    fake_closes++;
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
    const PwWineRegistryService registry = {
        .context = NULL, .open = fake_registry_open,
        .query = fake_registry_query, .close = fake_registry_close,
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
    config.root_module = "ntdll.dll";
    config.entry_module = "ntdll.dll";
    config.entry_symbol = "TestEntry";
    config.modules[0] = modules[0];
    config.module_count = 1u;
    config.bridge_calls = 1u;

    (void)pw_wine_gate_run(&config, &report);
    assert(report.registry_configured == 1u);
    assert(report.stop == PW_WINE_STOP_UNIX_CALL_UNIMPLEMENTED);
    assert(report.observed_syscall_id == 0x0021u);
    assert(report.calls.records == 17u);
    assert(report.calls.handled == 16u);
    assert(report.calls.unimplemented == 1u);
    assert(report.calls.rejected == 0u && report.calls.unknown == 0u);
    assert(report.calls_serviced == 16u);

    /* The Wine version: the guest asked for the one class ntdll initializes
     * from, and the gate answered with the host's block. */
    assert(report.calls.sequence[0].id == 0x0036u);
    assert(report.calls.sequence[0].args[0] == 1000u);
    assert(report.calls.sequence[0].args[2] == 0x100u);
    assert(report.calls.sequence[0].status == PW_NT_SUCCESS);

    /* The registry keys: opened, resolved and counted. */
    assert(report.key_opens == 3u);
    assert(report.calls.sequence[1].id == 0x0012u);
    assert(report.calls.sequence[1].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[6].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[7].status == PW_NT_SUCCESS);
    assert(fake_opens == 3u);
    /* The relative open resolved against the key it was given. */
    assert(strcmp(fake_last_path, "\\registry\\machine\\software\\wine") == 0);
    assert(strcmp(report.last_key,
                  "\\Registry\\Machine\\..\\..\\X") == 0);

    /* The values: one found, one absent, one that does not fit, twice. */
    assert(report.key_queries == 5u);
    assert(report.key_values == 4u);
    assert(report.key_refusals == 5u);
    assert(report.calls.sequence[2].id == 0x0017u);
    assert(report.calls.sequence[2].status == PW_NT_SUCCESS);
    assert(report.calls.sequence[3].status == PW_NT_OBJECT_NAME_NOT_FOUND);
    assert(report.calls.sequence[4].status == PW_NT_BUFFER_TOO_SMALL);
    assert(report.calls.sequence[5].status == PW_NT_BUFFER_OVERFLOW);
    assert(report.calls.sequence[8].status == PW_NT_SUCCESS);
    /* An information class with no meaning here, a value name that is not a
     * name, a path outside the namespace and a traversal inside it. */
    assert(report.calls.sequence[9].status == PW_NT_INVALID_INFO_CLASS);
    assert(report.calls.sequence[10].status == PW_NT_OBJECT_NAME_INVALID);
    assert(report.calls.sequence[11].status == PW_NT_OBJECT_NAME_INVALID);
    assert(report.calls.sequence[12].status == PW_NT_OBJECT_NAME_INVALID);
    /* A refused open never reached the platform service: three opens did. */
    assert(report.calls.sequence[11].id == 0x0012u);
    assert(fake_opens == 3u);

    /* Every key handle was closed by the guest, through the service. */
    assert(fake_closes == 3u);
    assert(report.file_closes == 3u);
    assert(report.file_handles == 0u);

    /*
     * The stop call's arguments are the values the guest loaded out of its own
     * memory: the dword the profile declared (42), the length the value query
     * reported (12 header + 12 data for the UTF-16 "win10"), and the first
     * four bytes of the version block ("9.0\0").
     */
    assert(report.calls.sequence[16].id == 0x0021u);
    assert(report.calls.sequence[16].outcome == PW_UNIX_CALL_UNIMPLEMENTED);
    assert(report.calls.sequence[16].args[0] == 42u);
    assert(report.calls.sequence[16].args[1] == 24u);
    assert(report.calls.sequence[16].args[2] == 0x00302e39u);
    return 0;
}
