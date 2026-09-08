#include "pw_compat32.h"

#include <string.h>

/*
 * The stub is emitted as raw bytes rather than assembled, because the
 * encodings differ by mode and an assembler running in 64-bit mode will not
 * produce the 32-bit forms this needs. Each sequence is annotated with its
 * mnemonic and every field patched by offset, so the byte-level test can
 * pin the whole thing.
 */

static void put_bytes(uint8_t *page, uint32_t offset, const uint8_t *bytes,
                      size_t count)
{
    memcpy(page + offset, bytes, count);
}

static void put_u16(uint8_t *page, uint32_t offset, uint16_t value)
{
    memcpy(page + offset, &value, sizeof(value));
}

static void put_u32(uint8_t *page, uint32_t offset, uint32_t value)
{
    memcpy(page + offset, &value, sizeof(value));
}

static int usable_base(uint32_t base)
{
    /*
     * `mov rsp, imm32` sign-extends, and every far pointer holds a 32-bit
     * offset, so a page has to sit in the low 2 GiB rather than merely
     * below 4 GiB.
     */
    return base != 0u && base < 0x80000000u &&
           (base & (PW_COMPAT32_PAGE_BYTES - 1u)) == 0u;
}

int pw_compat32_build(void *code_page, void *data_page,
                      const PwCompat32Layout *layout)
{
    uint8_t *bytes = code_page;
    uint8_t *data = data_page;

    if (!code_page || !data_page || !layout)
        return PW_ERR_PRECONDITION;
    if (!usable_base(layout->code_base) || !usable_base(layout->data_base))
        return PW_ERR_PRECONDITION;
    if (layout->code_selector == 0u || layout->data_selector == 0u ||
        layout->cs64 == 0u)
        return PW_ERR_PRECONDITION;

    memset(bytes, 0xcc, PW_COMPAT32_PAGE_BYTES);   /* int3 fills the gaps */
    memset(data, 0, PW_COMPAT32_PAGE_BYTES);

    /*
     * 64-bit launcher. The 64-bit stack pointer does not survive the round
     * trip — compatibility mode leaves only ESP meaningful, so RSP returns
     * with its upper half zeroed. Save it, hand the 32-bit side its own
     * stack inside this page, and restore on the way back. A real thunk
     * has to do exactly this for every crossing.
     */
    {
        const uint8_t code[] = {
            0x48, 0x89, 0x24, 0x25, 0, 0, 0, 0,  /* mov [saved_rsp], rsp   */
            0x48, 0x89, 0x2c, 0x25, 0, 0, 0, 0,  /* mov [saved_rbp], rbp   */
            0x48, 0xc7, 0xc4, 0, 0, 0, 0,        /* mov rsp, stack32_top   */
            0xff, 0x2c, 0x25, 0, 0, 0, 0,        /* ljmp *[far_in]         */
        };

        put_bytes(bytes, PW_COMPAT32_OFF_LAUNCH64, code, sizeof(code));
        put_u32(bytes, PW_COMPAT32_OFF_LAUNCH64 + 4,
                layout->data_base + PW_COMPAT32_OFF_SAVED_RSP);
        put_u32(bytes, PW_COMPAT32_OFF_LAUNCH64 + 12,
                layout->data_base + PW_COMPAT32_OFF_SAVED_RBP);
        put_u32(bytes, PW_COMPAT32_OFF_LAUNCH64 + 19,
                layout->data_base + PW_COMPAT32_OFF_STACK32);
        put_u32(bytes, PW_COMPAT32_OFF_LAUNCH64 + 26,
                layout->data_base + PW_COMPAT32_OFF_FAR_IN);
    }

    /*
     * 32-bit entry. DS is loaded first because the stores below are
     * DS-relative and a 64-bit caller's DS is commonly the null selector,
     * which is unusable once the CPU is in compatibility mode.
     */
    {
        const uint8_t code[] = {
            0xb8, 0, 0, 0, 0,                    /* mov eax, data_selector */
            0x8e, 0xd8,                          /* mov ds, ax             */
            0x31, 0xc0,                          /* xor eax, eax           */
            0x8c, 0xc8,                          /* mov ax, cs             */
            0xa3, 0, 0, 0, 0,                    /* mov [cs_seen], eax     */
            0xb8, 0x00, 0x00, 0x00, 0x00,        /* mov eax, 0             */
            0x40,                                /* inc eax  (REX in 64)   */
            0x40,                                /* inc eax  (REX in 64)   */
            0x40,                                /* inc eax  (REX in 64)   */
            0xa3, 0, 0, 0, 0,                    /* mov [result], eax      */
            0xff, 0x2d, 0, 0, 0, 0,              /* jmp far [far_back]     */
        };

        put_bytes(bytes, PW_COMPAT32_OFF_ENTRY32, code, sizeof(code));
        put_u32(bytes, PW_COMPAT32_OFF_ENTRY32 + 1, layout->data_selector);
        put_u32(bytes, PW_COMPAT32_OFF_ENTRY32 + 12,
                layout->data_base + PW_COMPAT32_OFF_CS_SEEN);
        put_u32(bytes, PW_COMPAT32_OFF_ENTRY32 + 25,
                layout->data_base + PW_COMPAT32_OFF_RESULT);
        put_u32(bytes, PW_COMPAT32_OFF_ENTRY32 + 31,
                layout->data_base + PW_COMPAT32_OFF_FAR_BACK);
    }

    /* 64-bit landing: restore DS and the full 64-bit stack, then return. */
    {
        const uint8_t code[] = {
            0xb8, 0, 0, 0, 0,                    /* mov eax, ds64          */
            0x8e, 0xd8,                          /* mov ds, ax             */
            0x48, 0x8b, 0x24, 0x25, 0, 0, 0, 0,  /* mov rsp, [saved_rsp]   */
            0x48, 0x8b, 0x2c, 0x25, 0, 0, 0, 0,  /* mov rbp, [saved_rbp]   */
            0xff, 0x24, 0x25, 0, 0, 0, 0,        /* jmp qword [saved_ret]  */
        };

        put_bytes(bytes, PW_COMPAT32_OFF_LAND64, code, sizeof(code));
        put_u32(bytes, PW_COMPAT32_OFF_LAND64 + 1, layout->ds64);
        put_u32(bytes, PW_COMPAT32_OFF_LAND64 + 11,
                layout->data_base + PW_COMPAT32_OFF_SAVED_RSP);
        put_u32(bytes, PW_COMPAT32_OFF_LAND64 + 19,
                layout->data_base + PW_COMPAT32_OFF_SAVED_RBP);
        put_u32(bytes, PW_COMPAT32_OFF_LAND64 + 26,
                layout->data_base + PW_COMPAT32_OFF_SAVED_RET);
    }

    /* Far pointers are a 32-bit offset followed by a 16-bit selector. */
    put_u32(data, PW_COMPAT32_OFF_FAR_IN,
            layout->code_base + PW_COMPAT32_OFF_ENTRY32);
    put_u16(data, PW_COMPAT32_OFF_FAR_IN + 4, layout->code_selector);
    put_u32(data, PW_COMPAT32_OFF_FAR_BACK,
            layout->code_base + PW_COMPAT32_OFF_LAND64);
    put_u16(data, PW_COMPAT32_OFF_FAR_BACK + 4, layout->cs64);

    /* Seeded so a stale or unwritten slot can never read as a pass. */
    put_u32(data, PW_COMPAT32_OFF_RESULT, PW_COMPAT32_RESULT_SEED);
    put_u32(data, PW_COMPAT32_OFF_CS_SEEN, PW_COMPAT32_RESULT_SEED);
    return PW_OK;
}

void pw_compat32_current_selectors(uint16_t *cs, uint16_t *ds)
{
#if defined(__x86_64__)
    uint16_t current_cs = 0;
    uint16_t current_ds = 0;

    __asm__ volatile("movw %%cs, %0" : "=r"(current_cs));
    __asm__ volatile("movw %%ds, %0" : "=r"(current_ds));
    if (cs)
        *cs = current_cs;
    if (ds)
        *ds = current_ds;
#else
    if (cs)
        *cs = 0u;
    if (ds)
        *ds = 0u;
#endif
}

int pw_compat32_enter(void *data_page, const PwCompat32Layout *layout)
{
#if defined(__x86_64__)
    uint8_t *bytes = data_page;

    if (!data_page || !layout)
        return PW_ERR_PRECONDITION;
    /*
     * The return address is written into the page rather than pushed: a far
     * transfer breaks call/ret pairing, and the 64-bit landing has to reach
     * an address that no longer fits a 32-bit far pointer.
     */
    __asm__ volatile(
        "leaq 1f(%%rip), %%rax\n\t"
        "movq %%rax, (%0)\n\t"
        "jmp *%1\n\t"
        "1:\n\t"
        :
        : "r"(bytes + PW_COMPAT32_OFF_SAVED_RET),
          "r"((uint64_t)(layout->code_base + PW_COMPAT32_OFF_LAUNCH64))
        : "rax", "memory");
    return PW_OK;
#else
    (void)data_page;
    (void)layout;
    return PW_ERR_UNSUPPORTED;
#endif
}

int pw_compat32_probe(const PwCompat32Platform *platform,
                      int attempt_transfer, PwCompat32Report *report)
{
    PwCompat32Layout layout;
    void *code_page = NULL;
    void *data_page = NULL;
    uint32_t code_base = 0u;
    uint32_t data_base = 0u;
    uint32_t index = 0u;
    int os_errno = 0;
    int status;

    if (!report)
        return PW_ERR_PRECONDITION;
    memset(report, 0, sizeof(*report));
    report->install_result = PW_ERR_PRECONDITION;
    report->reserve_result = PW_ERR_PRECONDITION;
    report->build_result = PW_ERR_PRECONDITION;
    report->seal_result = PW_OK;        /* no sealing needed by default */
    report->transfer_result = PW_ERR_PRECONDITION;
    if (!platform || !platform->install || !platform->reserve_low ||
        !platform->release_low)
        return PW_ERR_PRECONDITION;

    pw_compat32_current_selectors(&report->cs64, &report->ds64);

    /* Stage one: ask the kernel for the descriptors. No execution yet. */
    status = platform->install(platform->context, pw_segment_compat32_code(),
                               pw_segment_compat32_data(), &index, &os_errno);
    report->install_result = status;
    report->install_errno = os_errno;
    if (status != PW_OK)
        return status;
    report->ldt_index = index;
    report->code_selector = pw_segment_ldt_selector(index, PW_SEG_RING_USER);
    report->data_selector =
        pw_segment_ldt_selector(index + 1u, PW_SEG_RING_USER);

    status = platform->reserve_low(platform->context, &code_page, &code_base,
                                   &data_page, &data_base);
    report->reserve_result = status;
    if (status != PW_OK)
        return status;
    report->code_base = code_base;
    report->data_base = data_base;

    memset(&layout, 0, sizeof(layout));
    layout.code_base = code_base;
    layout.data_base = data_base;
    layout.code_selector = report->code_selector;
    layout.data_selector = report->data_selector;
    layout.cs64 = report->cs64;
    layout.ds64 = report->ds64;

    status = pw_compat32_build(code_page, data_page, &layout);
    report->build_result = status;
    if (status != PW_OK) {
        platform->release_low(platform->context, code_page, data_page);
        return status;
    }

    if (platform->seal_code) {
        int seal_errno = 0;

        status = platform->seal_code(platform->context, code_page,
                                     &seal_errno);
        report->seal_result = status;
        report->seal_errno = seal_errno;
        if (status != PW_OK) {
            platform->release_low(platform->context, code_page, data_page);
            return status;
        }
    }

    if (!attempt_transfer) {
        /* Stage one only: the descriptors exist, nothing has been run. */
        platform->release_low(platform->context, code_page, data_page);
        report->transfer_result = PW_OK;
        return PW_OK;
    }

    /* Stage two: the part that can fault. Everything above is reported. */
    report->transfer_attempted = 1u;
    status = pw_compat32_enter(data_page, &layout);
    report->transfer_result = status;
    if (status == PW_OK) {
        report->transfer_returned = 1u;
        memcpy(&report->result_value,
               (uint8_t *)data_page + PW_COMPAT32_OFF_RESULT,
               sizeof(report->result_value));
        memcpy(&report->cs_seen,
               (uint8_t *)data_page + PW_COMPAT32_OFF_CS_SEEN,
               sizeof(report->cs_seen));
        report->compat32_proven =
            report->result_value == PW_COMPAT32_EXPECTED_RESULT &&
            report->cs_seen == report->code_selector ? 1u : 0u;
    }
    platform->release_low(platform->context, code_page, data_page);
    return status;
}
