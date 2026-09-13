/* SPDX-License-Identifier: LGPL-2.1-or-later */
.text
.globl _start
_start:
    pushl $-1
    pushl $0x11223344
    call target
target:
    /* Output the guest stack after call, then terminate via Linux i386 ABI. */
    movl %esp, %ecx
    movl $12, %edx
    movl $1, %ebx
    movl $4, %eax
    int $0x80
    movl $0xfffffff0, %eax
    movl $3, %ecx
    leal 0x20(%eax,%ecx,8), %edx
    pushl %edx
    movl %esp, %ecx
    movl $4, %edx
    movl $1, %ebx
    movl $4, %eax
    int $0x80
/*
 * FS-prefixed absolute operands. The translated engine executes
 * "mov edi, fs:[0x18]" / "mov fs:[0x1c], edi" against the guest's own FS
 * base; here the host kernel installs a real 32-bit FS base through
 * set_thread_area (i386 syscall 243), so the oracle is native i386 code and
 * not a second implementation of the same arithmetic.
 */
    leal tls_block, %eax
    pushl $0x11                 /* seg_32bit | limit_in_pages */
    pushl $0xfffff              /* limit, in pages */
    pushl %eax                  /* base_addr */
    pushl $0xffffffff           /* entry_number: let the kernel choose */
    movl %esp, %ebx
    movl $243, %eax             /* __NR_set_thread_area */
    int $0x80
    cmpl $0, %eax
    jne tls_failed
    movl (%esp), %eax           /* selected GDT entry number */
    shll $3, %eax
    orl $3, %eax                /* selector = index*8 | RPL 3 */
    movw %ax, %fs
    addl $16, %esp
    movl $0x11223344, %fs:0x18
    movl %fs:0x18, %edi
    movl %edi, %fs:0x1c
    movl %fs:0x1c, %esi
    pushl %esi
    pushl %edi
    movl %esp, %ecx
    movl $8, %edx
    movl $1, %ebx
    movl $4, %eax
    int $0x80
/*
 * LOCK-prefixed read-modify-write. Wine's critical sections use exactly
 * "lock add [mem], 1", and the translated engine emits the same host
 * prefix, so this value is the architectural result to match.
 */
    lock addl $1, lock_target
    movl lock_target, %eax
    pushl %eax
    movl %esp, %ecx
    movl $4, %edx
    movl $1, %ebx
    movl $4, %eax
    int $0x80
/*
 * Bit test and conditional move: "btsl %ecx, %eax" sets a bit and reports
 * the previous one in CF, and "cmovel %esi, %edx" moves only when ZF is set.
 * Both are re-emitted by the translated engine, so these are the values to
 * match.
 */
    movl $0x100, %eax
    movl $4, %ecx
    btsl %ecx, %eax
    movl $0x55, %edx
    movl $0xaa, %esi
    cmpl $0x55, %edx
    cmovel %esi, %edx
    pushl %edx
    pushl %eax
    movl %esp, %ecx
    movl $8, %edx
    movl $1, %ebx
    movl $4, %eax
    int $0x80
    movl $0, %ebx
    movl $1, %eax
    int $0x80
tls_failed:
    /* Report the failure loudly instead of faulting through a null base. */
    movl $2, %ebx
    movl $4, %eax
    int $0x80
    movl $1, %ebx
    movl $1, %eax
    int $0x80
.data
.align 4
lock_target:
    .long 5
.bss
.align 16
tls_block:
    .space 256
.section .note.GNU-stack,"",@progbits
