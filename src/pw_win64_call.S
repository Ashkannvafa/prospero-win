/* SPDX-License-Identifier: LGPL-2.1-or-later */
.text
.globl pw_win64_call6
.type pw_win64_call6,@function
pw_win64_call6:
    .cfi_startproc
    /* SysV: rdi=entry, rsi=args. Entry rsp is 8 modulo 16.
     * Reserve home area (32), stack arguments (16), alignment (8). */
    subq $56, %rsp
    .cfi_adjust_cfa_offset 56
    movq %rdi, %rax
    movq 0(%rsi), %rcx
    movq 8(%rsi), %rdx
    movq 16(%rsi), %r8
    movq 24(%rsi), %r9
    movq 32(%rsi), %r10
    movq %r10, 32(%rsp)
    movq 40(%rsi), %r10
    movq %r10, 40(%rsp)
    call *%rax
    addq $56, %rsp
    .cfi_adjust_cfa_offset -56
    ret
    .cfi_endproc
.size pw_win64_call6, .-pw_win64_call6
.section .note.GNU-stack,"",@progbits
