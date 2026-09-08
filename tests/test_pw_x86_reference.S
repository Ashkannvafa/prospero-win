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
    movl $0, %ebx
    movl $1, %eax
    int $0x80
.section .note.GNU-stack,"",@progbits
