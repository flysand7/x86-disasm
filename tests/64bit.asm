bits 64

section .text
main:
    mov al, bh
    mov ax, bx
    mov ax, [rbx+1]
    mov r9b, r10b
    mov rax, rbx
    mov rbx, rcx
    mov [rsi], rax
    mov [eax + ecx*2 - 0xff], rax
    mov rax, 0x1122334455667788
    jge main

