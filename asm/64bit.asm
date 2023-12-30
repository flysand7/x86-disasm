bits 64

section .text
main:
    mov rax, rbx
    mov rbx, rcx
    mov [rsi], rax
    mov [eax + ecx*2 - 0xff], rax
    mov rax, 0x1122334455667788

