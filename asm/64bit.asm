bits 64

section .text
main:
    mov rax, rbx
    mov rbx, rcx
    mov rax, [rsi]
    mov rax, [eax + ecx*2 - 0xff]
    mov rax, 0x1122334455667788

