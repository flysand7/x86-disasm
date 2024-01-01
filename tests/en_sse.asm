cpu x86-64
bits 64

global enable_sse
global halt_catch_fire

section .text

enable_sse:
    mov rax, cr0
    and ax, 0xfffb
    or  ax, 0x0002
    mov rax, cr4
    or  ax, 3<<9
    mov cr4, rax
    ret

halt_catch_fire:
    cli
.loop:
    hlt
    jmp .loop
