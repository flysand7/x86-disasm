bits 64

section .text
main:
    ; movd mm0, mm1
    movd mm0, rax
    movd rax, mm0
    paddd mm0, mm1
    paddd mm0, [rax+2*rcx]
