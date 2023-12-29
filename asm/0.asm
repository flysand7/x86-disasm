bits 16

section .text
main:
    mov eax, ebx
    mov ax, cs:[bx]
    mov ax, ds:[0x88ff]
    mov ax, ax
    mov bx, bx
    mov ax, bx
    mov ax, cx
    mov ax, [si]
