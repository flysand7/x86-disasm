bits 64
section .text

; PARAMS
;   rdi: n
; RETURN
;   rax: fib(n)
fibonacci:
    mov rax, 0
    cmp rdi, rdi
    jz .ret1
    cmp rdi, 1
    jz .ret1
    mov rcx, rdi
    dec rcx
    dec rcx
    mov rsi, 0
    mov rdi, 1
.loop:
    mov rax, rsi
    add rax, rdi
    mov rdi, rsi
    mov rsi, rax
    dec rcx
    jnz .loop
.ret1:
    ret
    