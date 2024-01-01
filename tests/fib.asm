bits 64
section .text

; PARAMS
;   rdi: n
; RETURN
;   rax: fib(n)
fibonacci:
    xor rax, rax
    cmp rdi, rdi
    jz .ret1
    cmp rdi, 1
    jz .ret1
    mov rcx, rdi
    sub rcx, 2
    xor rsi, rsi
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
    