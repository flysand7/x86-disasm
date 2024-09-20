bits 16
cpu 8086

; Opcode 88
mov al, ah
mov ah, al
mov al, bl
mov al, bh
mov ch, dh
mov ch, cl
mov bl, [bx+di]
mov bl, [bp+si]
mov bl, [bp+di]
mov bl, [si]
mov bl, [di]
mov bl, [0xeeff]
mov bl, [bx]

; Opcode 89
mov ax, ax
mov ax, bx
mov bx, ax
mov cx, dx
mov bx, [bx+di]
mov bx, [bp+si]
mov bx, [bp+di]
mov bx, [si]
mov bx, [di]
mov bx, [0xeeff]
mov bx, [bx]

; Opcode 8a
mov [bx+di], bl
mov [bp+si], bl
mov [bp+di], bl
mov [si], bl
mov [di], bl
mov [0xeeff], bl
mov [bx], bl

; Opcode 8b
mov [bx+di], bx
mov [bp+si], bx
mov [bp+di], bx
mov [si], bx
mov [di], bx
mov [0xeeff], bx
mov [bx], bx

; Opcode 8c
mov ax, es
mov ax, ds
mov ax, ss
mov ax, cs

; Opcode 8e
mov es, ax
mov ds, ax
mov ss, ax
mov cs, ax

; Opcodes a0..a3
mov al, [0xeeff]
mov ax, [0xeeff]
mov [0xeeff], al
mov [0xeeff], ax

; Opcodes b0..b7
mov al, -0xf
mov cl, -0xf
mov dl, -0xf
mov bl, -0xf
mov ah, +0xe
mov ch, +0xe
mov dh, +0xe
mov bh, +0xe

; Opcodes b8..bf
mov ax, -0xf
mov cx, -0xf
mov dx, -0xf
mov bx, -0xf
mov sp, +0xe
mov bp, +0xe
mov si, +0xe
mov di, +0xe

; Opcode c6/0
mov byte [bx+si], -0xf
mov byte [bx+si+0x55aa], +0xe
mov byte [bx+si], -0xf
mov byte [bx+si+0x55aa], +0xe

; Opcode c7/0
mov word [bx+si], -0xf
mov word [bx+si+0x55aa], +0xe
mov word [bx+si], -0xf
mov word [bx+si+0x55aa], +0xe
