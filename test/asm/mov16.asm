bits 16
cpu 8086

; Opcode 88
mov al, ah
mov ah, al
mov al, bl
mov al, bh
mov ch, dh
mov ch, cl
mov bl, byte [bx+di]
mov bl, byte [bp+si]
mov bl, byte [bp+di]
mov bl, byte [si]
mov bl, byte [di]
mov bl, byte [-0x1122]
mov bl, byte [bx]

; Opcode 89
mov ax, ax
mov ax, bx
mov bx, ax
mov cx, dx
mov bx, word [bx+di]
mov bx, word [bp+si]
mov bx, word [bp+di]
mov bx, word [si]
mov bx, word [di]
mov bx, word [-0x1122]
mov bx, word [bx]

; Opcode 8a
mov byte [bx+di], bl
mov byte [bp+si], bl
mov byte [bp+di], bl
mov byte [si], bl
mov byte [di], bl
mov byte [-0x1122], bl
mov byte [bx], bl

; Opcode 8b
mov word [bx+di], bx
mov word [bp+si], bx
mov word [bp+di], bx
mov word [si], bx
mov word [di], bx
mov word [-0x1122], bx
mov word [bx], bx

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
mov al, byte [-0x1122]
mov ax, word [-0x1122]
mov byte [-0x1122], al
mov word [-0x1122], ax

; Opcodes b0..b7
mov al, 0x0f
mov cl, 0x0f
mov dl, 0x0f
mov bl, 0x0f
mov ah, 0x0e
mov ch, 0x0e
mov dh, 0x0e
mov bh, 0x0e

; Opcodes b8..bf
mov ax, 0x000f
mov cx, 0x000f
mov dx, 0x000f
mov bx, 0x000f
mov sp, 0x000e
mov bp, 0x000e
mov si, 0x000e
mov di, 0x000e

; Opcode c6/0
mov byte [bx+si], 0x01
mov byte [bx+si+0x55aa], 0x0e
mov byte [bx+si], 0x01
mov byte [bx+si+0x55aa], 0x0e

; Opcode c7/0
mov word [bx+si], 0x0001
mov word [bx+si+0x55aa], 0x000e
mov word [bx+si], 0x0001
mov word [bx+si+0x55aa], 0x000e
