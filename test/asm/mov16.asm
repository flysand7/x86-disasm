bits 16
cpu 8086

; Test 8-bit mov
mov al, ah
mov ah, al
mov al, bl
mov al, bh

; Test mov to itself
mov ax, ax
mov cx, cx
mov dx, dx
mov bx, bx
mov sp, sp
mov bp, bp
mov si, si
mov di, di

; Test AX <-> 16 bit
mov ax, cx
mov cx, ax
mov ax, dx
mov dx, ax
mov ax, bx
mov bx, ax
mov ax, sp
mov sp, ax
mov ax, bp
mov bp, ax
mov ax, si
mov si, ax
mov ax, di
mov di, ax

; Some other 16 bit <-> 16 bit
mov bx, cx
mov cx, bx
mov si, di
mov di, si
mov sp, bp
mov bp, sp

; Test 16 bit <- IMM
mov ax, 0
mov cx, 0
mov dx, 0
mov bx, 0
mov sp, 0
mov bp, 0
mov si, 0
mov di, 0

; Test BX <- RM[mod=00]
mov bx, [bx+si]
mov bx, [bx+di]
mov bx, [bp+si]
mov bx, [bp+di]
mov bx, [si]
mov bx, [di]
mov bx, [0xeeff]
mov bx, [bx]

; Test DX <- RM[mod=01]
mov dx, [bx+si+0xef]
mov dx, [bx+di+0xef]
mov dx, [bp+si+0xef]
mov dx, [bp+di+0xef]
mov dx, [si+0xef]
mov dx, [di+0xef]
mov dx, [bp+0xef]
mov dx, [bx+0xef]

; Test CX <- RM[mod=02]
; mov ax, [bx+si+0xeffe]
mov cx, [bx+di+0x4455]
mov cx, [bp+si+0x4455]
mov cx, [bp+di+0x4455]
mov cx, [si+0x4455]
mov cx, [di+0x4455]
mov cx, [bp+0x4455]
mov cx, [bx+0x4455]