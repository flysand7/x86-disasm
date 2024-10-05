bits 16

; Far instructions
call 0x1100
call word [0x1101]
call far word [0x1102]
call word [si]
call far word [si]
jmp 0x1100
jmp word [0x1101]
jmp far word [0x1103]
; retf ; (printed differently)
