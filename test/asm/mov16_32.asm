bits 16
cpu 386

; Test mov to itself
mov eax, eax
mov ecx, ecx
mov edx, edx
mov ebx, ebx
mov esp, esp
mov ebp, ebp
mov esi, esi
mov edi, edi

; Test AX <-> 16 bit
mov eax, ecx
mov ecx, eax
mov eax, edx
mov edx, eax
mov eax, ebx
mov ebx, eax
mov eax, esp
mov esp, eax
mov eax, ebp
mov ebp, eax
mov eax, esi
mov esi, eax
mov eax, edi
mov edi, eax

; Some other 16 bit <-> 16 bit
mov ebx, ecx
mov ecx, ebx
mov esi, edi
mov edi, esi
mov esp, ebp
mov ebp, esp

; Test 32 bit <- IMM
mov eax, 0
mov ecx, 0
mov edx, 0
mov ebx, 0
mov esp, 0
mov ebp, 0
mov esi, 0
mov edi, 0

; Test EBX <- mem16
mov ebx, [bx+si]
mov ebx, [bx+di]
mov ebx, [bp+si]
mov ebx, [bp+di]
mov ebx, [si]
mov ebx, [di]
mov ebx, [0xeeff]
mov ebx, [bx]

; Test EBX < mem32
mov ebx, [eax + ecx*2 + 0x11]
mov ebx, [ebp + ebx*2 + 0x11]
mov ebx, [esp + ebp*2 + 0x11]
mov ebx, [ebx+esi]
mov ebx, [ebx+edi]
mov ebx, [ebp+esi]
mov ebx, [ebp+edi]
mov ebx, [esi]
mov ebx, [edi]
mov ebx, [0xeeff]
mov ebx, [ebx]
