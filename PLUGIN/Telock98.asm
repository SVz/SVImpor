.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib

.const
.data
add_ dd 0
;.data?
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
    xor ebx,ebx
    ;int 3
    mov edi,eax
    mov add_,0
loop_s:
    mov eax,dword ptr [edi]
    cmp eax,0c330ff40h
    jz ret_inc_found
    cmp eax,0c330ff90h
    jz ret_found
    inc edi
    jmp loop_s
ret_found:
    inc ebx
ret_inc_found:
    sub edi,4
    mov eax,dword ptr [edi]
    test ebx,ebx
    jnz no_ret
    inc eax
no_ret:
    mov eax,dword ptr [eax]
    mov add_,eax
    popad
    mov eax,add_
    ret
process_add Endp

End DllEntry
