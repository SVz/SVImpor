.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib

;.const
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
    mov ebx,dword ptr [eax+1]       ;YodaCrypt
    add ebx,eax                     ;indirect call
    add ebx,5                       ;jmp BFFXXXXX
    mov add_,ebx    
    popad
    mov eax,add_
    ret
process_add Endp

End DllEntry
