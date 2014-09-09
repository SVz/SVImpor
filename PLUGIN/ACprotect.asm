;******************************************* KRYPTON 0.2 SV 22/04/01 ********************************
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
    mov ebx,dword ptr [eax+1]
    mov ecx,dword ptr [eax+8]
    xor ebx,ecx
    mov add_,ebx
    popad
    mov eax,add_
    ret
process_add Endp

End DllEntry
