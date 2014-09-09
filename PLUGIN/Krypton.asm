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
    mov ebx,dword ptr [eax+6]       ;81 05 12 05 67 00 27F9A443 ADD       DWORD PTR [00670512],43A4F927
    mov edi,dword ptr [eax+11]      ;A1 12056700                MOV       EAX,[00670512]
    mov ecx,[edi]
    .if (byte ptr [eax+1]==35h)     ;XOR ?
        xor ecx,ebx
    .else
        add ecx,ebx
    .endif
    mov add_,ecx
    popad
    mov eax,add_
    ret
process_add Endp

End DllEntry
