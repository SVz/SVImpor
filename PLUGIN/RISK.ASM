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
    mov ebx,dword ptr [eax+1]       ;RISK import tricks !!!
    mov eax,dword ptr [eax+8]       ;68DC2AF88D     PUSH 8DF82ADC                           
    xor eax,ebx                     ;81342411CA0032 XOR  DWORD PTR [ESP],3200CA11           
    mov add_,eax    
    popad
    mov eax,add_
    ret
process_add Endp

End DllEntry
