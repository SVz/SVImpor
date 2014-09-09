;******************************************* KRYPTON 0.2 SV 22/04/01 ********************************
.386
.model flat,stdcall
option casemap:none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib

.const
k_start equ 40222dh
k_code  equ 6a0038h
k_s     equ 4200c8h

.data
add_ dd 0
buffer1                 dd 0
;.data?
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
    int 3
    mov add_,eax
    mov eax,ebx
    sub eax,k_s
    mov ebx,4
    xor edx,edx
    idiv ebx
    mov edi,eax
    imul edi,6
    add edi,k_start
    
    imul eax,1fh
    add eax,k_code

    mov edx,dword ptr [eax]
    mov buffer1,edx

    mov bl,0c3h
    mov [eax],bl
    mov add_,eax
    call edi
    
    mov edi,add_
    mov add_,eax
    
    mov eax,buffer1
    mov dword ptr [edi],eax         ;restore original cpde


    popad
    mov eax,add_
    ret
process_add Endp

End DllEntry
