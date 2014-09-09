;-----------------------------------------------------------------------    
;--------------------- ASPROTECT PLUGIN SV V1.0 ------------------------    
;-----------------------------------------------------------------------    
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
add_                    dd 0
.data?
handle_library          dd ?
tbl                     db      2048 dup (?)    ; 2k for disasm internal table
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
;-----------------------------------------------------------------------    
;----------------------------INIT---------------------------------------    
;-----------------------------------------------------------------------    
    mov add_,0
;    int 3
    .if (eax)
        mov add_,eax
        mov edi,eax
        cmp word ptr [edi+5],0e0ffh ;jmp eax ?
        jnz fin
        mov edi,[edi+1]
        mov eax,[edi+1]

;        push offset tbl      ; build disasm flag tables
;        call disasm_init
;loop_:
;        push edi
;        push offset tbl
;        call disasm_main     ; disasm opcode
;        cmp eax,6
;        jz suite
;        cmp byte ptr [edi],0c3h
;        jz error
;        cmp byte ptr [edi],0c2h
;        jz error
;        add edi,eax
;        jmp loop_

;suite:
;        cmp word ptr [edi],15ffh
;        jz call_detected
;        add edi,eax
;        jmp loop_
;call_detected:
;        mov eax,dword ptr [edi+2]
;        mov eax,dword ptr [eax]
        mov add_,eax    
fin:
    .endif
    popad
    mov eax,add_
    ret
error:
    popad
    popad
    mov eax,0ffffffffh
    ret
process_add Endp

include lde32bin.inc   ; LDE32

End DllEntry
