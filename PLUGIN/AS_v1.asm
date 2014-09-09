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
add_ dd 0
buffer1 dd 0
buffer2 dd 0
.data?
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
    .if (eax)
        mov add_,eax
        push    offset tbl      ; build disasm flag tables
        call    disasm_init
        mov edi,eax
        push    eax
        push    offset tbl
        call    disasm_main     ; disasm opcode
        cmp eax,5
        jnz _type2 
        mov dl,[edi]
        cmp dl,0e9h             ; jmp direct
        jz _type2
        add edi,eax 
        push    edi
        push    offset tbl
        call    disasm_main     ; disasm opcode
        cmp eax,5
        jnz _type2
        cmp byte ptr [edi],0E8h; call
        jnz _type2
        jmp _type5        
;-----------------------------------------------------------------------    
;---------------------------------------TYPE 2---------------------------    
;-----------------------------------------------------------------------    
_type2:
        mov edi,add_

loop6:
        mov     eax,edi
        push    eax
        push    offset tbl
        call    disasm_main     ; disasm opcode
        cmp eax,5
        jz suite6
next6:    
        add edi,eax
        jmp loop6
suite6:      
        mov dl,[edi]
        cmp dl,0e9h             ;jmp ?
        jz jump6
        cmp dl,068h
        jz push6                ;push / ret
        cmp dl,0e8h
        jnz next6
                                ; Call Getprocaddress ?
        mov eax,dword ptr [edi+1]
        add eax,edi
        add eax,5
        mov eax,dword ptr [eax+2]
        mov eax,dword ptr [eax]
        mov add_,eax    
        jmp fin    
push6:
        cmp byte ptr [edi+5],0c3h
        jnz next6
        mov eax,dword ptr [edi+1]
        add eax,add_
        sub eax,edi
        mov add_,eax    
        jmp fin
jump6:                       ; jmp BFFXXXX
        mov eax,dword ptr [edi+1]
        add eax,add_
        add eax,5
        mov add_,eax    
        jmp fin      
;-----------------------------------------------------------------------    
;---------------------------------------TYPE 5---------------------------    
;-----------------------------------------------------------------------    
_type5:
        mov edx,add_
        mov eax,add_
        mov edi,eax
        add edi,6
        mov edi,dword ptr [edi]
        add eax,edi
        add eax,0ah                     ;import call
        add eax,0c2h                    ;eax is now api offset
        mov edi,dword ptr [eax]
        mov buffer1,edi
        mov edi,dword ptr [eax+4]
        mov buffer2,edi
        mov dword ptr [eax],140c481h    ;patch import call
        mov dword ptr [eax+4],90c30000h ;with add esp ... ret
        mov edi,eax
        call edx                        ;import calling
        mov add_,eax
        mov eax,buffer1
        mov dword ptr [edi],eax         ;restore original cpde
        mov eax,buffer2
        mov dword ptr [edi+4],eax
;-----------------------------------------------------------------------    
;-----------------------------------------------------------------------    
;-----------------------------------------------------------------------    
fin:
    .endif
    popad
    mov eax,add_
    ret
process_add Endp

include lde32bin.inc   ; LDE32

End DllEntry
