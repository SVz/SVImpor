;-----------------------------------------------------------------------    
;------------------------ PEX V0.99 PLUGIN SV V1.0 ---------------------    
;-----------------------------------------------------------------------    
.386
.model flat,stdcall
option casemap:none
include     \masm32\include\windows.inc
include     \masm32\include\kernel32.inc
includelib  \masm32\lib\kernel32.lib
.const
.data
add_        dd 0
offset_     dd 0
.data?
tbl         db 2048 dup (?)             ; 2k for disasm internal table
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
;----------------------------INIT---------------------------------------    
    xor  edx,edx
    mov  add_,edx
    mov  offset_,edx
    .if (eax)
      mov     add_,eax
      invoke  IsBadCodePtr,eax          ; is it good code ?
      .if (!eax)
        push    offset tbl              ; build disasm flag tables
        call    disasm_init
        mov     edi,add_
;----------------------------OPCODE LOOP--------------------------------    
loop_opcode:
        push    edi
        push    offset tbl
        call    disasm_main             ; disasm opcode
        cmp     eax,5                   ; long jump ? Must be 5 lengh 
        jnz     no_jmp_api              ;             and start by E9
        mov     dl,[edi]
        cmp     dl,0E9h                 ; jump ?
        jz      jmp_api
no_jmp_api:
        mov     dl,[edi]
        cmp     dl,0EBh                 ; crappy jmp ?
        jz      jmp_crappy
;----------------------------SOME API OPCODE----------------------------    
        add     offset_,eax             ; opcode lengh increment
        add     edi,eax
        jmp     loop_opcode             ; next opcode
;----------------------------FUCKING JUMP-------------------------------    
jmp_crappy:
        xor     edx,edx
        mov     dl,[edi+1]              ; jump value
        add     edi,eax                 ; add opcode lengh
        add     edi,edx                 ; add jump value
        jmp     loop_opcode
;----------------------------FINAL JUMP---------------------------------    
jmp_api:
        mov     eax,dword ptr [edi+1]   ; jmp value
        add     eax,edi                 ; api offset
        add     eax,5                   
        sub     eax,offset_             ; start api address
        mov     add_,eax    
      .endif
    .endif
    popad
    mov eax,add_
    ret
process_add Endp
include     lde32bin.inc                ; LDE32
End DllEntry
