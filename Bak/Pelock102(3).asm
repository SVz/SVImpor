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
pre_code_count dd 0
pile            dd 0

.data?
tbl         db 2048 dup (?)             ; 2k for disasm internal table
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
;    int 3
;----------------------------INIT---------------------------------------    
    xor  edx,edx
    mov  add_,edx
    mov  offset_,edx
    .if (eax)
      mov     add_,eax
      invoke  IsBadCodePtr,eax          ; is it good code ?
      .if (!eax)
        mov pile,esp
        push    offset tbl              ; build disasm flag tables
        call    disasm_init
        mov     edi,add_
;----------------------------OPCODE LOOP--------------------------------    
loop_opcode:
        cmp byte ptr [edi],68h          ;push 
        jz push_found
        cmp byte ptr [edi],0c3h         ;ret
        jz ret_found
        cmp byte ptr [edi],0EBh         ;jmp 0x
        jz jmp_found
        cmp byte ptr [edi],0E9h         ;jmp XXXXXXXX
        jz long_jmp_found
        cmp byte ptr [edi],0E8h         ;call XXXXXXXX
        jz call_found
        cmp word ptr [edi],0F6C1h       ;INVALID
        jz invalid_found
        cmp word ptr [edi],0F5C1h       ;INVALID
        jz invalid_found

count_code:
        push    edi
        push    offset tbl
        call    disasm_main             ; disasm opcode
        add pre_code_count,eax  

        add edi,eax
        jmp loop_opcode

call_found:
        mov eax,dword ptr [edi+1]
        add eax,5
        add eax,edi
        push eax
        add edi,5     
        jmp loop_opcode


long_jmp_found:
        mov eax,dword ptr [edi+1]
        add eax,5
        add eax,edi
        jmp check_esp

invalid_found:
        cmp byte ptr [edi+2],00
        jnz count_code
        add edi,3
        jmp loop_opcode


jmp_found:
        xor eax,eax
        mov al,byte ptr [edi+1]
        add edi,eax
        add edi,2                                       ; EB02 jmp +2
        jmp loop_opcode

push_found:
        push    edi
        push    offset tbl
        call    disasm_main             ; disasm opcode
        cmp     eax,5                   ; long push ? Must be 5 lengh 
        jnz count_code
                
        mov eax,dword ptr [edi+1]
        cmp eax,edi
        jl count_code                                   ;long push with other value like push 0010000
        
      
suite_push:
        push eax
        push    edi
        push    offset tbl
        call    disasm_main             ; disasm opcode
        add edi,eax
        jmp loop_opcode


ret_found:
        pop edi
        cmp edi,10000000h
        jg right_push
        ;mov edi,push_store
        jmp loop_opcode
        
right_push:
        mov eax,edi
        
check_esp:
        mov edi,pile
        sub edi,esp
        mov ecx,edi
        shr ecx,2
        add edi,ecx
        add pre_code_count,edi
        
sub_pre_code:

        sub eax,pre_code_count
        
        mov add_,eax
        mov esp,pile    
      .endif
    .endif
    popad
    mov eax,add_
    ret
process_add Endp
include     lde32bin.inc                ; LDE32
End DllEntry
