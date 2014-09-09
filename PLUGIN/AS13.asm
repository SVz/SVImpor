;-----------------------------------------------------------------------    
;------------------------ ASProtect 1.3 PLUGIN SV V1.0 -----------------    
;-----------------------------------------------------------------------    
.386
.model flat,stdcall
option casemap:none
include     \masm32\include\windows.inc
include     \masm32\include\kernel32.inc
includelib  \masm32\lib\kernel32.lib
.const
.data
add_        	dd 0
offset_     	dd 0
pre_code_count 	dd 0
pile            dd 0

user32_libname          db "user32.dll",0
kernel32_libname        db "kernel32.dll",0
dialog_procname         db "DialogBoxParamA",0
GetVersion_             db "GetVersion",0
GetCurrentProcess_      db "GetCurrentProcess",0
GetCurrentProcessId_    db "GetCurrentProcessId",0
GetCommandLineA_        db "GetCommandLineA",0


.data?
handle_library          dd ?
tbl         	db 2048 dup (?)             ; 2k for disasm internal table
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
;   int 3
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
        cmp byte ptr [edi+10],0c3h          ;ret 
        jnz fin
        mov edi,dword ptr [edi+6]

        mov ecx,10000h
        mov eax,04244489h       ; mov [esp+04],eax
        repne scasb             ; find _end of text

        test ecx,ecx            ; fooound ?
        jz fin
        
        dec edi
        
        mov eax,0c308c483h      ; add esp,8 ret
        mov dword ptr [edi],eax

        mov eax,add_
        call eax
        mov esi,eax
        
        mov eax,04244489h       ; mov [esp+04],eax
        mov dword ptr [edi],eax
        
        xor eax,eax
        
loop_opcode:

        cmp byte ptr [esi],0c3h     ;ret final ?
        jz final_ret
        
        push    esi
        push    offset tbl
        call    disasm_main     ; disasm opcode
        
        cmp eax,5
        jnz suite
        cmp byte ptr [esi],0e9h     ; jmp final ?
        jz final_jump

suite:
        add pre_code_count,eax
        
        add esi,eax
        jmp loop_opcode

final_jump:
        mov eax,dword ptr [esi+1]
        add eax,esi
        add eax,5        
        jmp good
        
final_ret:
        sub esi,4
        mov eax,dword ptr [esi]
        add eax,5               ; push BFFXXXXX

good:
        sub eax,pre_code_count
        mov add_,eax
                
      .endif
    .endif

fin:
    popad
    mov eax,add_
    ret
process_add Endp
include     lde32bin.inc                ; LDE32
End DllEntry
