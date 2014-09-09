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
add_p                   dd 0
buffer1                 dd 0
buffer2                 dd 0
user32_libname          db "user32.dll",0
kernel32_libname        db "kernel32.dll",0
dialog_procname         db "DialogBoxParamA",0
GetVersion_             db "GetVersion",0
GetCurrentProcess_      db "GetCurrentProcess",0
GetCurrentProcessId_    db "GetCurrentProcessId",0
GetCommandLineA_        db "GetCommandLineA",0

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
;        int 3
    mov ebx,eax
    invoke  IsBadCodePtr,ebx          ; is it good code ?
    test eax,eax
    jnz bad_
    mov eax,ebx
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
        cmp byte ptr [edi],0E8h
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
;        cmp eax,1               ; ret case pre-processed API
;        jnz next6
;int 3
;        cmp word ptr [edi+13],0c358h     ;asprotect new trick v1.5 24/12/02
;        jz as15trick
        cmp byte ptr [edi],0c3h
        jz ret_found
        cmp byte ptr [edi],0c2h
        jnz next6
ret_found:
        invoke  GetModuleHandleA,addr kernel32_libname
        .if (!eax)
            invoke LoadLibrary,addr kernel32_libname
        .endif
        mov handle_library,eax

        mov ebx,dword ptr [edi-4]
        invoke  IsBadCodePtr,ebx          ; is it good code ?
        test eax,eax
        jnz error_

        mov ebx,dword ptr [ebx]

apipostprocessed:
        invoke GetProcAddress,handle_library,addr GetVersion_
        mov add_,eax
        call eax
        cmp ebx,eax
        jz fin

        invoke GetProcAddress,handle_library,addr GetCurrentProcess_
        mov add_,eax
        call eax
        cmp ebx,eax
        jz fin

        invoke GetProcAddress,handle_library,addr GetCurrentProcessId_
        mov add_,eax
        call eax
        cmp ebx,eax
        jz fin

        invoke GetProcAddress,handle_library,addr GetCommandLineA_
        mov add_,eax
        call eax
        cmp ebx,eax
        jz fin

error_:
        mov eax,0ffffffffh
        mov add_,eax
        jmp fin
as15trick:
;int 3
        invoke  GetModuleHandleA,addr kernel32_libname
        .if (!eax)
            invoke LoadLibrary,addr kernel32_libname
        .endif
        mov handle_library,eax
        mov ebx,dword ptr [edi+9]
        mov ebx,dword ptr [ebx]
        jmp apipostprocessed

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
;        pushad
;        invoke  IsBadCodePtr,eax          ; is it good code ?
;        test eax,eax
;        jz fin
;        popad
        mov eax,dword ptr [eax+2]
        pushad
        invoke  IsBadCodePtr,eax          ; is it good code ?
        test eax,eax
        jnz error
        popad
        
        cmp byte ptr [edi+28],14h
        jz dialogbox
        
        mov eax,dword ptr [eax]
        mov add_,eax    
        jmp fin    
dialogbox:
        invoke  GetModuleHandleA,addr user32_libname
        .if (!eax)
            invoke LoadLibrary,addr user32_libname
        .endif
        invoke GetProcAddress,eax,addr dialog_procname

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
        add eax,0b8h                    ;eax is now api offset
        cmp byte ptr [eax],089h         ;must be 894504 MOV [EBP+04],EAX
        jz right_code_type5
        xor eax,eax                     ;not right code
        mov add_,eax                    ;clear & exit
        jmp fin 
right_code_type5:
;        int 3
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
error:
    popad
bad_:
    popad
    mov eax,0ffffffffh
    ret
process_add Endp

include lde32bin.inc   ; LDE32

End DllEntry
