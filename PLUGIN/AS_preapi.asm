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
GetVersionExA_          db "GetVersionExA",0
GetCurrentProcess_      db "GetCurrentProcess",0
GetCurrentProcessId_    db "GetCurrentProcessId",0
GetCommandLineA_        db "GetCommandLineA",0
FreeResource_           db "FreeResource",0
LockResource_           db "LockResource",0

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
    .if (eax)
        mov ebx,esp
        mov add_,eax
        
        invoke  GetModuleHandleA,addr kernel32_libname
        .if (!eax)
            invoke LoadLibrary,addr kernel32_libname
        .endif
        mov handle_library,eax
        mov eax,add_
        
        call eax        ;call to return right value
        
        cmp ebx,esp     ;Free and Lock -> esp+4
        jnz resource
        
        mov ebx,eax
        
        invoke  GetModuleHandleA,addr kernel32_libname
        .if (!eax)
            invoke LoadLibrary,addr kernel32_libname
        .endif
        mov handle_library,eax

;        mov ebx,dword ptr [edi-4]
;        invoke  IsBadCodePtr,ebx          ; is it good code ?
;        test eax,eax
;        jnz error_


apipostprocessed:
        invoke GetProcAddress,handle_library,addr GetVersion_
        mov add_,eax
        call eax
        cmp ebx,eax
        jz fin

;        invoke GetProcAddress,handle_library,addr GetVersionExA_
;        mov add_,eax
;        call eax
;        cmp ebx,eax
;        jz fin

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
        
resource:
        mov esp,ebx
        cmp eax,edi
        jnz free_
        invoke GetProcAddress,handle_library,addr LockResource_
        mov add_,eax
        jmp fin
free_:        
        invoke GetProcAddress,handle_library,addr FreeResource_
        mov add_,eax
        jmp fin
        
fin:
    .endif
    popad
    mov eax,add_
    ret
error:
    popad
    mov eax,0ffffffffh
    ret
process_add Endp
End DllEntry
