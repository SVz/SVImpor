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
;.data?
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
    mov edi,eax
    mov add_,0
    mov eax,edi
    add eax,2
    invoke IsBadCodePtr,eax
    .if (!eax)
        mov edi,dword ptr [edi+2]
        .if (edi)
            invoke IsBadCodePtr,edi
            .if (!eax)
                mov edi,dword ptr [edi]
                .if (edi)
                   mov add_,edi    
                .endif
            .endif        
        .endif
    .endif
    popad
    mov eax,add_
    ret
process_add Endp

End DllEntry
