;-----------------------------------------------------------------------    
;--------------------- SAFECAST  PLUGIN SV V1.0 ------------------------    
;     eax : thunk value   ebx : bool call/call(call)  edx : call offset
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
add_            dd 0
buffer1         dd 0
buffer2         dd 0
bool_safecast   dd 0
.data?
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
;-----------------------------------------------------------------------    
;-----------------------------------------------------------------------    
    .if (eax)
        mov bool_safecast,ebx
        mov add_,eax
        mov edi,add_        
        mov ebx,[edi+20]
        mov edi,[ebx]
        add edi,0d7h
        mov ebx,[edi+1]
        add edi,ebx
        add edi,5dh
        mov eax,dword ptr [edi]
        mov buffer1,eax
        mov eax,dword ptr [edi+4]
        mov buffer2,eax
        .if (bool_safecast==1)
            mov dword ptr [edi],0c308c483h  ;add esp,8 ret
            call edx
            mov eax,[esp-0Ch]
        .elseif    
            mov dword ptr [edi],0c304c483h  ;add esp,4 ret
            call [add_]
            mov eax,[esp-08h]
        .endif
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

End DllEntry
