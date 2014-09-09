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
jump_return     dd 0
.data?
esp_val         dd ?
hMemory         dd ?
pMemory         dd ?
esp_dll         dd ?
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
;int 3
        mov esp_dll,ecx
        mov bool_safecast,ebx
        mov add_,eax
        mov edi,add_        
        mov ebx,[edi+0Eh]
        add edi,ebx
        add edi,012h
        sub edi,11fah
        cmp byte ptr [edi],0c3h             ;must be ret
        jz good_ret
        sub edi,65bh                        ;****************** B&W
good_ret:
        mov eax,dword ptr [edi]
        mov buffer1,eax
        .if (bool_safecast==1)

            mov dword ptr [edi],0c308c483h  ;add esp,8 ret
;            mov esp_val,esp        ;HH
;            mov esp,0ecfe3ch       ;HH
            call edx
            mov eax,[esp-0Ch]
            mov edx,[esp-08h]
            mov jump_return,edx
;            mov esp,esp_val        ;HH
        .elseif    
            mov dword ptr [edi],0c304c483h  ;add esp,4 ret
            mov esp_val,esp    ;HH
            mov esp,esp_dll   ;HH
            call [add_]
            mov eax,[esp-08h]
            mov esp,esp_val    ;HH
        .endif
        mov add_,eax
        mov eax,buffer1
        mov dword ptr [edi],eax         ;restore original cpde
        
;-----------------------------------------------------------------------    
;-----------------------------------------------------------------------    
;-----------------------------------------------------------------------    
fin:
    .endif
    popad
    mov eax,add_
    mov edx,jump_return
    ret
process_add Endp

End DllEntry
