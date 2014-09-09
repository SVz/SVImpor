;-----------------------------------------------------------------------    
;--------------------- ARMA2 PLUGIN SV V1.0 ------------------------    
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
    mov add_,eax    
    mov eax,dword ptr [eax+1]
    mov add_,eax    
    
fin:
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
