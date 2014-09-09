;-----------------------------------------------------------------------    
;---------------------   PECRYPT V1.02 PLUGIN   ------------------------    
;-----------------------------------------------------------------------    
.386
.model flat,stdcall
option casemap:none
include         \masm32\include\windows.inc
include         \masm32\include\kernel32.inc
includelib      \masm32\lib\kernel32.lib
include         \masm32\include\user32.inc
includelib      \masm32\lib\user32.lib

.const
.data
add_            dd 0
buffer1         dd 0
buffer2         dd 0
patch_code      dd 0
call_add        dd 0
.data?
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    pushad
    mov add_,0
    .if (eax)
      mov call_add,eax
      invoke  IsBadCodePtr,eax          ; is it good code ?
      .if (!eax)
          invoke GetModuleHandle,NULL
          mov edx,eax
          add eax,[eax+03ch]            ;dosstub
          mov edi,eax
          add eax,6
          movsx ecx,byte ptr [eax]
          dec ecx                       ;nb section -1
          imul ecx,28h                  ;section header size
          mov eax,edi
          add eax,0f8h                  ;Section header
          add eax,ecx
          add eax,0ch
          mov eax,dword ptr [eax]       ;vo last section
          add eax,edx
          add eax,565dh                    ;Offset of push bffxxxxx ret Version ??
          .if (byte ptr [eax]==2eh)        ;Is it right code?
             mov patch_code,eax
             mov edi,dword ptr [eax]       ;original save
             mov buffer1,edi
             mov edi,dword ptr [eax+4]     ;original save
             mov buffer2,edi
             mov edi,eax
             add edi,8
             mov byte ptr [eax],0a1h       ;mov eax,[(bffxxxx)]
             inc eax
             mov dword ptr [eax],edi
             add eax,4
             mov byte ptr [eax],0c3h       ;ret
             call [call_add]
             mov add_,eax                  ;eax=bffxxxx
             mov edi,patch_code
             mov eax,buffer1
             mov dword ptr [edi],eax       ;restore original cpde
             mov eax,buffer2
             mov dword ptr [edi+4],eax
        .endif
      .endif
    .endif
    popad
    mov eax,add_
    ret
process_add Endp

include lde32bin.inc   ; LDE32

End DllEntry
