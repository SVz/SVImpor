;-----------------------------------------------------------------------    
;------------------------    VBOX 4.6.2 PLUGIN SV V1.0   ---------------    
;-----------------------------------------------------------------------    
.386
.model flat,stdcall
option casemap:none
include     \masm32\include\windows.inc
include     \masm32\include\kernel32.inc
includelib  \masm32\lib\kernel32.lib
.const
.data
add_            dd 0
.data?
back            dd ?
.code
DllEntry proc hInst:HINSTANCE, reason:DWORD, reserved1:DWORD
      mov  eax,TRUE
      ret
DllEntry Endp

process_add proc
    ;int 3
    pushad
    mov add_,eax
    .if (eax)
      invoke  IsBadCodePtr,eax                  ;is it good code ?
      .if (!eax)
        mov eax,add_
        .if (byte ptr [eax] == 0E8h)            ;call ? 
            mov esi,dword ptr [eax+1]
            add esi,eax                         ;esi is call address
            add esi,5
            add esi,023h                        ;call decrypt offset (4.6.2)            
            .if (byte ptr [esi] == 0E8h)        ;call ? 
                mov edi,dword ptr [esi+1]
                add edi,esi                     ;edi is call address
                add edi,5
                .if (byte ptr [edi-1] == 0C3h)  ;ret ?
                    invoke IsBadCodePtr,edi     ;is it good code ?
                    .if (!eax)
                        mov eax,add_
                        add eax,5                    
                        push return_here
                        push eax
                        
                        PUSH EBP                   
                        MOV EBP, ESP               
                        SUB ESP, 10h                
                        PUSH EBX                   
                        MOV DWORD PTR [EBP-04h], EAX 
                        MOV DWORD PTR [EBP-08h], EBX 
                        MOV DWORD PTR [EBP-0Ch], ECX 
                        MOV DWORD PTR [EBP-010h], EDX
                        LEA EAX, DWORD PTR [EBP-10h]
                        PUSH EAX                   
                        LEA EAX, DWORD PTR [EBP-0Ch] 
                        PUSH EAX                   
                        LEA EAX, DWORD PTR [EBP-8h] 
                        PUSH EAX                   
                        LEA EAX, DWORD PTR [EBP-4h] 
                        PUSH EAX
                                           
                        CALL edi
                        mov add_,eax
                                      
                        ADD ESP, 10h                
                        MOV EAX, DWORD PTR [EBP-4h] 
                        MOV EBX, DWORD PTR [EBP-8h] 
                        MOV ECX, DWORD PTR [EBP-0Ch] 
                        MOV EDX, DWORD PTR [EBP-10h]
                        POP EBX                    
                        LEAVE
                        ADD ESP,4                      
                        RETN                       
                        return_here:                    
                    .endif
                .endif
            .elseif
	         mov eax,add_
                .if (word ptr [eax+15h]==15ffh)
            	    mov edi,dword ptr [eax+17h]
                    mov eax,dword ptr [edi]
                    mov add_,eax
                .endif
            .endif
        .elseif (word ptr [eax+17h]==15ffh)
            mov edi,dword ptr [eax+19h]
            mov eax,dword ptr [edi]
            mov add_,eax
	.endif  
      .endif
    .endif
fin:
    popad
    mov eax,add_
    ret
process_add Endp
End DllEntry
