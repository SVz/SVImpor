;v1.7.3
.386
.model flat,stdcall
option casemap:none
WinMain proto :DWORD,:DWORD,:DWORD,:DWORD
svadditemmodule proto :DWORD, :DWORD, :DWORD
svadditemapi proto :DWORD, :DWORD, :DWORD, :DWORD
getprocname proto :DWORD,:DWORD,:DWORD
fonction2name proto :DWORD,:DWORD

include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
include \masm32\include\gdi32.inc
include \masm32\include\masm32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\advapi32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\gdi32.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\comdlg32.lib
includelib \masm32\lib\advapi32.lib

.const
IDC_REFRESH                                     equ 3000
IDC_EXIT                                        equ 3001
IDC_MODULE                                      equ 3002
IDC_RVA                                         equ 3003
IDC_API                                         equ 3004
IDC_ADDRESS                                     equ 3005
IDC_VIEW                                        equ 3006
IDC_SEARCH                                      equ 3007
IDC_NEXT                                        equ 3008
IDC_GO                                          equ 3009
IDC_RELOC                                       equ 3010
IDC_LISTAPI                                     equ 3011
IDC_START                                       equ 3012
IDC_END                                         equ 3013
IDC_SAVE                                        equ 3014
IDC_LISTPLUG                                    equ 3015
IDC_PLUG                                        equ 3016
IDC_LISTERROR                                   equ 3017
IDC_UPDATE                                      equ 3018
IDC_SAFE                                        equ 3019
IDC_PROGRESS                                    equ 3020
IDC_SAFEAPI                                     equ 3021

LIMITEDLL equ 20000000h
MAXSIZE equ 260
PBM_SETRANGE32 equ     (1030)

SEH struct
    PrevLink dd ?       ; the address of the previous seh structure
    CurrentHandler dd ? ; the address of the new exception handler
    SafeOffset dd ? ; The offset where it's safe to continue execution
    PrevEsp dd ?        ; the old value in esp
    PrevEbp dd ?        ; The old value in ebp
SEH ends

;##############################################################################

.data
ClassName       db "DLGCLASS",0
MenuName        db "MyMenu",0
DlgName         db "SVDialog",0
AppName         db "SV",0
ofn             OPENFILENAME <>
tag_context     CONTEXT <>
buffer          db MAXSIZE dup(0)
dll_name_buffer db MAXSIZE dup(0)
hMapFile        HANDLE 0
hwMapFile       HANDLE 0
FilterString    db "Bin Files",0,"*.bin",0,0
template        db "%x",0  
txtemplate      db "%s",0             

mapicz          db "IczMap",0
iczevent        db "IczEvent",0

template_deci   db "%08X",0
template_ordi   db "Ordinal :%08X -> %s",0
template_ord    db "Ordinal :%08X",0
template_api    db "%s -> %s",0
template_cal    db "DLL:%d - API:%d IAT Size:%d",0
template_err    db "Error thunk entry at %x value: %x",0
template_log    db "Thunk: %x -> call@: %x -> value: %x -> %s -> %s",0dh,0ah,0
template_logjmp db "Jump -> call@: %x -> value: %x -> %s -> %s",0dh,0ah,0
nbitem          dd 0
Titlecolumn     db "API Name",0
Titlecolumn1    db "Module Name",0
Titlecolumn0    db "Offset",0
Titlecolumn2    db "Address",0
Titlecolumn3    db "Module Name",0
Titlecolumn4    db "Base",0
Titlecolumn5    db "Size",0
errormsg        db "%x Not found !!!",0
dir_plug        db "plugin/*.dll",0
plug_fontion_n  db "process_add",0
antislash       db "\",0
message_error   db "Error rebuilding IT !",0
message_error_update   db "Error updating thunk !",0
message_error_search   db "Error searching !",0
szsvKey         db  '\Software\SV',0
szsvDir         db  'plugdir',0
szSIZE          dd 256
search_call     db 0ffh,015h
add_to_search   dd 0
v_rva           dd 0
buffer1         dd 0
buffer2         dd 0
kernel          db "kernel32.dll",0
openprocess     db "OpenProcess",0

;##############################################################################

.data?
file32          WIN32_FIND_DATA <>
p_hInstance     HINSTANCE ?
CommandLine     LPSTR ?
hFileRead       HANDLE ?
hFileWrite      HANDLE ?
lpTargetHandle  HANDLE ?
SizeWritten     DWORD ?
hMemory         HANDLE ?
pMemory         DWORD ?
textbuffer      db 512 dup(?)
plugbuffer      db 512 dup(?)
textbuffer2     db 512 dup(?)
buffer_api_name db 512 dup(?)
buffer_dll_name db 512 dup(?)
et_741c         dd ?
et_73b8         dd ?
p_base          dd ?
et_7464         dd ?
pe_base         dd ?
et_742c         dd ?
lpThreadId      dd ?
dllhandle       dd ?
;v_rva           dd ?
v_add           dd ?
mo32 MODULEENTRY32 <?>
hSnapshot       DWORD ?
hwnd            dd ?
pitem LVITEM <?>
pcol LVCOLUMN <?>
entry_size      dd ?
thunk_size      dd ?
base_section    dd ?
index_apiname   dd ?
index_entry     dd ?
index_api       dd ?
file_size       dd ?
nbdll           dd ?
nbapi           dd ?
ordi            dd ?
addsearch       dd ?
v_end           dd ?
v_start         dd ?
testhandle      dd ?
hReg            dd ?
lpdwDisposition dd ?
update_rva      dd ?
update_address  dd ?
code_start      dd ?
code_size       dd ?
code_end        dd ?
code_index      dd ?
image_size      dd ?
thunk_start     dd ?
;thunk_size  dd ?
index_thunk     dd ?
index_buffer    dd ?
index_safeapi   dd ?
right_rva       dd ?
pMemory_newthunk dd ?
hMemory_newthunk dd ?
base_thunk      dd ?
pMemory_code    dd ?
hMemory_code    dd ?
pMemory_log     dd ?
hMemory_log     dd ?
plugin_api_address dd ?
handle_library_safe DWORD ?
one_wrapped     dd ?
tbl             db      2048 dup (?)    ; 2k for disasm internal table
nb_bytes        dd ?
api_call        dd ?
obsfucator      dd ?
id_pro          dd ?
esp_value       dd ?
index_err       dd ?
align dword
context CONTEXT <>
.code
;--------------------------------------------------------------------
;##############################################################################
;--------------------------------------------------------------------
DllEntry proc hInstance:HINSTANCE, reason:DWORD, reserved1:DWORD
    .if reason==DLL_PROCESS_ATTACH
        mov esp_value,esp       ; safedisk2 esp for plugin
        mov et_741c, 00000000
        push [ebp+08h]                     
        pop dllhandle  
        push 00000000                     
        call GetModuleHandleA

        mov p_base, eax
        mov et_7464, eax
        add eax, dword ptr [eax+3Ch]
        mov pe_base, eax
        mov et_742c, eax
        push edi

        Call GetCurrentThread
        mov edi, eax
        Call GetCurrentProcess

        push 00000002
        push 00000000
        push 00000000
        push offset lpTargetHandle
        push eax
        push edi
        push eax
        Call DuplicateHandle

        pop edi
        push offset lpThreadId
        push 00000000
        push 00000000
        lea eax,svstart
        push eax
        push 00000000
        push 00000000
        Call CreateThread
        push eax
        Call CloseHandle
        mov eax, 00000001
        ret

    .elseif reason==DLL_PROCESS_DETACH
    .endif
        mov eax, 00000001
        ret
DllEntry Endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
SEHHandler proc C uses edx pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
    mov edx,pFrame      
    assume edx:ptr SEH
    mov eax,pContext
    assume eax:ptr CONTEXT
    push [edx].SafeOffset
    pop [eax].regEip
    push [edx].PrevEsp
    pop [eax].regEsp
    push [edx].PrevEbp
    pop [eax].regEbp
    mov eax,ExceptionContinueExecution
    ret
SEHHandler endp
;------------------------------------------------------------------------------
;##############################################################################
;##############################################################################
;##############################################################################
;------------------------------------------------------------------------------
svstart:
    invoke WinMain, dllhandle,NULL,NULL, SW_SHOWDEFAULT
exit:
    invoke FreeLibraryAndExitThread,dllhandle,eax
;    invoke ExitThread,eax
;    invoke ExitProcess,eax
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
WinMain proc hInst:HINSTANCE,hPrevInst:HINSTANCE,CmdLine:LPSTR,CmdShow:DWORD
    LOCAL wc:WNDCLASSEX
    LOCAL msg:MSG
    LOCAL hDlg:HWND
    LOCAL hPicture:HWND
    
    mov   wc.cbSize,SIZEOF WNDCLASSEX
    mov   wc.style, CS_HREDRAW or CS_VREDRAW
    mov   wc.lpfnWndProc, OFFSET WndProc
    mov   wc.cbClsExtra,NULL
    mov   wc.cbWndExtra,DLGWINDOWEXTRA
    push  hInst
    pop   wc.hInstance
    mov   wc.hbrBackground,COLOR_BTNFACE+1
    mov   wc.lpszClassName,OFFSET ClassName
    
    invoke LoadIcon,hInst,1
    mov   wc.hIcon,eax
    mov   wc.hIconSm,eax
    invoke LoadCursor,NULL,IDC_ARROW
    mov   wc.hCursor,eax
    invoke RegisterClassEx, addr wc
    invoke CreateDialogParam,hInst,65h,NULL,NULL,NULL
    mov   hDlg,eax
    INVOKE ShowWindow, hDlg,SW_SHOWNORMAL
    INVOKE UpdateWindow, hDlg

    mov ofn.lStructSize,SIZEOF ofn
    push hDlg
    pop  ofn.hWndOwner
    push hInst
    pop  ofn.hInstance
    mov  ofn.lpstrFilter, OFFSET FilterString
    mov  ofn.lpstrFile, OFFSET buffer
    mov  ofn.nMaxFile,MAXSIZE

    mov pcol.imask,LVCF_FMT or LVCF_TEXT or LVCF_WIDTH or LVCF_SUBITEM
    mov pcol.fmt,LVCFMT_LEFT
    mov pcol.lx,329
    mov pcol.pszText,offset Titlecolumn3
    mov pcol.iSubItem,0
    invoke GetDlgItem,hDlg,IDC_MODULE
    invoke SendMessage,eax,LVM_INSERTCOLUMN,1,offset pcol

    mov pcol.iSubItem,1
    mov pcol.pszText,offset Titlecolumn5
    mov pcol.lx,70
    mov pcol.fmt,LVCFMT_RIGHT
    invoke GetDlgItem,hDlg,IDC_MODULE
    invoke SendMessage,eax,LVM_INSERTCOLUMN,1,offset pcol

    mov pcol.iSubItem,2
    mov pcol.pszText,offset Titlecolumn4
    mov pcol.lx,70
    mov pcol.fmt,LVCFMT_RIGHT
    invoke GetDlgItem,hDlg,IDC_MODULE
    invoke SendMessage,eax,LVM_INSERTCOLUMN,1,offset pcol

    mov eax,pe_base
    mov eax,dword ptr [eax+50h]       ;Size (new section must start at size offset)
    invoke wsprintf,addr textbuffer,offset template,eax
    invoke SetDlgItemText,hDlg,IDC_RELOC,addr textbuffer

    mov pcol.imask,LVCF_FMT or LVCF_TEXT or LVCF_WIDTH or LVCF_SUBITEM
    mov pcol.fmt,LVCFMT_LEFT
    mov pcol.lx,160
    mov pcol.pszText,offset Titlecolumn
    mov pcol.iSubItem,0
    invoke GetDlgItem,hDlg,IDC_LISTAPI
    invoke SendMessage,eax,LVM_INSERTCOLUMN,1,offset pcol

    mov pcol.iSubItem,1
    mov pcol.pszText,offset Titlecolumn2
    mov pcol.lx,68
    mov pcol.fmt,LVCFMT_RIGHT
    invoke GetDlgItem,hDlg,IDC_LISTAPI
    invoke SendMessage,eax,LVM_INSERTCOLUMN,1,offset pcol

    mov pcol.iSubItem,2
    mov pcol.pszText,offset Titlecolumn0
    mov pcol.lx,62
    mov pcol.fmt,LVCFMT_RIGHT
    invoke GetDlgItem,hDlg,IDC_LISTAPI
    invoke SendMessage,eax,LVM_INSERTCOLUMN,1,offset pcol

    mov pcol.iSubItem,3
    mov pcol.pszText,offset Titlecolumn1
    mov pcol.lx,100
    mov pcol.fmt,LVCFMT_LEFT
    invoke GetDlgItem,hDlg,IDC_LISTAPI
    invoke SendMessage,eax,LVM_INSERTCOLUMN,1,offset pcol
    
    push hDlg
    pop hwnd
    call plugin_fill

    invoke SendMessage,hDlg,WM_COMMAND,IDC_REFRESH,BN_CLICKED
    
    .WHILE TRUE
                INVOKE GetMessage, ADDR msg,NULL,0,0
                .BREAK .IF (!eax)
                invoke IsDialogMessage, hDlg, ADDR msg
                .if eax==FALSE
                        INVOKE TranslateMessage, ADDR msg
                        INVOKE DispatchMessage, ADDR msg
                .endif
    .ENDW
    mov     eax,msg.wParam
    ret
WinMain endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
WndProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
    LOCAL seh:SEH
    .IF uMsg==WM_DESTROY
        invoke PostQuitMessage,NULL
    .ELSEIF uMsg==WM_COMMAND
        mov eax,wParam
        mov edx,wParam
        shr edx,16
        .IF dx==BN_CLICKED
;------------------------------------------------------------------------------
            .IF ax==IDC_REFRESH
                mov nbitem,0
                invoke GetDlgItem,hwnd,IDC_MODULE
                invoke SendMessage,eax,LVM_DELETEALLITEMS,0,0
                push hWnd
                pop hwnd
                invoke GetCurrentProcessId
                invoke CreateToolhelp32Snapshot, TH32CS_SNAPMODULE, eax 
                mov hSnapshot, eax
                mov mo32.dwSize, sizeof MODULEENTRY32
                invoke Module32First, hSnapshot, addr mo32
            svloopm:
                invoke wsprintf,addr textbuffer,offset template_deci,mo32.modBaseAddr
                invoke wsprintf,addr textbuffer2,offset template_deci,mo32.modBaseSize
                invoke svadditemmodule,addr mo32.szExePath,addr textbuffer,addr textbuffer2
                invoke Module32Next, hSnapshot, addr mo32
                test eax,eax
                jnz svloopm
                invoke CloseHandle, hSnapshot
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_VIEW
                assume fs:nothing
                push fs:[0]
                pop seh.PrevLink
                mov seh.CurrentHandler,offset SEHHandler
                mov seh.SafeOffset,offset error_view
                lea eax,seh
                mov fs:[0], eax
                mov seh.PrevEsp,esp
                mov seh.PrevEbp,ebp
;int 3
;                invoke GetCurrentThreadId
;                mov id_pro,eax
;                invoke GetCurrentProcessId
;                mov ebx,fs:[30h]
;                xor ebx,eax
;                mov obsfucator,ebx
;                invoke GetModuleHandle,addr kernel
;                invoke GetProcAddress,eax,addr openprocess
;                mov edi,eax
;                add edi,24h
;                mov eax,id_pro
;                xor eax,obsfucator
;                push 7ah
;                push 0
;                push id_pro
;                call edi
;                invoke GetThreadContext,eax,offset tag_context
;                mov eax,tag_context.regEsp
                invoke GetDlgItemText,hWnd,IDC_RVA,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov v_rva,eax
                .if (eax)
                        mov eax,dword ptr [eax]
                        invoke wsprintf,addr textbuffer,offset template_deci,eax
                        invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
                .endif
            error_view:
                push seh.PrevLink
                pop fs:[0]
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_SEARCH
                pushad
                assume fs:nothing
                push fs:[0]
                pop seh.PrevLink
                mov seh.CurrentHandler,offset SEHHandler
                mov seh.SafeOffset,offset error_search
                lea eax,seh
                mov fs:[0], eax
                mov seh.PrevEsp,esp
                mov seh.PrevEbp,ebp

                invoke GetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer,10
                invoke htodw,addr textbuffer

                mov v_add,eax
                .if (eax)
                    invoke getprocname,v_add,addr buffer_dll_name,addr buffer_api_name
                    .if (eax==0ffffffffh)
                        mov eax,v_add
                        call plugin_process
                        mov v_add,eax
                        invoke getprocname,v_add,addr buffer_dll_name,addr buffer_api_name
                    .endif                    
                    .if (eax)
                        .if (eax==0ffffffffh)
                            invoke wsprintf,addr textbuffer,offset errormsg,v_add
                            invoke SetDlgItemText,hWnd,IDC_API,addr textbuffer
                        .else
                            invoke wsprintf,addr textbuffer,offset template_ordi,eax,addr buffer_dll_name
                            invoke SetDlgItemText,hWnd,IDC_API,addr textbuffer
                        .endif
                    .else        
                        invoke wsprintf,addr textbuffer,offset template_api,addr buffer_api_name,addr buffer_dll_name
                        invoke SetDlgItemText,hWnd,IDC_API,addr textbuffer
                    .endif
                .endif
                jmp error_search_end                                
            error_search:
                push seh.PrevLink
                pop fs:[0]
                invoke MessageBox,NULL,addr message_error_search,addr AppName,MB_OK
                jmp end_search
            error_search_end:
                push seh.PrevLink
                pop fs:[0]
            end_search:
                popad
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_NEXT
                add v_rva,4
                mov eax,dword ptr [v_rva]
                .if (eax)
                        invoke wsprintf,addr textbuffer,offset template,eax
                        invoke SetDlgItemText,hWnd,IDC_RVA,addr textbuffer
                        invoke SendMessage,hWnd,WM_COMMAND,IDC_VIEW,BN_CLICKED
                        invoke SendMessage,hWnd,WM_COMMAND,IDC_SEARCH,BN_CLICKED
                .endif
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_SAFE
                pushad
                assume fs:nothing
                push fs:[0]
                pop seh.PrevLink
                mov seh.CurrentHandler,offset SEHHandler
                mov seh.SafeOffset,offset safe_safe
                lea eax,seh
                mov fs:[0], eax
                mov seh.PrevEsp,esp
                mov seh.PrevEbp,ebp

                call get_code_section_info  ; get code offset and section size

                call search_plug_api        ; plugin address in plugin_api_address
                
                invoke GetDlgItemText,hWnd,IDC_RELOC,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov base_thunk,eax

                invoke GetDlgItemText,hwnd,IDC_END,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov v_end,eax

                invoke GetDlgItemText,hWnd,IDC_START,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov v_start,eax

                invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,10000h
                mov  hMemory_newthunk,eax
                invoke GlobalLock,hMemory_newthunk
                mov  pMemory_newthunk,eax
                call fill_thunk             ; fill thunk's array copy with right API address
                
;__________________________________________________________________________________________
;                invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,code_size
;                mov  hMemory_log,eax
;                invoke GlobalLock,hMemory_log
;                mov  pMemory_log,eax
;__________________________________________________________________________________________

                invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,code_size
                mov  hMemory_code,eax
                invoke GlobalLock,hMemory_code
                mov  pMemory_code,eax
                call copy_code              ; copy all code section in buufer to allow writting
                
                call search_fix_call        ; search all Call [xxxx] to fix IAT (multi IAT/thunk)
                
                call search_fix_jump        ; search jump to unwrapper

                mov [buffer],0  ;filename buffer a vide
                invoke GetSaveFileName, ADDR ofn
                .if eax==TRUE
                        invoke CreateFile,ADDR buffer,\
                           GENERIC_READ or GENERIC_WRITE ,\
                           FILE_SHARE_READ or FILE_SHARE_WRITE,\
                           NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,\
                           NULL
                        mov hFileWrite,eax
                        invoke WriteFile,hFileWrite,pMemory_code,code_size,ADDR SizeWritten,NULL
                        invoke CloseHandle,hFileWrite
                .endif
                
;__________________________________________________________________________________________
;int 1
;                invoke GlobalUnlock,pMemory_log
;                invoke GlobalFree,hMemory_log
;__________________________________________________________________________________________

                invoke GlobalUnlock,pMemory_code
                invoke GlobalFree,hMemory_code

                invoke GlobalUnlock,pMemory_newthunk
                invoke GlobalFree,hMemory_newthunk

                invoke FreeLibrary,handle_library_safe

            safe_safe:
                push seh.PrevLink
                pop fs:[0]
                popad   
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_SAFEAPI
                pushad               
                call get_code_section_info  ; get code offset and section size
                call search_safe_api
                invoke GetDlgItem,hwnd,IDC_PROGRESS
                invoke SendMessage,eax,PBM_SETRANGE32,0,index_safeapi
                  
                mov index_safeapi,0
            loop_decrypt_api:
                invoke GetDlgItem,hwnd,IDC_LISTERROR
                invoke SendMessage,eax,LB_GETTEXT,index_safeapi,offset buffer
                cmp eax,0ffffffffh
                jz fin_decrypt_api
                invoke htodw,addr buffer
                mov api_call,eax
                call decrypt_api
                add index_safeapi,1
                invoke GetDlgItem,hwnd,IDC_PROGRESS
                invoke SendMessage,eax,PBM_SETPOS,index_safeapi,0
                jmp loop_decrypt_api
            fin_decrypt_api:
                invoke GetDlgItem,hwnd,IDC_LISTERROR
                invoke SendMessage,eax,LB_RESETCONTENT,0,0
                invoke GetDlgItem,hwnd,IDC_PROGRESS
                invoke SendMessage,eax,PBM_SETPOS,0,0
                popad
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_UPDATE
                pushad
                assume fs:nothing
                push fs:[0]
                pop seh.PrevLink
                mov seh.CurrentHandler,offset SEHHandler
                mov seh.SafeOffset,offset error_update
                lea eax,seh
                mov fs:[0], eax
                mov seh.PrevEsp,esp
                mov seh.PrevEbp,ebp

                invoke GetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov update_address,eax

                invoke GetDlgItemText,hWnd,IDC_RVA,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov update_rva,eax

                invoke  IsBadCodePtr,eax          ; is it good code ?
                .if (!eax)
                    mov edi,update_rva
                    mov eax,update_address
                    .if (eax)
                        mov [edi],eax
                    .endif
                .endif
                jmp error_update_end
                
            error_update:
                push seh.PrevLink
                pop fs:[0]
                invoke MessageBox,NULL,addr message_error_update,addr AppName,MB_OK
                jmp end_update
            error_update_end:
                push seh.PrevLink
                pop fs:[0]
            end_update:
                popad

;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_GO
                pushad
                assume fs:nothing
                push fs:[0]
                pop seh.PrevLink
                mov seh.CurrentHandler,offset SEHHandler
                mov seh.SafeOffset,offset error_Rebuild_IAT
                lea eax,seh
                mov fs:[0], eax
                mov seh.PrevEsp,esp
                mov seh.PrevEbp,ebp

                push hWnd
                pop hwnd
                call Rebuild_IAT
                jmp error_Rebuild_IAT_end
                
            error_Rebuild_IAT:
                push seh.PrevLink
                pop fs:[0]
                invoke MessageBox,NULL,addr message_error,addr AppName,MB_OK
                jmp end_rebuild
            error_Rebuild_IAT_end:
                push seh.PrevLink
                pop fs:[0]
            end_rebuild:
                popad
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_SAVE
                pushad
                mov [buffer],0  ;filename buffer a vide
                invoke GetSaveFileName, ADDR ofn
                .if eax==TRUE
                        invoke CreateFile,ADDR buffer,\
                           GENERIC_READ or GENERIC_WRITE ,\
                           FILE_SHARE_READ or FILE_SHARE_WRITE,\
                           NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,\
                           NULL
                        mov hFileWrite,eax
                        invoke WriteFile,hFileWrite,pMemory,file_size,ADDR SizeWritten,NULL
                        invoke CloseHandle,hFileWrite
                .endif
                invoke CloseHandle, hSnapshot
                invoke GlobalUnlock,pMemory
                invoke GlobalFree,hMemory
                popad
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_EXIT
                invoke DestroyWindow,hWnd
            .ENDIF
        .ELSEIF dx==LBN_SELCHANGE ;DBLCLK
            .IF ax==IDC_LISTPLUG
                invoke GetDlgItem,hWnd,IDC_PLUG
                invoke SendMessage,eax,BM_SETCHECK,BST_CHECKED,0
            .ELSEIF ax==IDC_LISTERROR
                invoke GetDlgItem,hWnd,IDC_LISTERROR
                invoke SendMessage,eax,LB_GETCURSEL,0,0
                mov index_err,eax
                invoke GetDlgItem,hWnd,IDC_LISTERROR
                invoke SendMessage,eax,LB_GETTEXT,index_err,addr buffer
                invoke SetDlgItemText,hWnd,IDC_RVA,addr buffer
                invoke SendMessage,hWnd,WM_COMMAND,IDC_VIEW,BN_CLICKED
                invoke SendMessage,hWnd,WM_COMMAND,IDC_SEARCH,BN_CLICKED
             .ENDIF
        .ENDIF
    .ENDIF
    invoke DefWindowProc,hWnd,uMsg,wParam,lParam
    ret
WndProc endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
search_safe_api proc
;LOCAL nb_bytes:DWORD
    pushad
    invoke GetDlgItem,hwnd,IDC_PROGRESS
    invoke SendMessage,eax,PBM_SETRANGE32,code_start,code_end

    mov index_safeapi,0
    
    mov eax,p_base
    add image_size,eax
    
    push    offset tbl      ; build disasm flag tables
    call    disasm_init

    mov edi,code_start

loop_search_api:
    push    edi
    push    offset tbl
    call    disasm_main     ; disasm opcode
    .if eax==0ffffffffh
        mov eax,1
    .endif
    mov nb_bytes,eax
    .if eax==5
        .if byte ptr [edi] == 0e9h
            pushad
            invoke GetDlgItem,hwnd,IDC_PROGRESS
            invoke SendMessage,eax,PBM_SETPOS,edi,0
            popad
            mov ebx,[edi+1]
            add ebx,edi
            add ebx,5
            .if ebx>image_size
              invoke  IsBadCodePtr,ebx          ; is it good code ?
                .if (!eax)
                    .if byte ptr [ebx]==68h
                        pushad
                        add index_safeapi,1
                        invoke wsprintf,addr textbuffer2,offset template,edi
                        invoke GetDlgItem,hwnd,IDC_LISTERROR
                        invoke SendMessage,eax,LB_ADDSTRING,0,offset textbuffer2
                        INVOKE UpdateWindow, hwnd
                        popad
                    .endif
                .endif
            .endif
        .endif
    .endif
    add edi,nb_bytes
    cmp edi,code_end
    jl loop_search_api        
    invoke GetDlgItem,hwnd,IDC_PROGRESS
    invoke SendMessage,eax,PBM_SETPOS,0,0
    popad
    ret
search_safe_api endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
decrypt_api proc
    pushad
test_api:
;    int 3
    mov eax,api_call
    mov edi,dword ptr [eax+1]
    add edi,eax
    add edi,5
    mov edi,dword ptr [edi+0fh]    ;B&W
;    mov edi,dword ptr [edi+19h]    ;Alice
    
    mov edi,dword ptr [edi]
    add edi,458h                   ;B&W
;    add edi,5d1h                   ;Alice
    lea eax,test_ret
    mov byte ptr [edi],0e9h
    sub eax,edi
    sub eax,5
    mov [edi+1],eax
    mov eax,api_call
    jmp eax

test_ret:
    push eax
    mov eax,api_call
    cmp dword ptr [esp],eax
    pop eax
    jz call_decrypted
    ret
call_decrypted:
    add esp,4
    popad
    ret
decrypt_api endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
get_code_section_info proc
    pushad
    mov edi,p_base
    add edi,[edi+03ch]            ;dosstub
    mov eax,dword ptr [edi+050h]
    mov image_size,eax
    add edi,100h                  ;first section size
    mov eax,dword ptr [edi]
    mov code_size,eax
    add edi,4                     ;first section offset
    mov eax,dword ptr [edi]
    add eax,p_base
    mov code_start,eax
    add eax,code_size
    mov code_end,eax    
    popad
    ret
get_code_section_info endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
copy_code proc                      ;copy first section in buffer
    pushad
    mov ecx,code_size
    mov esi,code_start
    mov edi,pMemory_code
    rep movsb
    popad
    ret
copy_code endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
get_jmp_section proc                ;get section jmp if present (section nb -2)
LOCAL stx_offset:DWORD
LOCAL stx_size:DWORD
    pushad
    xor eax,eax
    mov edi,p_base
    add edi,[edi+03ch]              ; dosstub
    mov al,[edi+06h]
    sub al,2                        ; Avant derniere section                        
    add edi,0f8h                    ; Section start
    imul eax,028h                   ; section size x*28h
    add edi,eax
    mov eax,[edi+0ch]               ; Virtual RVA
    add eax,p_base
    mov stx_offset,eax
    mov eax,[edi+08h]               ; Virtual size
    mov stx_size,eax
    popad
    mov eax,stx_offset
    mov ecx,stx_size
    ret
get_jmp_section endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
search_fix_jump proc
LOCAL addr_orig_call:DWORD
LOCAL stx_offset:DWORD
LOCAL stx_size:DWORD
;    push 41b008h   ;RA2
;    push 494008h    ;NOLF
;    push 0f39008h    ;ALICE
;    push 0EE5008h    ;BW
;    mov edi,7eb000h ;BW
;    mov edi,4ff080h ;ALICE
;    mov edi,41d0ach ;NOLF

    pushad
    call get_jmp_section
    mov stx_offset,eax
    mov stx_size,ecx
    mov eax,0000e853h               ;is there some jmp wrapped code ?
    mov edi,stx_offset
    mov ecx,stx_size
    repnz scasd
    test ecx,ecx
    jz exit_jump
    sub edi,4
    
    mov code_index,edi
    
loop_fucking_jmp:
    mov edx,code_index
    cmp dword ptr [edx],0000e853h
    jnz exit_jump
    
    mov ebx,1
    mov edi,one_wrapped
    mov eax,dword ptr [edi]
    
    call [plugin_api_address]
    
    mov right_rva,eax

    sub edx,6
    mov addr_orig_call,edx
    
    mov edi,pMemory_newthunk        ;where is api in thunk array
    mov ecx,thunk_size
    repnz scasd
    test ecx,ecx
    jz error_jump

    sub edi,4
    sub edi,pMemory_newthunk
    add edi,v_start

    mov eax,addr_orig_call
    sub eax,code_start
    add eax,pMemory_code

    mov word ptr [eax],015ffh
    mov dword ptr [eax+2],edi    
;_________________________     LOG LOG LOG
;    invoke getprocname,right_rva,addr buffer_dll_name,addr buffer_api_name
;    invoke wsprintf,addr textbuffer,offset template_logjmp,addr_orig_call,edi,addr buffer_dll_name,addr buffer_api_name
;    invoke lstrcat,pMemory_log,addr textbuffer
;_________________________     LOG LOG LOG

    add code_index,01dh
    jmp loop_fucking_jmp
    
error_jump:
    int 1

exit_jump:
    popad
    ret
search_fix_jump endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
search_fix_call proc
    pushad
    
    push code_start
    pop code_index

    push v_start
    pop index_thunk

    call bar_init               ;******************* Bar PROGRESS

loop_search_thunk:
    mov edi,index_thunk
    call bar_update             ;******************* Bar PROGRESS
    cmp edi,v_end
    jge fin_fix

    mov ebx,dword ptr [edi]
    test ebx,ebx
    jz not_found_call

    mov v_add,ebx
            
    invoke getprocname,ebx,addr buffer_dll_name,addr buffer_api_name
    cmp eax,0ffffffffh          ;is it a good address
    jnz not_found_call 
    
    mov one_wrapped,edi
    mov add_to_search,edi

loop_search_call:
    lea eax,search_call ;search_call
    mov edx,code_index
    mov edi,code_end
    call searchproc 
    test edx,edx
    jz not_found_call

    sub edx,5
    mov code_index,edx

    mov edi,add_to_search
    mov eax,dword ptr [edi]
    mov ebx,1               ; bool safecast call ou call(call) 
    call [plugin_api_address]
    
    mov right_rva,eax
;    mov code_index,edx
;    add edx,6

    mov edi,pMemory_newthunk        ;where is api in thunk array
    mov ecx,thunk_size
    repnz scasd
    test ecx,ecx
    jz error_fix
    
    sub edi,4
    sub edi,pMemory_newthunk
    add edi,v_start

    mov eax,code_index
    sub eax,code_start
    add eax,pMemory_code
    add code_index,6
;__________________________________________________________________________________________
    call add_log
;__________________________________________________________________________________________
    
    mov dword ptr [eax+2],edi       ;fix with good thunk

    jmp loop_search_call

not_found_call:
    add index_thunk,4
    push code_start
    pop code_index
    jmp loop_search_thunk         

error_fix:
    int 1

fin_fix:
    mov eax,pMemory_code
    popad
    ret
search_fix_call endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
add_log proc
    pushad
    invoke getprocname,right_rva,addr buffer_dll_name,addr buffer_api_name
    invoke wsprintf,addr textbuffer,offset template_log,index_thunk,code_index,right_rva,addr buffer_dll_name,addr buffer_api_name
    invoke lstrcat,pMemory_log,addr textbuffer
    popad
    ret
add_log endp    
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
fill_thunk proc
    pushad

    push v_start
    pop index_thunk

    push pMemory_newthunk
    pop index_buffer
       
loop_thunk:

    mov edi,index_thunk
    cmp edi,v_end
    jge fin_fill

    mov ebx,dword ptr [edi]
    test ebx,ebx
    jz thunk_vide

    mov v_add,ebx
            
    invoke getprocname,ebx,addr buffer_dll_name,addr buffer_api_name
    cmp eax,0ffffffffh          ;is it a good address
    jnz thunk_valid 
    
    mov eax,v_add
    call [plugin_api_address]
    mov v_add,eax

thunk_valid:
    mov edx,index_buffer
    mov ebx,v_add
    mov dword ptr [edx],ebx

thunk_vide:
    add index_thunk,4
    add index_buffer,4
    jmp loop_thunk

fin_fill:
    mov eax,index_thunk
    sub eax,v_start
    mov thunk_size,eax

    popad
    ret
fill_thunk endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
search_plug_api proc
LOCAL index:DWORD
    pushad
    invoke GetDlgItem,hwnd,IDC_PLUG
    invoke SendMessage,eax,BM_GETSTATE,0,0
    .if eax==BST_CHECKED                            ; plug is checked ?
        invoke SetCurrentDirectory,offset plugbuffer
        invoke GetDlgItem,hwnd,IDC_LISTPLUG
        invoke SendMessage,eax,LB_GETCURSEL,0,0
        mov index,eax
        invoke GetDlgItem,hwnd,IDC_LISTPLUG
        invoke SendMessage,eax,LB_GETTEXT,index,offset buffer
        invoke lstrlen,offset offset dir_plug
        sub eax,5
        invoke lstrcpyn,offset dll_name_buffer,offset dir_plug,eax
        invoke lstrcat,offset dll_name_buffer,offset antislash
        invoke lstrcat,offset dll_name_buffer,offset buffer
        invoke LoadLibrary,offset dll_name_buffer   ;load function
        mov handle_library_safe,eax
        .if (eax)
            invoke GetProcAddress,eax,offset plug_fontion_n 
            mov plugin_api_address,eax
        .endif
    .endif
    popad
    ret
search_plug_api endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
plugin_process proc
LOCAL index:DWORD
LOCAL result:DWORD
LOCAL add_:DWORD
LOCAL handle_library:DWORD
    pushad
    mov result,eax
    invoke GetDlgItem,hwnd,IDC_PLUG
    invoke SendMessage,eax,BM_GETSTATE,0,0
    .if eax==BST_CHECKED                            ; plug is checked ?
        invoke SetCurrentDirectory,offset plugbuffer
        invoke GetDlgItem,hwnd,IDC_LISTPLUG
        invoke SendMessage,eax,LB_GETCURSEL,0,0
        mov index,eax
        invoke GetDlgItem,hwnd,IDC_LISTPLUG
        invoke SendMessage,eax,LB_GETTEXT,index,offset buffer
        invoke lstrlen,offset offset dir_plug
        sub eax,5
        invoke lstrcpyn,offset dll_name_buffer,offset dir_plug,eax
        invoke lstrcat,offset dll_name_buffer,offset antislash
        invoke lstrcat,offset dll_name_buffer,offset buffer
        invoke LoadLibrary,offset dll_name_buffer   ;load function
        mov handle_library,eax
        .if (eax)
            invoke GetProcAddress,eax,offset plug_fontion_n 
            .if (eax)
                mov edi,eax
                mov eax,result
                mov ebx,v_rva
                mov ecx,esp_value
                call edi        ; call de la fonction plugin
                mov result,eax
            .endif
        .endif
        invoke FreeLibrary,handle_library
    .endif
    popad
    mov eax,result
    ret
plugin_process endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
plugin_fill proc    ;Search all dll in plugin dir and fill list
    LOCAL search_handle:DWORD
    pushad
    invoke RegCreateKeyExA,HKEY_CURRENT_USER,offset szsvKey,0,0,0,1F0003h,0,offset hReg,offset lpdwDisposition
    invoke RegQueryValueExA,hReg,offset szsvDir,0,0,offset plugbuffer,offset szSIZE
    invoke SetCurrentDirectory,offset plugbuffer
    invoke FindFirstFile,offset dir_plug,offset file32
    .if (eax!=INVALID_HANDLE_VALUE)
        mov search_handle,eax    
        invoke GetDlgItem,hwnd,IDC_LISTPLUG
        invoke SendMessage,eax,LB_ADDSTRING,0,offset file32.cFileName
        mov eax,TRUE
        .while (eax)
            invoke FindNextFile,search_handle,offset file32
            .if (eax)
                invoke GetDlgItem,hwnd,IDC_LISTPLUG
                invoke SendMessage,eax,LB_ADDSTRING,0,offset file32.cFileName
                mov eax,TRUE
            .endif
        .endw
    .endif
    popad
    ret
plugin_fill endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
Rebuild_IAT proc    ;Build an idata section in memeory with original first thunk
                    ;and offset on new section by defaults (end of file)
LOCAL thunk_value:DWORD
LOCAL new_dll_bool:BYTE

        pushad

        invoke GetDlgItem,hwnd,IDC_LISTERROR
        invoke SendMessage,eax,LB_RESETCONTENT,0,0
        invoke GetDlgItem,hwnd,IDC_LISTAPI
        invoke SendMessage,eax,LVM_DELETEALLITEMS,0,0
        mov nbitem,0

        invoke GetDlgItemText,hwnd,IDC_RELOC,addr textbuffer,10
        invoke htodw,addr textbuffer
        mov base_section,eax

        invoke GetDlgItemText,hwnd,IDC_START,addr textbuffer,10
        invoke htodw,addr textbuffer
        mov nbdll,0             ;init calcul size IAT entry & thunks
        mov nbapi,0
        mov v_rva,eax
        mov v_start,eax
        
        mov edi,v_rva

        invoke GetDlgItemText,hwnd,IDC_END,addr textbuffer,10
        invoke htodw,addr textbuffer
        mov v_end,eax

        call bar_init                   ;******************* Bar PROGRESS

        mov new_dll_bool,TRUE;_______
loop_:
        call bar_update                 ;******************* Bar PROGRESS
        cmp edi,v_end
        jz fin_calcul
        mov edx,[edi]
        test edx,edx
        jnz suite_api
        mov new_dll_bool,TRUE;_______
        add edi,4
        jmp loop_

suite_api:
        mov thunk_value,edx
        invoke getprocname,edx,addr buffer_dll_name,addr buffer_api_name
        .if (eax==0ffffffffh)
            mov eax,edx
            call plugin_process
            mov edx,eax
            invoke getprocname,edx,addr buffer_dll_name,addr buffer_api_name
        .endif                    
        .if (eax!=0ffffffffh)
;                invoke lstrcmp,addr textbuffer,addr buffer_dll_name
;                test eax,eax
                cmp new_dll_bool,TRUE ;__________
;                jnz new_dll
                jz new_dll;_________
                inc nbapi
        .else
               invoke wsprintf,addr textbuffer2,offset template,edi
               invoke GetDlgItem,hwnd,IDC_LISTERROR
               invoke SendMessage,eax,LB_ADDSTRING,0,offset textbuffer2
        .endif
        add edi,4
        jmp loop_
new_dll:
        inc nbdll
        inc nbapi
        invoke lstrcpy,addr textbuffer,addr buffer_dll_name
        add edi,4
        mov new_dll_bool,FALSE;___________
        jmp loop_

fin_calcul:
        mov edx,nbdll
        mov edi,nbapi
        add edi,nbdll
        inc edi
        mov eax,nbdll
        inc eax         ;entry null
        imul eax,5*4    ;nb IAT entry
        mov entry_size,eax
        imul edi,4      ;nb thunks
        mov thunk_size,edi
        add eax,edi
        invoke wsprintf,addr textbuffer,offset template_cal,nbdll,nbapi,eax
        invoke SetDlgItemText,hwnd,IDC_API,addr textbuffer

;_____________________________________________________ debut de la reconstruction ________________

        .if (pMemory)
            invoke GlobalUnlock,pMemory
        .endif
        .if (hMemory)
            invoke GlobalFree,hMemory
        .endif
        
        invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,10000h
        mov  hMemory,eax
        invoke GlobalLock,hMemory
        mov  pMemory,eax
        mov edi,eax             ;offset of new section
                                ;edi=index entry esi=index API edx=index apiname
        mov index_entry,edi

        mov esi,pMemory
        add esi,entry_size
        mov index_api,esi
        sub index_api,4         ;le premier pasage est new dll donc add 4 !!
        
        mov edx,esi
        add edx,thunk_size
        mov index_apiname,edx
       
        call bar_init           ;******************* Bar PROGRESS

        mov new_dll_bool,TRUE;_______
loop_b:
        mov edi,v_rva
        call bar_update         ;******************* Bar PROGRESS
        cmp edi,v_end
        jz fin_calculb
        mov edx,[edi]
        test edx,edx
        jnz suite_apib
        mov new_dll_bool,TRUE;_______
        add v_rva,4
        mov edi,v_rva
        mov edx,[edi]
        test edx,edx
;        jz fin_calculb
        jmp loop_b
suite_apib:
        mov addsearch,edx

        invoke getprocname,edx,addr buffer_dll_name,addr buffer_api_name
        .if (eax==0ffffffffh)
            mov eax,edx
            call plugin_process
            mov edx,eax
            invoke getprocname,edx,addr buffer_dll_name,addr buffer_api_name
        .endif                    
        mov ordi,eax
        .if (ordi!=0ffffffffh)
;                invoke lstrcmp,addr textbuffer,addr buffer_dll_name
;                test eax,eax
                cmp new_dll_bool,TRUE ;__________
;                jnz new_dllb
                jz new_dllb;_________
        .endif

;__________________________________________________________________________
        .if (ordi==0)
                mov eax,index_apiname
                sub eax,2
                sub eax,pMemory
                add eax,base_section
                mov esi,index_api
                mov [esi],eax          ;entry API offset
                add index_api,4
                invoke lstrcpy,index_apiname,addr buffer_api_name ;API Name copied
                invoke lstrlen,index_apiname
                add index_apiname,eax
                add index_apiname,3
                invoke svadditemapi,addr buffer_api_name,addr buffer_dll_name,addsearch,v_rva
        .else
                .if (ordi!=0ffffffffh)
                        ;ordinal
                        mov eax,ordi
                        add eax,80000000h
                        mov esi,index_api
                        mov [esi],eax          ;entry API offset
                        add index_api,4
                        invoke wsprintf,addr buffer,offset template_ord,eax
                        invoke svadditemapi,addr buffer,addr buffer_dll_name,addsearch,v_rva
                .endif
        .endif
        add v_rva,4
        jmp loop_b
new_dllb:
;________________________________________________________
        add index_api,4                        

        mov edi,index_entry
        ;add edi,12
        mov eax,index_api
        sub eax,pMemory
        add eax,base_section
        mov [edi],eax          ;entry API offset
        
        add edi,12

        mov eax,index_apiname
        sub eax,pMemory
        add eax,base_section
        mov [edi],eax          ;entry DLL offset

        add edi,4
        mov eax,v_rva
        sub eax,p_base
        mov [edi],eax
        
        add edi,4
        mov index_entry,edi
        
        invoke lstrcpy,index_apiname,addr buffer_dll_name ;Name copied
        invoke lstrlen,index_apiname
        add index_apiname,eax
        add index_apiname,3

;________________________________________________________
        .if (ordi==0)
                mov eax,index_apiname
                sub eax,2
                sub eax,pMemory
                add eax,base_section
                mov esi,index_api
                mov [esi],eax          ;entry API offset
                add index_api,4
                invoke lstrcpy,index_apiname,addr buffer_api_name ;API Name copied
                invoke lstrlen,index_apiname
                add index_apiname,eax
                add index_apiname,3
                invoke svadditemapi,addr buffer_api_name,addr buffer_dll_name,addsearch,v_rva
        .else
                ;ordinal
                mov eax,ordi
                add eax,80000000h
                mov esi,index_api
                mov [esi],eax          ;entry API offset
                add index_api,4
                invoke wsprintf,addr buffer,offset template_ord,eax
                invoke svadditemapi,addr buffer,addr buffer_dll_name,addsearch,v_rva
        .endif
;___________________________________________________________                        
                
        invoke lstrcpy,addr textbuffer,addr buffer_dll_name
        add v_rva,4
        mov new_dll_bool,FALSE;___________
        jmp loop_b

fin_calculb:
_fin:
        mov eax,index_apiname
        sub eax,pMemory
        mov file_size,eax
        invoke GetDlgItem,hwnd,IDC_SAVE
        invoke EnableWindow,eax,TRUE
        popad
    ret
Rebuild_IAT endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
bar_init proc
    pushad
    mov edi,v_end
    sub edi,v_start
    invoke GetDlgItem,hwnd,IDC_PROGRESS
    invoke SendMessage,eax,PBM_SETRANGE32,0,edi
;    invoke SendMessage,eax,PBM_SETRANGE32,v_rva,v_end
    popad
    ret
bar_init endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
bar_update proc
    pushad
    sub edi,v_start
    invoke GetDlgItem,hwnd,IDC_PROGRESS
    invoke SendMessage,eax,PBM_SETPOS,edi,0
    popad
    ret
bar_update endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
RestoreCode proc
;  pushad
  push ebp
  mov ebp, esp
  add esp, 0FFFFFFF4h
  push edi
  push esi

  push offset mapicz
  push 00000000
  push 00000004
  Call OpenFileMappingA

  mov dword ptr [ebp-04], eax
  push 00000000
  push 00000000
  push 00000000
  push 00000004
  push [ebp-04]

  Call MapViewOfFile
  mov dword ptr [ebp-08], eax
  mov edi, pe_base
  mov edi, dword ptr [edi+28h] 
  add edi, p_base
  mov dword ptr [ebp-0Ch], edi
  mov esi, dword ptr [ebp-08]
  push dword ptr [esi]
  push edi
  mov ecx, dword ptr [esi]
  add esi, 00000004
  rep movsb
  push [ebp-08]

  Call UnmapViewOfFile
  push [ebp-04]

  Call CloseHandle
  push offset iczevent
  push 00000000
  push 00000002
  Call OpenEventA
  push eax
  push eax

  Call SetEvent
  pop eax
  push eax

  Call CloseHandle
  
;  Call HookVirtualAlloc
  
  add esp, 0000001Ch
  mov esi,[ebp-0Ch]
  pop ebp
  add esp,4
  jmp esi

  ret
                invoke GetSaveFileName, ADDR ofn
RestoreCode endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
svadditemmodule proc ptext:DWORD, pbase:DWORD ,psize:DWORD
    mov pitem.imask,LVIF_TEXT
    push nbitem  
    pop pitem.iItem
    mov pitem.iSubItem,0
    mov eax,ptext
    mov pitem.pszText,eax
    invoke GetDlgItem,hwnd,IDC_MODULE
    invoke SendMessage,eax,LVM_INSERTITEM,0,offset pitem

    mov pitem.iSubItem,1
    mov eax,pbase
    mov pitem.pszText,eax
    invoke GetDlgItem,hwnd,IDC_MODULE
    invoke SendMessage,eax,LVM_SETITEMTEXT,nbitem,offset pitem

    mov pitem.iSubItem,2
    mov eax,psize
    mov pitem.pszText,eax
    invoke GetDlgItem,hwnd,IDC_MODULE
    invoke SendMessage,eax,LVM_SETITEMTEXT,nbitem,offset pitem

    add nbitem,1
    ret
svadditemmodule endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
svadditemapi proc apiname:DWORD, dllname:DWORD ,address:DWORD, offset_:DWORD
    pushad
    mov pitem.imask,LVIF_TEXT
    push nbitem  
    pop pitem.iItem
    mov pitem.iSubItem,0
    mov eax,apiname
    mov pitem.pszText,eax
    invoke GetDlgItem,hwnd,IDC_LISTAPI
    invoke SendMessage,eax,LVM_INSERTITEM,0,offset pitem

    mov pitem.iSubItem,1
    mov eax,dllname
    mov pitem.pszText,eax
    invoke GetDlgItem,hwnd,IDC_LISTAPI
    invoke SendMessage,eax,LVM_SETITEMTEXT,nbitem,offset pitem

    mov pitem.iSubItem,2
    mov eax,offset_
    invoke wsprintf,addr buffer,offset template,eax
    mov pitem.pszText,offset buffer
    invoke GetDlgItem,hwnd,IDC_LISTAPI
    invoke SendMessage,eax,LVM_SETITEMTEXT,nbitem,offset pitem

    mov pitem.iSubItem,3
    mov eax,address
    invoke wsprintf,addr buffer,offset template,eax
    mov pitem.pszText,offset buffer
    invoke GetDlgItem,hwnd,IDC_LISTAPI
    invoke SendMessage,eax,LVM_SETITEMTEXT,nbitem,offset pitem

    add nbitem,1
    popad
    ret
svadditemapi endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
getprocname PROC addresse_api:DWORD,asci_dll:DWORD,asci_api:DWORD
LOCAL ordinal:DWORD
LOCAL seh:SEH

    assume fs:nothing
    push fs:[0]
    pop seh.PrevLink
    mov seh.CurrentHandler,offset SEHHandler
    mov seh.SafeOffset,offset error_getprocname
    lea eax,seh
    mov fs:[0], eax
    mov seh.PrevEsp,esp
    mov seh.PrevEbp,ebp

    pushad
    invoke GetCurrentProcessId
    invoke CreateToolhelp32Snapshot, TH32CS_SNAPMODULE, eax 
    mov hSnapshot, eax
    mov mo32.dwSize, sizeof MODULEENTRY32
    invoke Module32First, hSnapshot, addr mo32
    svloop_m:
    mov eax,addresse_api
    mov ebx,mo32.modBaseAddr
    add ebx,mo32.modBaseSize
    .if (eax>=mo32.modBaseAddr) && (eax<ebx)
            invoke  fonction2name,addr mo32.szExePath,addresse_api
            .if (eax==0ffffffffh)
                popad
                mov eax,0ffffffffh
                ret
            .endif
            .if (eax>mo32.modBaseAddr)
                invoke lstrcpy,asci_api,eax
                invoke lstrcpy,asci_dll,addr mo32.szModule
                mov ordinal,0
             .else
                mov ordinal,eax
                invoke lstrcpy,asci_dll,addr mo32.szModule
            .endif
    .else
            invoke Module32Next, hSnapshot, addr mo32
            test eax,eax
            jnz svloop_m
            mov ordinal,0ffffffffh
    .endif                                            
    invoke CloseHandle, hSnapshot
    popad
    mov eax,ordinal
error_getprocname:
    push seh.PrevLink
    pop fs:[0]
    ret
getprocname endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
fonction2name PROC a_libname:DWORD, search_add:DWORD
    LOCAL pe_header:DWORD
    LOCAL handle:DWORD 
    LOCAL _export:DWORD 
    LOCAL _functions:DWORD
    LOCAL _names:DWORD
    LOCAL _ordinal:DWORD
    LOCAL _base:DWORD
    LOCAL size_export:DWORD
    LOCAL namesize:DWORD
    LOCAL seh:SEH

        assume fs:nothing
        push fs:[0]
        pop seh.PrevLink
        mov seh.CurrentHandler,offset SEHHandler
        mov seh.SafeOffset,offset error
        lea eax,seh
        mov fs:[0], eax
        mov seh.PrevEsp,esp
        mov seh.PrevEbp,ebp

        invoke  GetModuleHandleA,a_libname
        .if (!eax)
            invoke LoadLibrary,a_libname
        .endif

        mov     handle, eax
        mov     edi, handle
        cmp     word ptr [edi], 5A4Dh
        jnz     error
        add     edi, [edi+3Ch]
        mov     pe_header, edi
        cmp     dword ptr [edi], 4550h
        jnz     error
        mov     edi,[edi+78h]
        add     edi,handle
        mov     _export,edi
        mov     edi,pe_header
        mov     edi,[edi+7ch]
        mov     size_export,edi
        mov     edi,_export
        mov     edi,[edi+1ch]
        add     edi,handle
        mov     _functions,edi
        mov     edi,_export
        mov     edi,[edi+18h]
        shl     edi,1
        mov     namesize,edi
        
        mov     edi,_export
        mov     edi,[edi+10h]
        mov     _base,edi
        mov     edi,_export
        mov     edi,[edi+20h]
        add     edi,handle
        mov     _names,edi
        mov     edi,_export
        mov     edi,[edi+24h]
        add     edi,handle
        mov     _ordinal,edi
        mov     eax,search_add
        sub     eax,handle
        mov     edi,_functions
        mov     ecx,size_export
        repne   scasd
        test    ecx,ecx
        jz      error
        sub     edi,4
        sub     edi,_functions
        shr     edi,2
        mov     eax,edi
        mov     edi,_ordinal
        mov     ecx,namesize
        repne   scasw
        test    ecx,ecx
        jnz     suite
        add     eax,_base
        ret
suite:
        sub     edi,2
        sub     edi,_ordinal
        shl     edi,1
        add     edi,_names
        mov     eax,[edi]
        .if (eax)
            add     eax,handle
        .else
            sub     edi,_names
            add     edi,_ordinal
            mov     eax,[edi]
        .endif                
        push seh.PrevLink
        pop fs:[0]
        ret
error:
        push seh.PrevLink
        pop fs:[0]
        mov eax,0FFFFFFFFH
        ret
fonction2name endp

searchproc proc             ; edx where to search
LOCAL indexs:DWORD          ; eax what to search
LOCAL start:DWORD           ; edi limit
LOCAL nb:DWORD
        mov start,eax
starts:
        mov nb,0
        mov eax,start
        mov cl,[eax]
loops1:
        mov bl,[edx]
        cmp cl,bl
        jz search1
        inc edx
        cmp edx,edi
        jz not_found
        jmp loops1
search1:
        mov indexs,edx
loops2:
        inc nb
        cmp nb,6            ; crappy !!!!!!!!!
        jz found
        inc eax
        inc edx
        mov cl,[eax]
        mov bl,[edx]
        cmp cl,bl
        jz loops2
        mov edx,indexs
        inc edx
        cmp edx,edi
        jz not_found
        jmp starts
not_found:
        xor edx,edx
found:
        ret
searchproc endp
; ___________________________________________________________________________
include lde32bin.inc   ; LDE32
;------------------------------------------------------------------------------
End DllEntry
;------------------------------------------------------------------------------
;------------------------------------------------------------------------------
