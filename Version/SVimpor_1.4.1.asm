;v1.4.1
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

LIMITEDLL equ 20000000h
MAXSIZE equ 260

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
message_error_search   db "Error searching !",0
szsvKey         db  '\Software\SV',0
szsvDir         db  'plugdir',0
szSIZE          dd 256

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
v_rva           dd ?
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
testhandle      dd ?
hReg            dd ?
lpdwDisposition dd ?
align dword
context CONTEXT <>
.code
;--------------------------------------------------------------------
;##############################################################################
;--------------------------------------------------------------------
DllEntry proc hInstance:HINSTANCE, reason:DWORD, reserved1:DWORD
    .if reason==DLL_PROCESS_ATTACH
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
    invoke ExitProcess,eax
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
             .ENDIF
        .ENDIF
    .ENDIF
    invoke DefWindowProc,hWnd,uMsg,wParam,lParam
    ret
WndProc endp
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
        mov edi,v_rva

        invoke GetDlgItemText,hwnd,IDC_END,addr textbuffer,10
        invoke htodw,addr textbuffer
        mov v_end,eax

        mov new_dll_bool,TRUE;_______
loop_:
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
       
        mov new_dll_bool,TRUE;_______
loop_b:
        mov edi,v_rva
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
; ___________________________________________________________________________
End DllEntry
;------------------------------------------------------------------------------
;------------------------------------------------------------------------------
