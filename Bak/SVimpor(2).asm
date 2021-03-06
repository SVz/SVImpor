;v2.3.1
.386
.model flat,stdcall
option casemap:none

include SVImpor.inc

;##############################################################################
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
;    LOCAL hPicture:HWND
    
    mov   wc.cbSize,SIZEOF WNDCLASSEX
    mov   wc.style, CS_HREDRAW or CS_VREDRAW
    mov   wc.lpfnWndProc, OFFSET WndProc
    mov   wc.cbClsExtra,NULL
    mov   wc.cbWndExtra,DLGWINDOWEXTRA
    push  hInst
    pop   wc.hInstance
    mov   wc.hbrBackground,COLOR_BTNFACE+1
    mov   wc.lpszMenuName,OFFSET ClassName
    mov   wc.lpszClassName,OFFSET ClassName
    
    invoke LoadIcon,hInst,1
    mov   wc.hIcon,eax
    mov   wc.hIconSm,eax
    invoke LoadCursor,NULL,IDC_ARROW
    mov   wc.hCursor,eax
    invoke RegisterClassEx, addr wc
    invoke CreateDialogParam,hInst,65h,NULL,NULL,NULL
    mov   hDlg,eax

    invoke LoadImage,hInst,7,IMAGE_BITMAP,24,25,0
    mov hPicture, eax

    ;invoke Transparency,hDlg,240            ;set 240/255 transparency value to dialog
    INVOKE ShowWindow, hDlg,SW_SHOWNORMAL
    INVOKE UpdateWindow, hDlg

    mov ofn.lStructSize,SIZEOF ofn
    push hDlg
    pop  ofn.hWndOwner
    push hInst
    pop  ofn.hInstance
    mov  ofn.lpstrFilter, OFFSET FilterString
    mov ofn.lpstrDefExt, OFFSET bin_extend
    mov  ofn.lpstrFile, OFFSET buffer
    mov  ofn.nMaxFile,MAXSIZE

    mov pcol.imask,LVCF_FMT or LVCF_TEXT or LVCF_WIDTH or LVCF_SUBITEM
    mov pcol.fmt,LVCFMT_LEFT
    mov pcol.lx,330
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

    mov eax,p_base
    invoke wsprintf,addr textbuffer,offset template,eax
    invoke SetDlgItemText,hDlg,IDC_PEBASE,addr textbuffer

    invoke wsprintf,addr textbuffer,offset decitemplate,NBLIGNE
    invoke SetDlgItemText,hDlg,IDC_NBDISASM,addr textbuffer

    mov pcol.imask,LVCF_FMT or LVCF_TEXT or LVCF_WIDTH or LVCF_SUBITEM
    mov pcol.fmt,LVCFMT_LEFT
    mov pcol.lx,168
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
    
    call get_code_section_info  ; get code offset and section size :code_start,code_end
    
    invoke wsprintf,addr textbuffer,offset template,code_start
    invoke SetDlgItemText,hDlg,IDC_JMPSTART,addr textbuffer

    invoke wsprintf,addr textbuffer,offset template,code_end
    invoke SetDlgItemText,hDlg,IDC_JMPEND,addr textbuffer

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
    .ELSEIF uMsg==WM_RBUTTONDOWN
;------------------------------------------------------------------------------
;------------------ Rbutton Menu added with preprocessed ASPROTECT APIs -------
;------------------------------------------------------------------------------

        mov eax,lParam
        and eax,0ffffh
        mov hitpoint.x,eax
        mov eax,lParam
        shr eax,16
        mov hitpoint.y,eax
     
        invoke GetWindowRect,hWnd,addr lpRect
        invoke CreatePopupMenu
        mov handle_menu,eax
        szText ASAPI," ASprotect APIs"
        invoke AppendMenu,handle_menu,MF_STRING or MF_DISABLED,1,addr ASAPI
        invoke SetMenuItemBitmaps,handle_menu,1,MF_BYCOMMAND,hPicture,hPicture
        invoke AppendMenu,handle_menu,MF_SEPARATOR,2,addr GetVersion_
        invoke AppendMenu,handle_menu,MF_STRING,3,addr freeresource
        invoke AppendMenu,handle_menu,MF_STRING,4,addr lockresource
        invoke AppendMenu,handle_menu,MF_SEPARATOR,5,addr GetVersion_
        invoke AppendMenu,handle_menu,MF_STRING,6,addr GetVersion_
        invoke AppendMenu,handle_menu,MF_STRING,7,addr GetVersionExA_
        invoke AppendMenu,handle_menu,MF_STRING,8,addr GetCurrentProcess_
        invoke AppendMenu,handle_menu,MF_STRING,9,addr GetCurrentProcessId_
        invoke AppendMenu,handle_menu,MF_STRING,10,addr GetCommandLineA_
        invoke AppendMenu,handle_menu,MF_SEPARATOR,11,addr GetVersion_
        invoke AppendMenu,handle_menu,MF_STRING,12,addr GetModuleHandleA_
        invoke AppendMenu,handle_menu,MF_STRING,13,addr GetProcAddress_
        
        mov eax,hitpoint.x
        add eax,lpRect.left
        mov edx,hitpoint.y
        add edx,lpRect.top

        invoke TrackPopupMenu,handle_menu,TPM_LEFTALIGN or TPM_RETURNCMD or TPM_TOPALIGN ,eax,edx,NULL,hWnd,NULL

        .if eax==3
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset freeresource 
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==4
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset lockresource
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==6
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset GetVersion_
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==7
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset GetVersionExA_
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==8
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset GetCurrentProcess_
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==9
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset GetCurrentProcessId_
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==10
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset GetCommandLineA_
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==12
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset GetModuleHandleA_
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .elseif eax==13
            invoke  GetModuleHandleA,offset kernel
            invoke GetProcAddress,eax,offset GetProcAddress_
            invoke wsprintf,addr textbuffer,offset template,eax
            invoke SetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer
        .endif
        invoke DestroyMenu,handle_menu

    .ELSEIF uMsg==WM_COMMAND
        mov eax,wParam
        mov edx,wParam
        shr edx,16
            .IF ax==IDC_ADDRESS
            .ENDIF
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
                
;_______________________________________________________________________LOG LOG____________
;                invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,code_size
;                mov  hMemory_log,eax
;                invoke GlobalLock,hMemory_log
;                mov  pMemory_log,eax
;_______________________________________________________________________LOG LOG____________

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
                
;_______________________________________________________________________LOG LOG____________
;                invoke GlobalUnlock,pMemory_log
;                invoke GlobalFree,hMemory_log
;_______________________________________________________________________LOG LOG____________

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
;----------------IDC_TXT--------------------------------------------------------------
            .ELSEIF ax==IDC_TXT
                pushad
                invoke GetDlgItem,hwnd,IDC_LISTAPI
                invoke SendMessage,eax,LVM_GETITEMCOUNT,0,0
                mov nbapi,eax
                imul eax,512		; each line is max 512 bytes
                mov nbmemloc,eax
                ;----------- MEM ALLOC
                invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,eax
                mov  hMemory_log,eax
                invoke GlobalLock,hMemory_log
                mov  pMemory_log,eax
                invoke lstrcpy,pMemory_log,addr sv_copyright
                invoke lstrcat,pMemory_log,addr linefeed
                invoke lstrcat,pMemory_log,addr linefeed
                xor edi,edi
                .while (edi<nbapi)
                    mov pitem.iItem,edi		; read of items
                    xor esi,esi
                    .while (esi<4)
                        mov pitem.iSubItem,esi            ; column
                        mov pitem.imask,LVIF_TEXT
                        mov pitem.cchTextMax,512
                        lea eax,textbuffer
                        mov pitem.pszText,eax
                        invoke GetDlgItem,hwnd,IDC_LISTAPI
                        invoke SendMessage,eax,LVM_GETITEM,0,offset pitem 
                        .if (esi==0)
                            invoke wsprintf,addr textbuffer2,offset template_str_40,addr textbuffer
                            invoke lstrcpy,addr textbuffer,addr textbuffer2
                        .elseif (esi==1)
                            invoke wsprintf,addr textbuffer2,offset template_str_16,addr textbuffer
                            invoke lstrcpy,addr textbuffer,addr textbuffer2
                        .endif

                        invoke lstrcat,pMemory_log,addr textbuffer
                        invoke lstrcat,pMemory_log,addr space
                        inc esi
                    .endw
                    invoke lstrcat,pMemory_log,addr linefeed
                    inc edi
                .endw
                
                invoke DialogBoxParam, dllhandle, IDD_TEXTD, NULL, addr DlgProcText, NULL

		;----------- FREE MEM                
                invoke GlobalUnlock,pMemory_log
                invoke GlobalFree,hMemory_log
                
                popad
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

;                invoke  IsBadCodePtr,eax          ; is it good code ?
;                .if (!eax)
                    mov edi,update_rva
                    mov eax,update_address
;                    .if (eax)
                        mov [edi],eax
;                    .endif
;                .endif
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
                push hWnd
                pop  ofn.hWndOwner
                mov  ofn.lpstrFilter, OFFSET FilterString
                mov ofn.lpstrDefExt, OFFSET bin_extend
                mov  ofn.lpstrFile, OFFSET buffer
                mov  ofn.nMaxFile,MAXSIZE
                ;add filenamesave by default _idata.bin (version 2.4.1)
                invoke GetModuleFileName,NULL,addr textbuffer,512
                invoke szRep,addr textbuffer,addr buffer,CTXT(".exe"),CTXT("_idata.bin")
	            ;mov [buffer],0  ;filename buffer a vide
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
                popad
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_CODEFIXER
            	pushad
                invoke DialogBoxParam, dllhandle, IDD_DLGFIXER, NULL, addr DlgFixerProc, NULL
            	popad
;------------------------------------------------------------------------------
            .ELSEIF ax==IDC_EXIT
                invoke CloseHandle, hSnapshot
                invoke GlobalUnlock,pMemory
                invoke GlobalFree,hMemory
                invoke DestroyWindow,hWnd
;--------------------------------------------------------ASM BUTTON------------
            .ELSEIF ax==IDC_DISASM
                pushad
                invoke GetDlgItem,hwnd,IDC_LISTDISASM
                invoke SendMessage,eax,LB_RESETCONTENT,0,0
                call locate_disam
                .if (eax!=-1)
                    invoke GetDlgItemText,hWnd,IDC_ADDRESS,addr textbuffer,10
                    invoke htodw,addr textbuffer
                    mov Address,eax
                    invoke  IsBadCodePtr,eax    ; is it good code ?
                    .if (!eax)
                        invoke GetDlgItemText,hWnd,IDC_NBDISASM,addr textbuffer,10
                        invoke htodw,addr textbuffer
                        mov nb_ligne,eax
    
                        .while (nb_ligne>0)
                            cld                             ; copy 32 bytes at Address into OpcodeBuff  
                            mov ecx, 8                      ; 8 dwords to copy 
                            mov esi, Address                ; source
                            lea edi, OpcodeBuff             ; destination
                            rep movsd
                            push Address                    ; RVA address. Only used to correct displacement on Jumps and Calls
                            push offset OpcodeLength        ; Return pointer to length of opcode
                            push offset textbuffer          ; Return buffer holding disassembled text
                            push offset OpcodeBuff          ; 32 bytes starting at Address
                            call h_feedDisa                 ; disassembled text returned in StringBuff, length of text in ECX
                            add esp,10h
                        
                            lea esi,textbuffer
                            mov eax,dword ptr [esi]
                            .if (eax==6c6c6163h)            ;'CALL' == 6c6c6163
                                mov esi,Address
                                mov edi,dword ptr [esi+1]   
                                add edi,esi
                                add edi,OpcodeLength
                                invoke  IsBadCodePtr,edi    ; is it good code ?
                                .if (!eax)
                                    mov edi,dword ptr [edi+2]
                                    invoke  IsBadCodePtr,edi    ; is it good code ?
                                    .if (!eax)
                                        mov eax,dword ptr [edi]
                                        invoke getprocname,eax,addr buffer_dll_name,addr buffer_api_name
                                        .if (eax!=-1)       ; API name updated in text buffer
                                            .if (eax==0)    ; API name 
                                                lea esi,textbuffer
                                                add esi,5
                                                invoke lstrcpy,esi,offset buffer_api_name
                                            .elseif         ; API ordinal
                                                lea esi,textbuffer
                                                add esi,5
                                                invoke wsprintf,addr textbuffer2,offset template_ord,eax
                                                invoke lstrcpy,esi,addr textbuffer2
                                            .endif
                                        .endif
                                    .endif
                                .endif
                            .endif
                    
                            invoke wsprintf,addr textbuffer2,offset template_disasm,Address,addr textbuffer
                            invoke GetDlgItem,hwnd,IDC_LISTDISASM
                            invoke SendMessage,eax,LB_ADDSTRING,0,offset textbuffer2
                    
                            mov eax,OpcodeLength
                            add Address,eax
                            dec nb_ligne
                        .endw
                        invoke FreeLibrary,handle_DisInstr
                    .endif
                .endif
                popad
            .ELSEIF ax==IDC_RSRC
                invoke DialogBoxParam, dllhandle, IDD_DIALOG, NULL, addr DlgProc, NULL
            .ELSEIF ax==IDC_DUMP
                invoke DialogBoxParam, dllhandle, IDD_DLGDUMP, NULL, addr DlgDumpProc, NULL
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
             .ENDIF
        .ENDIF
    .ELSEIF uMsg==WM_NOTIFY
;------------------------------------------------------------------------------
;-------------------- Click on listapi select adresse in box ------------------
;------------------------------------------------------------------------------
        mov eax,wParam
        mov ebx,lParam
        add ebx,8
        mov ecx,[ebx]
        .IF eax==IDC_LISTAPI
            .IF ecx==NM_CLICK
                mov nbitem,0
                push hWnd
                pop hwnd
                add ebx,4
                mov eax,[ebx]
                mov pitem.iItem,eax
                mov pitem.iSubItem,2            ; column 2 of list (adresse)
                mov pitem.imask,LVIF_TEXT
                mov pitem.cchTextMax,500
                lea eax,textbuffer
                mov pitem.pszText,eax
                invoke GetDlgItem,hwnd,IDC_LISTAPI
                invoke SendMessage,eax,LVM_GETITEM,0,offset pitem 
                invoke SetDlgItemText,hWnd,IDC_RVA,addr textbuffer
                invoke SendMessage,hWnd,WM_COMMAND,IDC_VIEW,BN_CLICKED
            .ENDIF
        .ENDIF
    .ENDIF
    invoke DefWindowProc,hWnd,uMsg,wParam,lParam
    ret
WndProc endp
;------------------------------------------------------------------------------
;######################## PELOCK1.4 CODE FIXER ################################
;------------------------------------------------------------------------------
pelock_decrypt proc ret_pelock_decrypt:DWORD, call_pelock_decrypt:DWORD, pelock_code_start:DWORD, pelock_code_size:DWORD, pe_patern:DWORD
				;Parts of code are crypted and decrypted on the fly
LOCAL start_offset:DWORD
LOCAL code_backup:DWORD	
	pushad
	xor eax,eax
	mov count_decrypt,eax
	mov count_crypt,eax
	;mov edi,685bd3h			;backup code *********** HARDCODED *************PELOCK1.4 
	mov edi,ret_pelock_decrypt

	mov eax,dword ptr [edi]		;change ret by add..
	mov code_backup,eax			;to return decrypt call here
	
	mov eax,0c304c483h			;add esp,4
	mov dword ptr [edi],eax		;ret
	
	xor eax,eax
	mov al,0e8h
	mov edi,pelock_code_start
	mov ecx,pelock_code_size
	
@@:
	repnz scasb
	test ecx,ecx
	jz @f
		
	mov edx,dword ptr [edi]
	add edx,edi
	add edx,4
	;cmp edx,0685492h			;decrypt call *********** HARDCODED *************PELOCK1.4 
	cmp edx,call_pelock_decrypt
	jnz @b
	

	dec edi
	call edi					;call decrypt routine and return here
	inc count_decrypt
	
	mov ebx,909007ebh			;correct jmp to avoid recrypt and nop for visibility
	mov dword ptr [edi],ebx
	mov ebx,90909090h
	mov dword ptr [edi+4],ebx
	mov byte ptr [edi+8],bl
	inc edi

	jmp @b

@@:
	mov eax,code_backup			;restore code
	mov dword ptr [edi],eax		

	mov start_offset,0
@@:								;search for crypt section and fixed jump
 	invoke BMHBinsearch,start_offset,pelock_code_start,pelock_code_size,addr pelock_search_byte,16 ;qmp
	cmp eax,-1
	jz @f

	inc count_crypt				
		
	mov edi,eax
	add edi,pelock_code_start

	inc eax
	mov start_offset,eax
	mov byte ptr [edi+1],17h
	jmp @b
	
@@:
	popad
	mov eax,TRUE
	ret

pelock_decrypt endp
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
;    call add_log
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
;        invoke lstrlen,offset offset dir_plug
;        sub eax,5
;        invoke lstrcpyn,offset dll_name_buffer,offset dir_plug,eax
;        invoke lstrcat,offset dll_name_buffer,offset antislash
;        invoke lstrcat,offset dll_name_buffer,offset buffer
        invoke lstrcpy,offset dll_name_buffer,offset buffer
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
        invoke lstrcpy,offset dll_name_buffer,offset buffer
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
plugin_fill proc    ;Search all dll in plugin dir and fill list1F0003h
    LOCAL search_handle:DWORD
    pushad
    invoke RegCreateKeyExA,HKEY_CURRENT_USER,offset szsvKey,0,0,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,0,offset hReg,offset lpdwDisposition
    invoke RegQueryValueExA,hReg,offset szsvDir,0,0,offset plugbuffer,offset szSIZE

    lea eax,offset plugbuffer
    mov al,[eax]
    .if (al==0)
        invoke BrowseForFolder,hwnd,offset plugbuffer,offset plug_title1,offset plug_title2
        .if (al==1)
            invoke RegSetValueExA,hReg,offset szsvDir,0,REG_SZ,offset plugbuffer,255
        .endif
    .endif
    
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
LOCAL jmp_table_check:BYTE
LOCAL j_start:DWORD
LOCAL j_end:DWORD
LOCAL range:DWORD

        pushad

	    invoke GetDlgItem,hwnd,IDC_CHKJMP
    	invoke SendMessage,eax,BM_GETSTATE,0,0
    	.if eax==BST_CHECKED
	        invoke GetDlgItemText,hwnd,IDC_JMPSTART,addr textbuffer2,10
    	    invoke htodw,addr textbuffer2
	        mov j_start,eax
	        invoke GetDlgItemText,hwnd,IDC_JMPEND,addr textbuffer2,10
	        invoke htodw,addr textbuffer2
	        mov j_end,eax
		 	mov range,eax
		 	mov eax,j_start
		 	sub range,eax
    		mov jmp_table_check,TRUE
    	.elseif
    		mov jmp_table_check,FALSE
    	.endif

        invoke GetDlgItem,hwnd,IDC_LISTERROR
        invoke SendMessage,eax,LB_RESETCONTENT,0,0
        invoke GetDlgItem,hwnd,IDC_LISTAPI
        invoke SendMessage,eax,LVM_DELETEALLITEMS,0,0
        mov nbitem,0

        invoke GetDlgItemText,hwnd,IDC_RELOC,addr textbuffer,10
        invoke htodw,addr textbuffer
        mov base_section,eax

        invoke GetDlgItemText,hwnd,IDC_PEBASE,addr textbuffer,10
        invoke htodw,addr textbuffer
        mov p_base,eax

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
		.if (jmp_table_check==TRUE)
			invoke check_jmp_table,edi,j_start,range
			.if (eax==-1)
				add edi,4
				jmp loop_
			.endif
		.endif
        mov thunk_value,edx
        invoke getprocname,edx,addr buffer_dll_name,addr buffer_api_name
        .if (eax==0ffffffffh)
            mov eax,edx
            call plugin_process
            mov edx,eax
            invoke getprocname,edx,addr buffer_dll_name,addr buffer_api_name
        .endif                    
        .if (eax!=0ffffffffh)
                ;--------------- Readded for 2k (ntdll) NORMALISATION ------------
                push edx
                invoke lstrcmp,addr ntdll_str,addr buffer_dll_name
                pop edx
                test eax,eax
                jnz @f
                invoke normalize,addr buffer_api_name,edx
                .if (eax==TRUE)
                    invoke lstrcpy,addr buffer_dll_name,addr kernel
                    jmp normalize_suite
                .endif
                                
                @@:
                invoke lstrcmp,addr textbuffer,addr buffer_dll_name
                test eax,eax
                jnz new_dll
            normalize_suite:
                cmp new_dll_bool,TRUE ;__________
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
		.if (jmp_table_check==TRUE)
			invoke check_jmp_table,edi,j_start,range
			.if (eax==-1)
        		add v_rva,4
				jmp loop_b
			.endif
		.endif
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
                ;--------------- NT trick Rtl.... NORMALISATION ------------
                push edx
                invoke lstrcmp,addr ntdll_str,addr buffer_dll_name
                pop edx
                .if (eax==0)
                    invoke normalize,addr buffer_api_name,edx
                    .if (eax==TRUE)
                        invoke lstrcpy,addr buffer_dll_name,addr kernel
                        jmp no_new_dll_XP
                    .endif

                    ;invoke MessageBox,NULL,addr message_ntdll,addr AppName,MB_OK
                    ;invoke lstrcmp,addr getlasterror_XP,addr buffer_api_name
                    ;.if (eax==0)
                    ;    invoke lstrcpy,addr buffer_api_name,addr getlasterror_9x
                    ;    jmp no_new_dll_XP
                    ;.endif
                    ;invoke lstrcmp,addr setlasterror_XP,addr buffer_api_name
                    ;.if (eax==0)
                    ;    invoke lstrcpy,addr buffer_api_name,addr setlasterror_9x
                    ;    jmp no_new_dll_XP
                    ;.endif
                .endif
                ;--------------- Readded for 2k (ntdll)
                invoke lstrcmp,addr textbuffer,addr buffer_dll_name
                test eax,eax
                jnz new_dllb
        no_new_dll_XP:
                cmp new_dll_bool,TRUE ;__________
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
        invoke GetDlgItem,hwnd,IDC_TXT
        invoke EnableWindow,eax,TRUE
        popad
    ret
Rebuild_IAT endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
normalize proc str_api:DWORD, api_addr:DWORD
LOCAL hkernel32:DWORD
LOCAL result:DWORD
    pushad
    mov result,FALSE
    lea esi,kernel32_api
    invoke  GetModuleHandleA,offset kernel
    mov hkernel32,eax
loop_kernel_api:
    invoke GetProcAddress,hkernel32,esi
    cmp eax,api_addr
    jnz @f
    invoke lstrcpy,str_api,esi
    mov result,TRUE
    jmp exit_normalize
@@:
    invoke lstrlen,esi
    add esi,eax
    inc esi
    cmp esi,offset fin_kernel_api
    jz exit_normalize
    jmp loop_kernel_api
exit_normalize:    
    popad
    mov eax,result
    ret

normalize endp
;------------------------------------------------------------------------------
;##############################################################################
;------------------------------------------------------------------------------
check_jmp_table proc thunk:DWORD, j_start:DWORD, range:DWORD
LOCAL result:DWORD
LOCAL start_offset:DWORD
	 pushad
	 	mov start_offset,0
	 	inc range
	 	mov eax,thunk
	 	mov jmp_table_search_byte,eax
;	 	int 3
@@:
	 	invoke BMHBinsearch,start_offset,j_start,range,addr jmp_table_search_byte,4
	 	.if (eax!=-1)
		 	add eax,j_start
		 	mov dx, word ptr [eax-2]
		 	mov cl, byte ptr [eax-2]
		 	mov bl,byte ptr [eax-1]
		 	.if (dx==15ffh) || (dx==25ffh) || (cl==8bh) || (bl==0a1h)
		 				;(dx==3D8bh) || (dx==2D8bh) || (dx==1D8bh)
		 			 	;jmp - call - all mov (edi - mov esi - mov ebp - mov edx)
		 		mov eax,TRUE
		 	.else
		 		inc eax
		 		sub eax,j_start
		 		mov start_offset,eax
		 		jmp @b
		 	.endif
		 .else
	 		mov eax,-1
		 .endif
	 	mov result,eax
	 	popad
	 mov eax,result
	 ret
check_jmp_table endp
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
        mov     ecx,size_export ;ScanD -> size/4 ???? a voir
        repne   scasd
        test    ecx,ecx
        jz      error
        sub     edi,4
        sub     edi,_functions
        shr     edi,2
        mov     eax,edi
        mov     edi,_ordinal
        mov     ecx,namesize
        shr     ecx,1           ; ScanW -> size/2 Bug first api is Ordinal !!!!!!!!!!!!
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
; ########################################################################
mem_copy proc offset_esi:DWORD, offset_edi:DWORD, nb:DWORD
    pushad
    mov esi,offset_esi
    mov edi,offset_edi
    mov ecx,nb
    rep movsb
    popad
    ret
mem_copy endp
; ########################################################################
unicopy proc offset_str:DWORD, offset_buf:DWORD
    pushad
    mov esi,offset_str
    mov edi,offset_buf
    xor eax,eax
    mov al,[esi]
    add esi,2
    .while (eax>0)
        mov dl,[esi]
        mov [edi],dl
        add esi,2
        dec eax
        inc edi
    .endw
    mov [edi],al
    popad
    ret    
unicopy endp
; ########################################################################
round_ PROC val:DWORD,modulo:DWORD
    pushad
    mov eax,val
    mov ebx,modulo
    xor edx,edx
    cdq
    idiv ebx
    test edx,edx
    jz suite_modulo
    inc eax
suite_modulo:
    imul eax,modulo
    mov val,eax
    popad
    mov eax,val
    ret
round_ endp
; ########################################################################
ResLib PROC
    pushad
    .if (al==1)
        mov tvinsert.item.pszText,offset cursor
    .elseif (al==2)
        mov tvinsert.item.pszText,offset bitmap
    .elseif (al==3)
        mov tvinsert.item.pszText,offset icon
    .elseif (al==4)
        mov tvinsert.item.pszText,offset menu
    .elseif (al==5)
        mov tvinsert.item.pszText,offset dialog
    .elseif (al==6)
        mov tvinsert.item.pszText,offset string_table
    .elseif (al==7)
        mov tvinsert.item.pszText,offset font_directory
    .elseif (al==8)
        mov tvinsert.item.pszText,offset font
    .elseif (al==9)
        mov tvinsert.item.pszText,offset accelerators
    .elseif (al==10)
        mov tvinsert.item.pszText,offset unformatted_resource_data
    .elseif (al==11)
        mov tvinsert.item.pszText,offset message_table
    .elseif (al==12)
        mov tvinsert.item.pszText,offset group_cursor
    .elseif (al==14)
        mov tvinsert.item.pszText,offset group_icon
    .elseif (al==16)
        mov tvinsert.item.pszText,offset version_information
    .elseif (al==24)
        mov tvinsert.item.pszText,offset manifest
    .else
        szText templateres,"Unknow : %X"
        invoke wsprintf,addr buffer,offset templateres,eax
        mov tvinsert.item.pszText,offset buffer
    .endif
    popad                        
    ret
ResLib endp
; ########################################################################
CloseMapFile PROC
        invoke CloseHandle,hMapFile
        mov    hMapFile,0
        invoke CloseHandle,hFileRead
        ret
CloseMapFile endp
; ########################################################################
DlgProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
 LOCAL hdc:HDC 
 LOCAL ps:PAINTSTRUCT 
 LOCAL hfont:HFONT
 LOCAL hBitmap:DWORD
 LOCAL tvhit:TV_HITTESTINFO
 LOCAL menu_item:DWORD
 LOCAL res_offset:DWORD
 LOCAL res_length:DWORD
 
    .IF uMsg == WM_INITDIALOG
        mov eax,p_base
        add eax,3Ch
        mov eax,dword ptr [eax]
        add eax,p_base
        add eax,88h       ; Resource RVA
        mov eax,dword ptr [eax]
        add eax,p_base
        mov resource_rva,eax

        mov ebx,eax
        sub ebx,p_base
        invoke wsprintf,addr textbuffer,offset template,ebx
        invoke SetDlgItemText,hWnd,IDC_RS_RO,addr textbuffer
        invoke SetDlgItemText,hWnd,IDC_RS_RSRC,addr textbuffer
    .ELSEIF uMsg == WM_CLOSE
        invoke SendMessage, hWnd, WM_COMMAND, IDM_EXIT, 0
    .ELSEIF uMsg==WM_NOTIFY
        .IF wParam==IDC_RS_TREE
			mov		edx,lParam
			mov		eax,(NM_TREEVIEW ptr [edx]).hdr.code
			.IF eax==TVN_SELCHANGED
				;User changed selection in TreeView
				lea		edx,(NM_TREEVIEW ptr [edx]).itemNew
				mov		(TV_ITEM ptr [edx]).imask,TVIF_PARAM or TVIF_TEXT or TVIF_IMAGE
				lea		eax,tv_buffer
				mov		(TV_ITEM ptr [edx]).pszText,eax
				mov		(TV_ITEM ptr [edx]).cchTextMax,sizeof tv_buffer
				;check if item is a file
				push	edx
                invoke GetDlgItem,hWnd,IDC_RS_TREE
                pop edx
				invoke SendMessage,eax,TVM_GETITEM,0,edx
            .ELSEIF eax==NM_RCLICK

                invoke CreatePopupMenu
                mov handle_menu,eax
                szText szstrExport,"Export"
                invoke AppendMenu,handle_menu,MF_STRING,1,addr szstrExport

                invoke GetCursorPos,addr lpRect_tv
                mov eax,lpRect_tv.left
                mov edx,lpRect_tv.top
                invoke TrackPopupMenu,handle_menu,TPM_LEFTALIGN or TPM_RETURNCMD or TPM_TOPALIGN ,eax,edx,NULL,hWnd,NULL
                mov menu_item,eax

                invoke lstrcpyn,addr textbuffer,addr tv_buffer,7
                szText szstrOffset,"Offset"
                invoke lstrcmp,addr textbuffer,addr szstrOffset
                .if (eax==0)
                    .if (menu_item==1) ;Export
                        lea esi,tv_buffer
                        add esi,7
                        invoke lstrcpyn,addr textbuffer,esi,9
                        invoke htodw,addr textbuffer
                        add eax,p_base
                        mov res_offset,eax
                        
                        add esi,14
                        invoke lstrcpyn,addr textbuffer,esi,9
                        invoke htodw,addr textbuffer
                        mov res_length,eax

                        push hWnd
                        pop  ofn.hWndOwner
                        mov  ofn.lpstrFilter, OFFSET FilterString
                        mov ofn.lpstrDefExt, OFFSET bin_extend
                        mov  ofn.lpstrFile, OFFSET buffer
                        mov  ofn.nMaxFile,MAXSIZE
	                    mov [buffer],0  ;filename buffer a vide
        	            invoke GetSaveFileName, ADDR ofn
    	                .if eax==TRUE
    		                invoke CreateFile,ADDR buffer,\
    	                           GENERIC_READ or GENERIC_WRITE ,\
    	                           FILE_SHARE_READ or FILE_SHARE_WRITE,\
    	                           NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,\
    	                           NULL
    	                    mov hFileWrite,eax
    	                    invoke WriteFile,hFileWrite,res_offset,res_length,ADDR SizeWritten,NULL
    	                    invoke CloseHandle,hFileWrite
                            invoke MessageBox, hWnd,addr MsgBoxTextGood, addr MsgCaptionGood, MB_OK
                        .endif
                    .endif
                .endif                
                invoke DestroyMenu,handle_menu
            .ENDIF
        .ENDIF    
    .ELSEIF uMsg==WM_COMMAND
        mov eax,wParam
        mov edx,wParam
        shr edx,16
            .IF ax==IDC_ADDRESS
            .ENDIF
        .IF dx==BN_CLICKED
            .IF ax==IDC_RS_EXIT
                invoke EndDialog, hWnd, NULL
            .ELSEIF ax==IDC_RS_OPEN
                pushad
                invoke SendMessage,hwndTreeView,TVM_DELETEITEM,0,TVI_ROOT
                invoke ImageList_Create,16,16,ILC_COLOR16,2,10
                mov hImageList,eax
                invoke LoadBitmap,dllhandle,IDB_TREE
                mov hBitmap,eax
                invoke ImageList_Add,hImageList,hBitmap,NULL
                invoke DeleteObject,hBitmap
                invoke GetDlgItem,hWnd,IDC_RS_TREE
                mov hwndTreeView,eax
;                invoke SendMessage,hwndTreeView,TVM_SETIMAGELIST,0,hImageList
                xor eax,eax
                mov nb_total,eax                ;all sum at 0
                mov resource_data_size,eax
                mov total_rsrc_size,eax
                mov unicode_size,eax
                
                mov edi,resource_rva

                mov resource_rva_map,edi                    
                xor eax,eax
                mov ax,word ptr [edi+14]
                add ax,word ptr [edi+12]
                mov nb_IRDE,eax
                mov nb_IRDE_total,eax
                add edi,10h

                .while (nb_IRDE > 0)
                    mov eax,dword ptr [edi]
                    call ResLib
                    mov tvinsert.hParent,NULL
                    mov tvinsert.hInsertAfter,TVI_ROOT
                    mov tvinsert.item.imask,TVIF_TEXT+TVIF_IMAGE+TVIF_SELECTEDIMAGE
                    mov tvinsert.item.iImage,0
                    mov tvinsert.item.iSelectedImage,1
                    invoke SendMessage,hwndTreeView,TVM_INSERTITEM,0,addr tvinsert
                    mov hParent,eax
                    mov eax,dword ptr [edi+4]
                    .if (eax>80000000h)
                        xor eax,80000000h
                        mov esi,resource_rva_map                    
                        add esi,eax
                        xor eax,eax
                        mov ax,word ptr [esi+12]
                        add ax,word ptr [esi+14]
                        mov nb_,eax
                        add esi,10h
                        mov IRD,esi
                        .while (nb_>0)
                            mov ebx,dword ptr [esi]
                            .if (ebx<80000000h)
                                szText txtemplate_,"0x%02X -> %d"
                                invoke wsprintf,addr textbuffer,offset txtemplate_,ebx,ebx
                            .elseif
                                xor ebx,80000000h
                                add ebx,resource_rva_map
                                xor eax,eax
                                mov al,[ebx]
                                inc eax
                                shl eax,1
                                add unicode_size,eax
                                invoke unicopy,ebx,addr textbuffer
                            .endif
                            mov eax,hParent
                            mov tvinsert.hParent,eax
                            mov tvinsert.hInsertAfter,TVI_LAST
                            mov tvinsert.item.pszText,offset textbuffer
                            invoke SendMessage,hwndTreeView,TVM_INSERTITEM,0,addr tvinsert
                            mov hParent_,eax
                            mov ebx,dword ptr [esi+4]
                            xor ebx,80000000h
                            mov eax,resource_rva_map
                            add ebx,eax
                            mov ebx,dword ptr [ebx+14h]
                            add ebx,eax
                            mov eax,dword ptr [ebx]
                            mov ecx,dword ptr [ebx+4]
                            mov to_round,ecx
                            invoke wsprintf,addr textbuffer,offset res_template,eax,ecx
                            invoke round_,to_round,4
                            add resource_data_size,eax
                            mov eax,hParent_
                            mov tvinsert.hParent,eax
                            mov tvinsert.hInsertAfter,TVI_LAST
                            mov tvinsert.item.pszText,offset textbuffer
                            invoke SendMessage,hwndTreeView,TVM_INSERTITEM,0,addr tvinsert
                            
                            inc nb_total
                            dec nb_
                            add esi,8
                        .endw   
                    .endif
                    add edi,8
                    dec nb_IRDE
                    
                .endw
                mov eax,10h
                mov ebx,nb_IRDE_total
                shl ebx,3
                add eax,ebx
                mov size_IRDE,eax
                
                invoke round_,unicode_size,4
                mov unicode_size,eax
                
                mov eax,nb_IRDE_total
                shl eax,4
                mov ebx,nb_total
                imul ebx,30h
                add eax,ebx
                mov size_IRE,eax
                add eax,size_IRDE

                mov ebx,eax
                mov IRD_total_size,eax
                
                add ebx,resource_data_size
                add ebx,unicode_size
                mov total_rsrc_size,ebx
                
                add ebx,resource_rva_map
                
                invoke wsprintf,addr textbuffer,offset txresultat,nb_IRDE_total,nb_total,total_rsrc_size
                invoke SetDlgItemText,hWnd,IDC_RS_NOTE,addr textbuffer
                invoke GetDlgItem,hWnd,IDC_RS_CREATE
                invoke EnableWindow,eax,TRUE
                popad
            .ELSEIF ax==IDC_RS_CREATE
                pushad
                invoke GetDlgItemText,hWnd,IDC_RS_RO,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov resource_offset,eax

                invoke GlobalAlloc,GMEM_MOVEABLE or GMEM_ZEROINIT,total_rsrc_size
                mov  hMemory_rs,eax
                invoke GlobalLock,hMemory_rs
                mov  pMemory_rs,eax
                mov esi,resource_rva_map
                mov edi,pMemory_rs
                mov eax,nb_IRDE_total
                mov nb_IRDE,eax

                invoke mem_copy,esi,edi,10h     ; IRDE
                
                mov eax,nb_IRDE                 ; CALCUL INDEX 3
                shl eax,4
                mov ebx,nb_total
                shl ebx,3
                add eax,ebx
                add eax,size_IRDE
                mov index3_d,eax                                
                
                mov eax,index3_d                ; CALCUL INDEX 4
                mov ebx,nb_total
                imul ebx,18h
                add eax,ebx
                mov index4_d,eax
                
                mov eax,IRD_total_size
                mov unicode_index,eax
                add eax,unicode_size
                mov index5_d,eax
                
                mov index2_s,esi
                mov ebx,size_IRDE
                add index2_s,ebx
                mov index2_d,edi
                add index2_d,ebx
                mov ebx,pMemory_rs
                sub index2_d,ebx

                add esi,10h
                add edi,10h
                mov index1_s,esi
                mov index1_d,edi
                
                .while (nb_IRDE > 0)
                    invoke mem_copy,index1_s,index1_d,8     ; IRD TABLE
                    mov esi,index1_s
                    mov eax,dword ptr [esi+4]
                    .if (eax>80000000h)
                        mov ebx,index2_d
                        or ebx,80000000h
                        mov edi,index1_d
                        mov dword ptr [edi+4],ebx           ;MAJ good offset
                        xor eax,80000000h
                        mov esi,resource_rva_map                    
                        add esi,eax
                        xor eax,eax
                        mov ax,word ptr [esi+12]
                        add ax,word ptr [esi+14]
                        mov nb_,eax
                        mov edi,index2_d
                        add edi,pMemory_rs
                        invoke mem_copy,esi,edi,10h     ; IRD TABLE TYPE ENTRY
                           
                        add esi,10h
                        add edi,10h
                        mov index2_d,edi
                        .while (nb_>0)
                            invoke mem_copy,esi,edi,8     ; IRD TABLE ENTRY

                            mov eax,dword ptr [esi]
                            .if (eax>80000000)              ;UNICODE
                                xor eax,80000000h
                                add eax,resource_rva_map
                                xor ecx,ecx
                                mov cl,[eax]
                                inc ecx
                                shl ecx,1
                                mov ebx,unicode_index
                                add ebx,pMemory_rs
                                invoke mem_copy,eax,ebx,ecx     ; UNICODE STRING
                                mov eax,unicode_index
                                or eax,80000000h
                                mov dword ptr [edi],eax         ; MAJ UNICODE OFFSET
                                add unicode_index,ecx
                            .endif                        
                            
                            mov ebx,index3_d              ; MAJ a faire !!!!!!!
                            mov eax,dword ptr [esi+4]
                            xor eax,80000000h                            
                            add eax,resource_rva_map
                            add ebx,pMemory_rs
                            invoke mem_copy,eax,ebx,18h     ; IRD TABLE ENTRY 2
                            
                            mov ebx,index3_d
                            or ebx,80000000h
                            mov dword ptr [edi+4],ebx       ;MAJ good offset
                            

                            mov index4_s,eax
                            mov ebx,index4_d
                            mov eax,dword ptr [eax+14h]
                            add eax,resource_rva_map
                            add ebx,pMemory_rs
                            invoke mem_copy,eax,ebx,10h     ; IRD TABLE ENTRY 3
                            mov index5_s,eax
                            
                            mov ebx,index4_d
                            mov eax,index3_d
                            add eax,pMemory_rs
                            mov dword ptr [eax+14h],ebx     ;MAJ good offset
                            
                            mov ebx,index5_d
                            mov eax,index5_s
                            mov ecx,dword ptr [eax+4]       ;RESOURCE SIZE
                            mov eax,dword ptr [eax]         ;REAL OFFSET
                            add eax,p_base
                            add ebx,pMemory_rs
                            invoke mem_copy,eax,ebx,ecx     ; RESOURCE DATA COPY

                            mov ebx,index5_d
                            mov eax,index4_d
                            add eax,pMemory_rs
                            add ebx,resource_offset
                            mov dword ptr [eax],ebx         ; MAJ GOOD offset

                            add index3_d,18h
                            add index4_d,10h
                            
                            invoke round_,ecx,4
                            add index5_d,eax
                                                          
                            add esi,8
                            add edi,8
                            mov index2_d,edi
                            dec nb_
                           
                        .endw
                        add index1_s,8
                        add index1_d,8
                        mov ebx,pMemory_rs
                        sub index2_d,ebx
                        dec nb_IRDE
                    .endif 
                .endw

                push hWnd
                pop  ofn.hWndOwner
                mov ofn.Flags,OFN_LONGNAMES or OFN_EXPLORER or OFN_HIDEREADONLY
;                mov ofn.lpstrInitialDir, offset dirbuffer
                mov  ofn.lpstrFilter, OFFSET FilterString_copy
                mov byte ptr [buffer],0
                invoke GetSaveFileName, ADDR ofn
                .if eax==TRUE
                    invoke CreateFile,ADDR buffer,GENERIC_READ or GENERIC_WRITE ,\
                          FILE_SHARE_READ or FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
                    .if (eax)
                        mov hFileWrite,eax
                        invoke WriteFile,hFileWrite,pMemory_rs,total_rsrc_size,ADDR SizeReadWrite,NULL
                        invoke CloseHandle,hFileWrite
                        invoke MessageBox, NULL,addr MsgBoxTextGood, addr MsgCaptionGood, MB_OK
                    .endif
                .endif

                invoke GlobalUnlock,pMemory_rs
                invoke GlobalFree,hMemory_rs
                popad
            .ENDIF
        .ENDIF
    .ELSE
        mov eax, FALSE
        ret
    .ENDIF
    mov eax, TRUE
    ret
DlgProc endp
; ########################################################################
DlgDumpProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
LOCAL dump_start:DWORD
LOCAL dump_size:DWORD

    .IF uMsg == WM_INITDIALOG
    .ELSEIF uMsg == WM_CLOSE
        invoke SendMessage, hWnd, WM_COMMAND, IDM_EXIT, 0
    .ELSEIF uMsg==WM_COMMAND
        mov eax,wParam
        mov edx,wParam
        shr edx,16
        .IF dx==BN_CLICKED
            .IF ax==IDC_CANCELDUMP
                invoke EndDialog, hWnd, NULL
            .ELSEIF ax==IDC_DUMPDUMP
                pushad
                invoke GetDlgItemText,hWnd,IDC_DOFF,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov dump_start,eax
                invoke GetDlgItemText,hWnd,IDC_DSIZE,addr textbuffer,10
                invoke htodw,addr textbuffer
                mov dump_size,eax
                .if dump_start!=0 && dump_size!=0
                    push hWnd
                    pop  ofn.hWndOwner
                    mov  ofn.lpstrFilter, OFFSET FilterString
                    mov ofn.lpstrDefExt, OFFSET bin_extend
                    mov  ofn.lpstrFile, OFFSET buffer
                    mov  ofn.nMaxFile,MAXSIZE
	                mov [buffer],0  ;filename buffer a vide
    	            invoke GetSaveFileName, ADDR ofn
	                .if eax==TRUE
		                invoke CreateFile,ADDR buffer,\
	                           GENERIC_READ or GENERIC_WRITE ,\
	                           FILE_SHARE_READ or FILE_SHARE_WRITE,\
	                           NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,\
	                           NULL
	                    mov hFileWrite,eax
	                    invoke WriteFile,hFileWrite,dump_start,dump_size,ADDR SizeWritten,NULL

	                    invoke CloseHandle,hFileWrite
                        invoke MessageBox, hWnd,addr MsgBoxTextGood, addr MsgCaptionGood, MB_OK
 	             	.endif
                .endif
             	popad
            .ENDIF
        .ENDIF
    .ELSE
        mov eax, FALSE
        ret
    .ENDIF
    mov eax, TRUE
    ret
DlgDumpProc endp
; ########################################################################
DlgFixerProc proc hWin:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
	LOCAL	ts:TC_ITEM

	.IF uMsg==WM_COMMAND 
		mov eax,wParam 
		mov edx,wParam 
		shr edx,16 
		.IF dx==BN_CLICKED 
			.IF ax==IDCANCEL
			.ENDIF
		.ENDIF
	.ELSEIF uMsg==WM_NOTIFY
		mov eax,lParam
		mov eax,(NMHDR PTR [eax]).code
		.IF eax==TCN_SELCHANGE
			mov eax,WhichTabChosen
			.IF eax == 0
				invoke ShowWindow,hTab1,SW_HIDE
				invoke ShowWindow,hTab2,SW_SHOWDEFAULT
				mov WhichTabChosen,1
			.ELSEIF eax != 0
				invoke ShowWindow,hTab2,SW_HIDE
				invoke ShowWindow,hTab1,SW_SHOWDEFAULT
				mov WhichTabChosen,0
			.ENDIF
		.ENDIF
	.ELSEIF uMsg==WM_INITDIALOG
		invoke GetDlgItem,hWin,IDC_TAB		
		mov		hTab,eax
		mov		ts.imask,TCIF_TEXT			
		mov		ts.lpReserved1,0			
		mov		ts.lpReserved2,0 			
		mov		ts.pszText,offset TabTitle1 	
		mov		ts.cchTextMax,sizeof TabTitle1	
		mov		ts.iImage,0				
		mov		ts.lParam,0				
		invoke SendMessage,hTab,TCM_INSERTITEM,0,addr ts
		mov		ts.pszText,offset TabTitle2
		mov		ts.cchTextMax,sizeof TabTitle2
		invoke SendMessage,hTab,TCM_INSERTITEM,1,addr ts
		invoke CreateDialogParam,dllhandle,IDD_DLGPELOCK,hTab,addr DlgPelockProc ,0
		mov hTab1,eax
		invoke CreateDialogParam,dllhandle,IDD_DLGVIDE,hTab,addr DlgPelockProc ,0
		mov hTab2,eax
		mov WhichTabChosen,0 				
		invoke ShowWindow,hTab1,SW_SHOWDEFAULT
	.ELSEIF uMsg==WM_CLOSE
		invoke EndDialog,hWin,NULL
	.else
		mov eax,FALSE
		ret
	.endif
	mov  eax,TRUE
	ret
DlgFixerProc endp
; ########################################################################
; ########################################################################
DlgPelockProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
    LOCAL seh:SEH
	LOCAL dco:DWORD
	LOCAL dro:DWORD
	LOCAL pecod:DWORD
	LOCAL pecos:DWORD
	LOCAL patern:DWORD

    .IF uMsg == WM_INITDIALOG
        invoke SetDlgItemText,hWnd,IDC_PATERN,addr pelock_patern_ascii
       	call get_code_section_info 
        invoke wsprintf,addr textbuffer,offset template,code_start
        invoke SetDlgItemText,hWnd,IDC_CODESTART,addr textbuffer
       	mov esi,code_end
       	sub esi,code_start
        invoke wsprintf,addr textbuffer,offset template,esi
        invoke SetDlgItemText,hWnd,IDC_CODESIZE,addr textbuffer
    .ELSEIF uMsg == WM_CLOSE
        invoke SendMessage, hWnd, WM_COMMAND, IDM_EXIT, 0
    .ELSEIF uMsg==WM_COMMAND
        mov eax,wParam
        mov edx,wParam
        shr edx,16
        .IF dx==BN_CLICKED
            .IF ax==IDC_FIXEXIT
                invoke EndDialog, hWnd, NULL
            .ELSEIF ax==IDC_PELOCKS
            	pushad
                invoke GetDlgItemText,hWnd,IDC_CODESTART,addr textbuffer,10
                invoke htodw,addr textbuffer
            	mov code_start,eax
                invoke GetDlgItemText,hWnd,IDC_CODESIZE,addr textbuffer,10
                invoke htodw,addr textbuffer
            	mov esi,eax
 				invoke BMHBinsearch,0,code_start,esi,addr pelock_search_partial,8
			 	.if eax == -1
                    invoke MessageBox,NULL,addr pelock_pattern_error,addr AppName,MB_OK
           		.elseif
           			add eax,code_start
           			add eax,8
           			.if byte ptr [eax] == 0e8h
           				mov edi,dword ptr [eax+1]
           				add edi,eax
           				add edi,4
                        invoke wsprintf,addr textbuffer,offset template,edi
                        invoke SetDlgItemText,hWnd,IDC_DRO,addr textbuffer
                        sub edi,393h
                        invoke wsprintf,addr textbuffer,offset template,edi
                        invoke SetDlgItemText,hWnd,IDC_DCO,addr textbuffer
           			.endif
           		.endif
            	popad
            .ELSEIF ax==IDC_FIXCODE
            	pushad
                assume fs:nothing
                push fs:[0]
                pop seh.PrevLink
                mov seh.CurrentHandler,offset SEHHandler
                mov seh.SafeOffset,offset error_fixer
                lea eax,seh
                mov fs:[0], eax
                mov seh.PrevEsp,esp
                mov seh.PrevEbp,ebp

                invoke GetDlgItemText,hWnd,IDC_DCO,addr textbuffer,10
                invoke htodw,addr textbuffer
				mov dco,eax
                invoke GetDlgItemText,hWnd,IDC_DRO,addr textbuffer,10
                invoke htodw,addr textbuffer
				mov dro,eax
                invoke GetDlgItemText,hWnd,IDC_CODESTART,addr textbuffer,10
                invoke htodw,addr textbuffer
				mov pecod,eax
                invoke GetDlgItemText,hWnd,IDC_CODESIZE,addr textbuffer,10
                invoke htodw,addr textbuffer
				mov pecos,eax
                invoke GetDlgItemText,hWnd,IDC_PATERN,addr textbuffer,10
                invoke htodw,addr textbuffer
				mov patern,eax
            	invoke pelock_decrypt,dro,dco,pecod,pecos,patern
            	.if (eax)
           		    invoke wsprintf,addr textbuffer,offset message_pelock,count_decrypt,count_crypt
                    invoke MessageBox,NULL,addr textbuffer,addr AppName,MB_OK
            	.endif
            	
            	jmp error_fixer_end
            error_fixer:
                push seh.PrevLink
                pop fs:[0]
                invoke MessageBox,NULL,addr message_error_fixer,addr AppName,MB_OK
                jmp end_fixer
            error_fixer_end:
                push seh.PrevLink
                pop fs:[0]
            end_fixer:
            	popad
            .ENDIF
        .ENDIF
    .ELSE
        mov eax, FALSE
        ret
    .ENDIF
    mov eax, TRUE
    ret
DlgPelockProc endp
; ########################################################################
DlgProcText proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
    .IF uMsg == WM_INITDIALOG
    	invoke SetDlgItemText,hWnd,IDC_EDITTEXTAPI,pMemory_log
    .ELSEIF uMsg == WM_CLOSE
        invoke EndDialog, hWnd, NULL
    .ELSEIF uMsg==WM_COMMAND
        mov eax,wParam
        mov edx,wParam
        shr edx,16
        .IF dx==BN_CLICKED
            .IF ax==IDCANCEL
                invoke EndDialog, hWnd, NULL
            .ELSEIF ax==IDOK
                pushad
                mov edi,pMemory_log
                mov ecx,nbmemloc
                xor eax,eax
                repne scasb             ; find _end of text
                sub edi,pMemory_log
                mov nbmemloc,edi
                push hWnd
                pop  ofn.hWndOwner
                mov  ofn.lpstrFilter, OFFSET FilterString_txt
                mov ofn.lpstrDefExt, OFFSET txt_extend
                mov byte ptr [buffer],0
                invoke GetSaveFileName, ADDR ofn
                .if eax==TRUE
                    invoke CreateFile,ADDR buffer,GENERIC_READ or GENERIC_WRITE ,\
                          FILE_SHARE_READ or FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
                    .if (eax)
                        mov hFileWrite,eax
                        invoke WriteFile,hFileWrite,pMemory_log,nbmemloc,ADDR SizeReadWrite,NULL
                        invoke CloseHandle,hFileWrite
                        invoke MessageBox, NULL,addr MsgBoxTextGood, addr MsgCaptionGood, MB_OK
                    .endif
                .endif
                popad
            .ENDIF
        .ENDIF
    .ELSE
        mov eax, FALSE
        ret
    .ENDIF
    mov eax, TRUE
    ret
DlgProcText endp
; ########################################################################
; ########################################################################
;                        Transparency W2K
; ########################################################################
Transparency proc winh:DWORD,level_transp:DWORD
LOCAL h_SLWA
    szText SLWA_str,"SetLayeredWindowAttributes"
    szText User32_str,"User32"
    invoke GetWindowLong,winh,GWL_EXSTYLE
    or eax,WS_EX_LAYERED
    invoke SetWindowLong,winh,GWL_EXSTYLE,eax
    invoke LoadLibrary,offset User32_str
    .if (eax)
        invoke GetProcAddress,eax,offset SLWA_str 
        .if (eax)
            mov h_SLWA,eax
            push 00000002h      ;LWA_ALPHA
            push level_transp   ;% of 255
            push 0              ;transparency color key
            push winh
            call h_SLWA         ;WINAPI *lpfnSetLayeredWindowAttributes)
        .endif                  ;(HWND hWnd, COLORREF crKey,BYTE bAlpha, DWORD dwFlags)
    .endif
    ret
Transparency endp
; ########################################################################
;                        DISASM ROUTINE
; ########################################################################
locate_disam proc
    szText DisInstr,"\dll\DisInstr.dll"
    invoke lstrcpy,offset textbuffer2,offset plugbuffer
    invoke lstrcat,offset textbuffer2,offset DisInstr
    invoke LoadLibrary,offset textbuffer2
    .if (eax)
        mov handle_DisInstr,eax
        szText _feedDisa,"_feedDisa"
        invoke GetProcAddress,handle_DisInstr,offset _feedDisa 
        .if (eax)
            mov h_feedDisa,eax
        .endif
    .elseif
        mov eax,-1
    .endif
    ret
locate_disam endp

; ___________________________________________________________________________
include lde32bin.inc   ; LDE32
;------------------------------------------------------------------------------
End DllEntry
;------------------------------------------------------------------------------
;------------------------------------------------------------------------------
