WinMain         proto :DWORD,:DWORD,:DWORD,:DWORD
svadditemmodule proto :DWORD, :DWORD, :DWORD
svadditemapi    proto :DWORD, :DWORD, :DWORD, :DWORD
getprocname     proto :DWORD,:DWORD,:DWORD
fonction2name   proto :DWORD,:DWORD
DlgProc         proto :DWORD,:DWORD,:DWORD,:DWORD
DlgProcText     proto :DWORD,:DWORD,:DWORD,:DWORD
DlgDumpProc		proto :DWORD,:DWORD,:DWORD,:DWORD
DlgFixerProc	proto :DWORD,:DWORD,:DWORD,:DWORD
DlgPelockProc 	proto :DWORD,:DWORD,:DWORD,:DWORD
unicopy         proto :DWORD,:DWORD
round_          proto :DWORD,:DWORD
mem_copy        proto :DWORD,:DWORD,:DWORD
Transparency    proto :DWORD,:DWORD
check_jmp_table	proto :DWORD,:DWORD,:DWORD
pelock_decrypt  proto :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
normalize       proto :DWORD,:DWORD
Module32First PROTO STDCALL :DWORD,:DWORD
Module32Next PROTO STDCALL :DWORD,:DWORD

include \masm32\include\windows.inc
include \masm32\include\user32.inc
include \masm32\include\kernel32.inc
include \masm32\include\gdi32.inc
include \masm32\include\masm32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\advapi32.inc
include \masm32\include\ComCtl32.inc
include \masm32\include\Shell32.inc
include \masm32\include\Ole32.inc

includelib \masm32\lib\user32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\gdi32.lib
includelib \masm32\lib\masm32.lib
includelib \masm32\lib\comdlg32.lib
includelib \masm32\lib\advapi32.lib
includelib \masm32\lib\ComCtl32.lib
includelib \masm32\lib\Shell32.lib
includelib \masm32\lib\Ole32.lib

; --------------- Macros Section
szText  MACRO Name,Text:VARARG
        LOCAL   lbl
        jmp lbl
Name    db  Text,0
        lbl:
ENDM
    ; ---------------------
    ; literal string MACRO
    ; ---------------------
      literal MACRO quoted_text:VARARG
        LOCAL local_text
        .data
          local_text db quoted_text,0
        align 4
        .code
        EXITM <local_text>
      ENDM
    ; --------------------------------
    ; string address in INVOKE format
    ; --------------------------------
      SADD MACRO quoted_text:VARARG
        EXITM <ADDR literal(quoted_text)>
      ENDM
    ; --------------------------------
    ; string OFFSET for manual coding
    ; --------------------------------
      CTXT MACRO quoted_text:VARARG
        EXITM <offset literal(quoted_text)>
      ENDM
 
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
IDC_RSRC                                        equ 3022
IDC_DISASM                                      equ 3023
IDC_LISTDISASM                                  equ 3024
IDC_NBDISASM                                    equ 3025
IDC_TXT                                         equ 3026
IDC_PEBASE                                      equ 3027

IDC_JMPSTART									equ 1003
IDC_JMPEND										equ 1004
IDC_CHKJMP										equ 1001
IDC_DUMP										equ 1007
IDC_CODEFIXER									equ 1009

IDD_DIALOG                                      equ 102
IDM_EXIT                                        equ 5000
IDC_RS_OPEN                                     equ 3100
IDC_RS_EXIT                                     equ 3101
IDC_RS_RSRC                                     equ 3109
IDC_RS_TREE                                     equ 3110
IDC_RS_CREATE                                   equ 3111
IDC_RS_RO                                       equ 3112
IDC_RS_NOTE                                     equ 3113
IDB_TREE                                        equ 4006

IDD_TEXTD                                       equ 103
IDC_EDITTEXTAPI                                 equ 3200

;Res\dump.dlg
IDD_DLGDUMP								equ 1000
IDC_DUMPDUMP							equ 1001
IDC_CANCELDUMP							equ 1002
IDC_DOFF								equ 1003
IDC_STC3								equ 1004
IDC_STC4								equ 1005
IDC_DSIZE								equ 1006

;Res\Pelock.dlg
IDD_DLGPELOCK							equ 1001
IDC_FIXEXIT								equ 1002
IDC_DCO									equ 1003
IDC_STC5								equ 1004
IDC_STC6								equ 1005
IDC_DRO									equ 1006
IDC_STC7								equ 1007
IDC_STC8								equ 1008
IDC_CODESTART							equ 1009
IDC_CODESIZE							equ 1010
IDC_STC9								equ 1011
IDC_PATERN								equ 1012
IDC_FIXCODE								equ 1013
IDC_PELOCKS								equ 2001

;Res\Fixer.dlg
IDD_DLGFIXER							equ 1002
IDC_TAB									equ 1001

;Res\vide.dlg
IDD_DLGVIDE								equ 1003

SIDEBYSIDE_COMMONCONTROLS                       equ 1 

LIMITEDLL equ 20000000h
MAXSIZE equ 260
PBM_SETRANGE32 equ     (1030)
NBLIGNE                                         equ 16

SEH struct
    PrevLink dd ?       ; the address of the previous seh structure
    CurrentHandler dd ? ; the address of the new exception handler
    SafeOffset dd ? ; The offset where it's safe to continue execution
    PrevEsp dd ?        ; the old value in esp
    PrevEbp dd ?        ; The old value in ebp
SEH ends

WS_EX_LAYERED                                   equ 00080000h

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
FilterString    db "Bin Files",0    ;dont insert between
bin_extend      db "*.bin",0,0      ;here
template        db "%x",0  
txtemplate      db "%s",0             
decitemplate    db "%d",0             

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
template_str_40 db "%-40s",0
template_str_16 db "%-16s",0
nbitem          dd 0
Titlecolumn     db "API Name",0
Titlecolumn1    db "Module Name",0
Titlecolumn0    db "Offset",0
Titlecolumn2    db "Address",0
Titlecolumn3    db "Module Name",0
Titlecolumn4    db "Base",0
Titlecolumn5    db "Size",0
errormsg        db "%x Not found !!!",0
dir_plug        db "*.dll",0
plug_fontion_n  db "process_add",0
antislash       db "\",0
message_error   db "Error rebuilding IT !",0
message_error_fixer	   db "Error fixing code !",0
message_error_update   db "Error updating thunk !",0
message_error_search   db "Error searching !",0
message_error_disasm   db "Error Disasm dll !",0
message_pelock	db "Code section fixed !",0dh,0ah,"%d Decrypt call - %d Crypt call",0dh,0ah
				db "You can dump code section",0
szsvKey         db  'Software\SV',0
szsvDir         db  'plugdir',0
szSIZE          dd 256
search_call     db 0ffh,015h
add_to_search   dd 0
v_rva           dd 0
buffer1         dd 0
buffer2         dd 0
kernel          db "kernel32.dll",0
openprocess     db "OpenProcess",0
menutest        db "test popup",0
handle_menu     dd 0
GetVersion_             db "GetVersion",0
GetVersionExA_          db "GetVersionExA",0
GetCurrentProcess_      db "GetCurrentProcess",0
GetCurrentProcessId_    db "GetCurrentProcessId",0
GetCommandLineA_        db "GetCommandLineA",0

GetModuleHandleA_		db "GetModuleHandleA",0
GetProcAddress_			db "GetProcAddress",0

;ASAPI           db " ASprotect APIs",0
freeresource    db "FreeResource",0
lockresource    db "LockResource",0
;plugbuffer      db "D:\Masm32-files\sv\XP\IAT_rebuilder",0
ntdll_str       db "ntdll.dll",0
getlasterror_9x db "GetLastError",0
getlasterror_XP db "RtlGetLastWin32Error",0
setlasterror_9x db "SetLastError",0
setlasterror_XP db "RtlRestoreLastWin32Error",0
message_ntdll   db "NTdll.dll's api found -> check name !",0
plug_title1     db "Plugin dir not found !!",0
plug_title2     db "Please locate plugin dir",0
linefeed        db 0dh,0ah,0
space           db ' ',0
;##############################################################################
txresultat                      db "%d Resources Types -> %d Resources -> Total Size:%x",0
res_template                    db "Offset:%08x Size:%08x",0
unicode_size                    dd 0
unknown                         db "unknown",0
cursor                          db "cursor",0
bitmap                          db "bitmap",0                     
icon                            db "icon",0                       
menu                            db "menu",0                       
dialog                          db "dialog",0                     
string_table                    db "string table",0               
font_directory                  db "font directory",0             
font                            db "font",0                       
accelerators                    db "accelerators",0               
unformatted_resource_data       db "unformatted resource data",0 
message_table                   db "message table",0             
group_cursor                    db "group cursor",0              
group_icon                      db "group icon",0                
version_information             db "version information",0
manifest                        db "manifest",0
inconnu                         db "??",0
DragMode                        dd FALSE
MsgCaptionGood                  db "Yeah!",0
MsgCaptionError                 db "Error!",0
MsgBoxTextGood                  db "File successfully created !",0
FilterString_copy               db "Bin Files",0,"*.bin",0,0
FilterString_txt                db "Text Files",0   ;dont insert between
txt_extend                      db "*.txt",0,0      ;here
template_disasm                 db "%08X   %s",0
sv_copyright                    db '----------------   Generated by SV IT & Rsrc Rebuilder   ----------------',0
jmp_table_search_byte			dd 0
;pelock_search_byte				db 0ebh,06,0ebh,0fbh ;Pelock1.4
pelock_search_byte				db 0EBh,006h,0EBh,000h,0EBh,000h,0EBh,000h
pelock_search_partial			db 0EBh,006h,0CDh,020h,0EBh,0FDh,0CDh,020h
TabTitle1       				db "Pelock v1.4",0
TabTitle2       				db "Tab2",0
pelock_pattern_error			db "Pelock patern not found !",0
pelock_patern_ascii				db "0xEB,0x06,0xEB,0x00,0xEB,0x00,0xEB,0x00,0xEB,0x06,0xCD,0x20,0xEB,0xFD,0xCD,0x20",0

kernel32_api db "AddAtomA",0
 db "AddAtomW",0
 db "AllocConsole",0
 db "AllocLSCallback",0
 db "AllocSLCallback",0
 db "AreFileApisANSI",0
 db "BackupRead",0
 db "BackupSeek",0
 db "BackupWrite",0
 db "Beep",0
 db "BeginUpdateResourceA",0
 db "BeginUpdateResourceW",0
 db "BuildCommDCBA",0
 db "BuildCommDCBAndTimeoutsA",0
 db "BuildCommDCBAndTimeoutsW",0
 db "BuildCommDCBW",0
 db "CallNamedPipeA",0
 db "CallNamedPipeW",0
 db "Callback12",0
 db "Callback16",0
 db "Callback20",0
 db "Callback24",0
 db "Callback28",0
 db "Callback32",0
 db "Callback36",0
 db "Callback40",0
 db "Callback44",0
 db "Callback48",0
 db "Callback4",0
 db "Callback52",0
 db "Callback56",0
 db "Callback60",0
 db "Callback64",0
 db "Callback8",0
 db "CancelDeviceWakeupRequest",0
 db "CancelIo",0
 db "CancelWaitableTimer",0
 db "ClearCommBreak",0
 db "ClearCommError",0
 db "CloseHandle",0
 db "CloseProfileUserMapping",0
 db "CloseSystemHandle",0
 db "CommConfigDialogA",0
 db "CommConfigDialogW",0
 db "CompareFileTime",0
 db "CompareStringA",0
 db "CompareStringW",0
 db "ConnectNamedPipe",0
 db "ContinueDebugEvent",0
 db "ConvertDefaultLocale",0
 db "ConvertThreadToFiber",0
 db "ConvertToGlobalHandle",0
 db "CopyFileA",0
 db "CopyFileExA",0
 db "CopyFileExW",0
 db "CopyFileW",0
 db "CreateConsoleScreenBuffer",0
 db "CreateDirectoryA",0
 db "CreateDirectoryExA",0
 db "CreateDirectoryExW",0
 db "CreateDirectoryW",0
 db "CreateEventA",0
 db "CreateEventW",0
 db "CreateFiber",0
 db "CreateFileA",0
 db "CreateFileMappingA",0
 db "CreateFileMappingW",0
 db "CreateFileW",0
 db "CreateIoCompletionPort",0
 db "CreateKernelThread",0
 db "CreateMailslotA",0
 db "CreateMailslotW",0
 db "CreateMutexA",0
 db "CreateMutexW",0
 db "CreateNamedPipeA",0
 db "CreateNamedPipeW",0
 db "CreatePipe",0
 db "CreateProcessA",0
 db "CreateProcessW",0
 db "CreateRemoteThread",0
 db "CreateSemaphoreA",0
 db "CreateSemaphoreW",0
 db "CreateSocketHandle",0
 db "CreateTapePartition",0
 db "CreateThread",0
 db "CreateToolhelp32Snapshot",0
 db "CreateWaitableTimerA",0
 db "CreateWaitableTimerW",0
 db "DebugActiveProcess",0
 db "DebugBreak",0
 db "DefineDosDeviceA",0
 db "DefineDosDeviceW",0
 db "DeleteAtom",0
 db "DeleteCriticalSection",0
 db "DeleteFiber",0
 db "DeleteFileA",0
 db "DeleteFileW",0
 db "DeviceIoControl",0
 db "DisableThreadLibraryCalls",0
 db "DisconnectNamedPipe",0
 db "DosDateTimeToFileTime",0
 db "DuplicateHandle",0
 db "EndUpdateResourceA",0
 db "EndUpdateResourceW",0
 db "EnterCriticalSection",0
 db "EnumCalendarInfoA",0
 db "EnumCalendarInfoExA",0
 db "EnumCalendarInfoExW",0
 db "EnumCalendarInfoW",0
 db "EnumDateFormatsA",0
 db "EnumDateFormatsExA",0
 db "EnumDateFormatsExW",0
 db "EnumDateFormatsW",0
 db "EnumResourceLanguagesA",0
 db "EnumResourceLanguagesW",0
 db "EnumResourceNamesA",0
 db "EnumResourceNamesW",0
 db "EnumResourceTypesA",0
 db "EnumResourceTypesW",0
 db "EnumSystemCodePagesA",0
 db "EnumSystemCodePagesW",0
 db "EnumSystemLocalesA",0
 db "EnumSystemLocalesW",0
 db "EnumTimeFormatsA",0
 db "EnumTimeFormatsW",0
 db "EraseTape",0
 db "EscapeCommFunction",0
 db "ExitProcess",0
 db "ExitThread",0
 db "ExpandEnvironmentStringsA",0
 db "ExpandEnvironmentStringsW",0
 db "FT_Exit0",0
 db "FT_Exit12",0
 db "FT_Exit16",0
 db "FT_Exit20",0
 db "FT_Exit24",0
 db "FT_Exit28",0
 db "FT_Exit32",0
 db "FT_Exit36",0
 db "FT_Exit4",0
 db "FT_Exit40",0
 db "FT_Exit44",0
 db "FT_Exit48",0
 db "FT_Exit52",0
 db "FT_Exit56",0
 db "FT_Exit8",0
 db "FT_Prolog",0
 db "FT_Thunk",0
 db "FatalAppExitA",0
 db "FatalAppExitW",0
 db "FatalExit",0
 db "FileTimeToDosDateTime",0
 db "FileTimeToLocalFileTime",0
 db "FileTimeToSystemTime",0
 db "FillConsoleOutputAttribute",0
 db "FillConsoleOutputCharacterA",0
 db "FillConsoleOutputCharacterW",0
 db "FindAtomA",0
 db "FindAtomW",0
 db "FindClose",0
 db "FindCloseChangeNotification",0
 db "FindFirstChangeNotificationA",0
 db "FindFirstChangeNotificationW",0
 db "FindFirstFileA",0
 db "FindFirstFileExA",0
 db "FindFirstFileExW",0
 db "FindFirstFileW",0
 db "FindNextChangeNotification",0
 db "FindNextFileA",0
 db "FindNextFileW",0
 db "FindResourceA",0
 db "FindResourceExA",0
 db "FindResourceExW",0
 db "FindResourceW",0
 db "FlushConsoleInputBuffer",0
 db "FlushFileBuffers",0
 db "FlushInstructionCache",0
 db "FlushViewOfFile",0
 db "FoldStringA",0
 db "FoldStringW",0
 db "FormatMessageA",0
 db "FormatMessageW",0
 db "FreeConsole",0
 db "FreeEnvironmentStringsA",0
 db "FreeEnvironmentStringsW",0
 db "FreeLSCallback",0
 db "FreeLibrary",0
 db "FreeLibraryAndExitThread",0
 db "FreeResource",0
 db "FreeSLCallback",0
 db "GenerateConsoleCtrlEvent",0
 db "GetACP",0
 db "GetAtomNameA",0
 db "GetAtomNameW",0
 db "GetBinaryType",0
 db "GetBinaryTypeA",0
 db "GetBinaryTypeW",0
 db "GetCPInfo",0
 db "GetCPInfoExA",0
 db "GetCPInfoExW",0
 db "GetCalendarInfoA",0
 db "GetCalendarInfoW",0
 db "GetCommConfig",0
 db "GetCommMask",0
 db "GetCommModemStatus",0
 db "GetCommProperties",0
 db "GetCommState",0
 db "GetCommTimeouts",0
 db "GetCommandLineA",0
 db "GetCommandLineW",0
 db "GetCompressedFileSizeA",0
 db "GetCompressedFileSizeW",0
 db "GetComputerNameA",0
 db "GetComputerNameW",0
 db "GetConsoleCP",0
 db "GetConsoleCursorInfo",0
 db "GetConsoleMode",0
 db "GetConsoleOutputCP",0
 db "GetConsoleScreenBufferInfo",0
 db "GetConsoleTitleA",0
 db "GetConsoleTitleW",0
 db "GetCurrencyFormatA",0
 db "GetCurrencyFormatW",0
 db "GetCurrentDirectoryA",0
 db "GetCurrentDirectoryW",0
 db "GetCurrentProcess",0
 db "GetCurrentProcessId",0
 db "GetCurrentThread",0
 db "GetCurrentThreadId",0
 db "GetDateFormatA",0
 db "GetDateFormatW",0
 db "GetDaylightFlag",0
 db "GetDefaultCommConfigA",0
 db "GetDefaultCommConfigW",0
 db "GetDevicePowerState",0
 db "GetDiskFreeSpaceA",0
 db "GetDiskFreeSpaceExA",0
 db "GetDiskFreeSpaceExW",0
 db "GetDiskFreeSpaceW",0
 db "GetDriveTypeA",0
 db "GetDriveTypeW",0
 db "GetEnvironmentStrings",0
 db "GetEnvironmentStringsA",0
 db "GetEnvironmentStringsW",0
 db "GetEnvironmentVariableA",0
 db "GetEnvironmentVariableW",0
 db "GetErrorMode",0
 db "GetExitCodeProcess",0
 db "GetExitCodeThread",0
 db "GetFileAttributesA",0
 db "GetFileAttributesExA",0
 db "GetFileAttributesExW",0
 db "GetFileAttributesW",0
 db "GetFileInformationByHandle",0
 db "GetFileSize",0
 db "GetFileTime",0
 db "GetFileType",0
 db "GetFullPathNameA",0
 db "GetFullPathNameW",0
 db "GetHandleContext",0
 db "GetHandleInformation",0
 db "GetLSCallbackTarget",0
 db "GetLSCallbackTemplate",0
 db "GetLargestConsoleWindowSize",0
 db "GetLastError",0
 db "GetLocalTime",0
 db "GetLocaleInfoA",0
 db "GetLocaleInfoW",0
 db "GetLogicalDriveStringsA",0
 db "GetLogicalDriveStringsW",0
 db "GetLogicalDrives",0
 db "GetLongPathNameA",0
 db "GetLongPathNameW",0
 db "GetMailslotInfo",0
 db "GetModuleFileNameA",0
 db "GetModuleFileNameW",0
 db "GetModuleHandleA",0
 db "GetModuleHandleW",0
 db "GetNamedPipeHandleStateA",0
 db "GetNamedPipeHandleStateW",0
 db "GetNamedPipeInfo",0
 db "GetNumberFormatA",0
 db "GetNumberFormatW",0
 db "GetNumberOfConsoleInputEvents",0
 db "GetNumberOfConsoleMouseButtons",0
 db "GetOEMCP",0
 db "GetOverlappedResult",0
 db "GetPriorityClass",0
 db "GetPrivateProfileIntA",0
 db "GetPrivateProfileIntW",0
 db "GetPrivateProfileSectionA",0
 db "GetPrivateProfileSectionNamesA",0
 db "GetPrivateProfileSectionNamesW",0
 db "GetPrivateProfileSectionW",0
 db "GetPrivateProfileStringA",0
 db "GetPrivateProfileStringW",0
 db "GetPrivateProfileStructA",0
 db "GetPrivateProfileStructW",0
 db "GetProcAddress",0
 db "GetProcessAffinityMask",0
 db "GetProcessFlags",0
 db "GetProcessHeap",0
 db "GetProcessHeaps",0
 db "GetProcessPriorityBoost",0
 db "GetProcessShutdownParameters",0
 db "GetProcessTimes",0
 db "GetProcessVersion",0
 db "GetProcessWorkingSetSize",0
 db "GetProductName",0
 db "GetProfileIntA",0
 db "GetProfileIntW",0
 db "GetProfileSectionA",0
 db "GetProfileSectionW",0
 db "GetProfileStringA",0
 db "GetProfileStringW",0
 db "GetQueuedCompletionStatus",0
 db "GetSLCallbackTarget",0
 db "GetSLCallbackTemplate",0
 db "GetShortPathNameA",0
 db "GetShortPathNameW",0
 db "GetStartupInfoA",0
 db "GetStartupInfoW",0
 db "GetStdHandle",0
 db "GetStringTypeA",0
 db "GetStringTypeExA",0
 db "GetStringTypeExW",0
 db "GetStringTypeW",0
 db "GetSystemDefaultLCID",0
 db "GetSystemDefaultLangID",0
 db "GetSystemDirectoryA",0
 db "GetSystemDirectoryW",0
 db "GetSystemInfo",0
 db "GetSystemPowerStatus",0
 db "GetSystemTime",0
 db "GetSystemTimeAdjustment",0
 db "GetSystemTimeAsFileTime",0
 db "GetTapeParameters",0
 db "GetTapePosition",0
 db "GetTapeStatus",0
 db "GetTempFileNameA",0
 db "GetTempFileNameW",0
 db "GetTempPathA",0
 db "GetTempPathW",0
 db "GetThreadContext",0
 db "GetThreadLocale",0
 db "GetThreadPriority",0
 db "GetThreadPriorityBoost",0
 db "GetThreadSelectorEntry",0
 db "GetThreadTimes",0
 db "GetTickCount",0
 db "GetTimeFormatA",0
 db "GetTimeFormatW",0
 db "GetTimeZoneInformation",0
 db "GetUserDefaultLCID",0
 db "GetUserDefaultLangID",0
 db "GetVersion",0
 db "GetVersionExA",0
 db "GetVersionExW",0
 db "GetVolumeInformationA",0
 db "GetVolumeInformationW",0
 db "GetWindowsDirectoryA",0
 db "GetWindowsDirectoryW",0
 db "GetWriteWatch",0
 db "GlobalAddAtomA",0
 db "GlobalAddAtomW",0
 db "GlobalAlloc",0
 db "GlobalCompact",0
 db "GlobalDeleteAtom",0
 db "GlobalFindAtomA",0
 db "GlobalFindAtomW",0
 db "GlobalFix",0
 db "GlobalFlags",0
 db "GlobalFree",0
 db "GlobalGetAtomNameA",0
 db "GlobalGetAtomNameW",0
 db "GlobalHandle",0
 db "GlobalLock",0
 db "GlobalMemoryStatus",0
 db "GlobalReAlloc",0
 db "GlobalSize",0
 db "GlobalUnWire",0
 db "GlobalUnfix",0
 db "GlobalUnlock",0
 db "GlobalWire",0
 db "Heap32First",0
 db "Heap32ListFirst",0
 db "Heap32ListNext",0
 db "Heap32Next",0
 db "HeapAlloc",0
 db "HeapCompact",0
 db "HeapCreate",0
 db "HeapDestroy",0
 db "HeapFree",0
 db "HeapLock",0
 db "HeapReAlloc",0
 db "HeapSetFlags",0
 db "HeapSize",0
 db "HeapUnlock",0
 db "HeapValidate",0
 db "HeapWalk",0
 db "InitAtomTable",0
 db "InitializeCriticalSection",0
 db "InitializeCriticalSectionAndSpinCount",0
 db "InterlockedCompareExchange",0
 db "InterlockedDecrement",0
 db "InterlockedExchange",0
 db "InterlockedExchangeAdd",0
 db "InterlockedIncrement",0
 db "InvalidateNLSCache",0
 db "IsBadCodePtr",0
 db "IsBadHugeReadPtr",0
 db "IsBadHugeWritePtr",0
 db "IsBadReadPtr",0
 db "IsBadStringPtrA",0
 db "IsBadStringPtrW",0
 db "IsBadWritePtr",0
 db "IsDBCSLeadByte",0
 db "IsDBCSLeadByteEx",0
 db "IsDebuggerPresent",0
 db "IsLSCallback",0
 db "IsProcessorFeaturePresent",0
 db "IsSLCallback",0
 db "IsSystemResumeAutomatic",0
 db "IsValidCodePage",0
 db "IsValidLocale",0
 db "K32Thk1632Epilog",0
 db "K32Thk1632Prolog",0
 db "K32_NtCreateFile",0
 db "K32_RtlNtStatusToDosError",0
 db "LCMapStringA",0
 db "LCMapStringW",0
 db "LeaveCriticalSection",0
 db "LoadLibraryA",0
 db "LoadLibraryExA",0
 db "LoadLibraryExW",0
 db "LoadLibraryW",0
 db "LoadModule",0
 db "LoadResource",0
 db "LocalAlloc",0
 db "LocalCompact",0
 db "LocalFileTimeToFileTime",0
 db "LocalFlags",0
 db "LocalFree",0
 db "LocalHandle",0
 db "LocalLock",0
 db "LocalReAlloc",0
 db "LocalShrink",0
 db "LocalSize",0
 db "LocalUnlock",0
 db "LockFile",0
 db "LockFileEx",0
 db "LockResource",0
 db "MakeCriticalSectionGlobal",0
 db "MapHInstLS",0
 db "MapHInstLS_PN",0
 db "MapHInstSL",0
 db "MapHInstSL_PN",0
 db "MapHModuleLS",0
 db "MapHModuleSL",0
 db "MapLS",0
 db "MapSL",0
 db "MapSLFix",0
 db "MapViewOfFile",0
 db "MapViewOfFileEx",0
 db "Module32First",0
 db "Module32Next",0
 db "MoveFileA",0
 db "MoveFileExA",0
 db "MoveFileExW",0
 db "MoveFileW",0
 db "MulDiv",0
 db "MultiByteToWideChar",0
 db "NotifyNLSUserCache",0
 db "OpenEventA",0
 db "OpenEventW",0
 db "OpenFile",0
 db "OpenFileMappingA",0
 db "OpenFileMappingW",0
 db "OpenMutexA",0
 db "OpenMutexW",0
 db "OpenProcess",0
 db "OpenProfileUserMapping",0
 db "OpenSemaphoreA",0
 db "OpenSemaphoreW",0
 db "OpenVxDHandle",0
 db "OpenWaitableTimerA",0
 db "OpenWaitableTimerW",0
 db "OutputDebugStringA",0
 db "OutputDebugStringW",0
 db "PeekConsoleInputA",0
 db "PeekConsoleInputW",0
 db "PeekNamedPipe",0
 db "PostQueuedCompletionStatus",0
 db "PrepareTape",0
 db "Process32First",0
 db "Process32Next",0
 db "PulseEvent",0
 db "PurgeComm",0
 db "QT_Thunk",0
 db "QueryDosDeviceA",0
 db "QueryDosDeviceW",0
 db "QueryNumberOfEventLogRecords",0
 db "QueryOldestEventLogRecord",0
 db "QueryPerformanceCounter",0
 db "QueryPerformanceFrequency",0
 db "QueueUserAPC",0
 db "RaiseException",0
 db "ReadConsoleA",0
 db "ReadConsoleInputA",0
 db "ReadConsoleInputW",0
 db "ReadConsoleOutputA",0
 db "ReadConsoleOutputAttribute",0
 db "ReadConsoleOutputCharacterA",0
 db "ReadConsoleOutputCharacterW",0
 db "ReadConsoleOutputW",0
 db "ReadConsoleW",0
 db "ReadDirectoryChangesW",0
 db "ReadFile",0
 db "ReadFileEx",0
 db "ReadFileScatter",0
 db "ReadProcessMemory",0
 db "RegisterServiceProcess",0
 db "RegisterSysMsgHandler",0
 db "ReinitializeCriticalSection",0
 db "ReleaseMutex",0
 db "ReleaseSemaphore",0
 db "RemoveDirectoryA",0
 db "RemoveDirectoryW",0
 db "RequestDeviceWakeup",0
 db "RequestWakeupLatency",0
 db "ResetEvent",0
 db "ResetNLSUserInfoCache",0
 db "ResetWriteWatch",0
 db "ResumeThread",0
 db "RtlFillMemory",0
 db "RtlMoveMemory",0
 db "RtlUnwind",0
 db "RtlZeroMemory",0
 db "SMapLS",0
 db "SMapLS_IP_EBP_12",0
 db "SMapLS_IP_EBP_16",0
 db "SMapLS_IP_EBP_20",0
 db "SMapLS_IP_EBP_24",0
 db "SMapLS_IP_EBP_28",0
 db "SMapLS_IP_EBP_32",0
 db "SMapLS_IP_EBP_36",0
 db "SMapLS_IP_EBP_40",0
 db "SMapLS_IP_EBP_8",0
 db "SUnMapLS",0
 db "SUnMapLS_IP_EBP_12",0
 db "SUnMapLS_IP_EBP_16",0
 db "SUnMapLS_IP_EBP_20",0
 db "SUnMapLS_IP_EBP_24",0
 db "SUnMapLS_IP_EBP_28",0
 db "SUnMapLS_IP_EBP_32",0
 db "SUnMapLS_IP_EBP_36",0
 db "SUnMapLS_IP_EBP_40",0
 db "SUnMapLS_IP_EBP_8",0
 db "ScrollConsoleScreenBufferA",0
 db "ScrollConsoleScreenBufferW",0
 db "SearchPathA",0
 db "SearchPathW",0
 db "SetCalendarInfoA",0
 db "SetCalendarInfoW",0
 db "SetCommBreak",0
 db "SetCommConfig",0
 db "SetCommMask",0
 db "SetCommState",0
 db "SetCommTimeouts",0
 db "SetComputerNameA",0
 db "SetComputerNameW",0
 db "SetConsoleActiveScreenBuffer",0
 db "SetConsoleCP",0
 db "SetConsoleCtrlHandler",0
 db "SetConsoleCursorInfo",0
 db "SetConsoleCursorPosition",0
 db "SetConsoleMode",0
 db "SetConsoleOutputCP",0
 db "SetConsoleScreenBufferSize",0
 db "SetConsoleTextAttribute",0
 db "SetConsoleTitleA",0
 db "SetConsoleTitleW",0
 db "SetConsoleWindowInfo",0
 db "SetCriticalSectionSpinCount",0
 db "SetCurrentDirectoryA",0
 db "SetCurrentDirectoryW",0
 db "SetDaylightFlag",0
 db "SetDefaultCommConfigA",0
 db "SetDefaultCommConfigW",0
 db "SetEndOfFile",0
 db "SetEnvironmentVariableA",0
 db "SetEnvironmentVariableW",0
 db "SetErrorMode",0
 db "SetEvent",0
 db "SetFileApisToANSI",0
 db "SetFileApisToOEM",0
 db "SetFileAttributesA",0
 db "SetFileAttributesW",0
 db "SetFilePointer",0
 db "SetFileTime",0
 db "SetHandleContext",0
 db "SetHandleCount",0
 db "SetHandleInformation",0
 db "SetLastError",0
 db "SetLocalTime",0
 db "SetLocaleInfoA",0
 db "SetLocaleInfoW",0
 db "SetMailslotInfo",0
 db "SetMessageWaitingIndicator",0
 db "SetNamedPipeHandleState",0
 db "SetPriorityClass",0
 db "SetProcessAffinityMask",0
 db "SetProcessPriorityBoost",0
 db "SetProcessShutdownParameters",0
 db "SetProcessWorkingSetSize",0
 db "SetStdHandle",0
 db "SetSystemPowerState",0
 db "SetSystemTime",0
 db "SetSystemTimeAdjustment",0
 db "SetTapeParameters",0
 db "SetTapePosition",0
 db "SetThreadAffinityMask",0
 db "SetThreadContext",0
 db "SetThreadExecutionState",0
 db "SetThreadIdealProcessor",0
 db "SetThreadLocale",0
 db "SetThreadPriority",0
 db "SetThreadPriorityBoost",0
 db "SetTimeZoneInformation",0
 db "SetUnhandledExceptionFilter",0
 db "SetVolumeLabelA",0
 db "SetVolumeLabelW",0
 db "SetWaitableTimer",0
 db "SetupComm",0
 db "SignalObjectAndWait",0
 db "SignalSysMsgHandlers",0
 db "SizeofResource",0
 db "Sleep",0
 db "SleepEx",0
 db "SuspendThread",0
 db "SwitchToFiber",0
 db "SwitchToThread",0
 db "SystemTimeToFileTime",0
 db "SystemTimeToTzSpecificLocalTime",0
 db "TerminateProcess",0
 db "TerminateThread",0
 db "Thread32First",0
 db "Thread32Next",0
 db "ThunkConnect32",0
 db "TlsAlloc",0
 db "TlsAllocInternal",0
 db "TlsFree",0
 db "TlsFreeInternal",0
 db "TlsGetValue",0
 db "TlsSetValue",0
 db "Toolhelp32ReadProcessMemory",0
 db "TransactNamedPipe",0
 db "TransmitCommChar",0
 db "TryEnterCriticalSection",0
 db "UTRegister",0
 db "UTUnRegister",0
 db "UnMapLS",0
 db "UnMapSLFixArray",0
 db "UnhandledExceptionFilter",0
 db "UninitializeCriticalSection",0
 db "UnlockFile",0
 db "UnlockFileEx",0
 db "UnmapViewOfFile",0
 db "UpdateResourceA",0
 db "UpdateResourceW",0
 db "VerLanguageNameA",0
 db "VerLanguageNameW",0
 db "VirtualAlloc",0
 db "VirtualAllocEx",0
 db "VirtualFree",0
 db "VirtualFreeEx",0
 db "VirtualLock",0
 db "VirtualProtect",0
 db "VirtualProtectEx",0
 db "VirtualQuery",0
 db "VirtualQueryEx",0
 db "VirtualUnlock",0
 db "WaitCommEvent",0
 db "WaitForDebugEvent",0
 db "WaitForMultipleObjects",0
 db "WaitForMultipleObjectsEx",0
 db "WaitForSingleObject",0
 db "WaitForSingleObjectEx",0
 db "WaitNamedPipeA",0
 db "WaitNamedPipeW",0
 db "WideCharToMultiByte",0
 db "WinExec",0
 db "WriteConsoleA",0
 db "WriteConsoleInputA",0
 db "WriteConsoleInputW",0
 db "WriteConsoleOutputA",0
 db "WriteConsoleOutputAttribute",0
 db "WriteConsoleOutputCharacterA",0
 db "WriteConsoleOutputCharacterW",0
 db "WriteConsoleOutputW",0
 db "WriteConsoleW",0
 db "WriteFile",0
 db "WriteFileEx",0
 db "WriteFileGather",0
 db "WritePrivateProfileSectionA",0
 db "WritePrivateProfileSectionW",0
 db "WritePrivateProfileStringA",0
 db "WritePrivateProfileStringW",0
 db "WritePrivateProfileStructA",0
 db "WritePrivateProfileStructW",0
 db "WriteProcessMemory",0
 db "WriteProfileSectionA",0
 db "WriteProfileSectionW",0
 db "WriteProfileStringA",0
 db "WriteProfileStringW",0
 db "WriteTapemark",0
 db "_DebugOut",0
 db "_DebugPrintf",0
 db "_hread",0
 db "_hwrite",0
 db "_lclose",0
 db "_lcreat",0
 db "_llseek",0
 db "_lopen",0
 db "_lread",0
 db "_lwrite",0
 db "dprintf",0
 db "lstrcat",0
 db "lstrcatA",0
 db "lstrcatW",0
 db "lstrcmp",0
 db "lstrcmpA",0
 db "lstrcmpW",0
 db "lstrcmpi",0
 db "lstrcmpiA",0
 db "lstrcmpiW",0
 db "lstrcpy",0
 db "lstrcpyA",0
 db "lstrcpyW",0
 db "lstrcpyn",0
 db "lstrcpynA",0
 db "lstrcpynW",0
 db "lstrlen",0
 db "lstrlenA",0
 db "lstrlenW",0
fin_kernel_api db 0 
 
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
tv_buffer       db 512 dup(?)
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
pitem LVITEM    <?>
tv_item TVITEM  <?>
pcol LVCOLUMN   <?>
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
hPicture        dd ?
nbmemloc        dd ?
hTab			HWND ?
hTab1			HWND ?
hTab2			HWND ?
WhichTabChosen	dd ?

align dword
context         CONTEXT <>
hitpoint        POINT <>
lpRect          RECT <>
lpRect_tv       RECT <>
;--------------------------------------------------------------
tvinsert                        TV_INSERTSTRUCT <>
align dword
hImageList                      dd ?
hwndTreeView                    dd ?
hDragImageList                  dd ?
resource_rva                    dd ?
resource_rva_map                dd ?
nb_IRDE                         dd ?
nb_IRDE_total                   dd ?
IRD                             dd ?
IRD_                            dd ?
nb_                             dd ?
nb__                            dd ?
nb_total                        dd ?
size_IRDE                       dd ?
size_IRE                        dd ?
resource_data_size              dd ?
to_round                        dd ?
total_rsrc_size                 dd ?
IRD_total_size                  dd ?
hMemory_rs                      HANDLE ?
pMemory_rs                      DWORD ?
index1_s                        dd ?
index2_s                        dd ?
index3_s                        dd ?
index4_s                        dd ?
index5_s                        dd ?
index1_d                        dd ?
index2_d                        dd ?
index3_d                        dd ?
index4_d                        dd ?
index5_d                        dd ?
SizeReadWrite                   DWORD ?
resource_offset                 dd ?
unicode_index                   dd ?
hParent                         dd ?
hParent_                        dd ?
;--------------------------------------------------------------------
h_feedDisa                      dd ?
handle_DisInstr                 dd ?
Address                         dd ?
OpcodeBuff                      db 2048 dup (?)
OpcodeLength                    dd ?
nb_ligne                        dd ?
count_decrypt					dd ?
count_crypt						dd ?	

