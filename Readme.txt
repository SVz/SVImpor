Import Rebuilder V (see history) (always beta :)

Import table manipulations are used in most protectors.
Proggy only needs thunks to work, also sometimes, when dumping,
Import table and API names are destroyed.

This tool is used to rebuild a valid import table
which can be insert in section already present
or (by default) in a new appended section.

All you need, is to know thunk's array RVA offset.

How it works:
At top of dialog, you can enter a thunk's entry offset.
Click 'View' to view what it contains in Address box.
Click 'Search' to find what API it refers.
Click 'Next' is like adding 4 and clicking 'View' & 'Search'.

You can modify thunk entry: enter a thunk entry offset and
new value in Address box, then click 'Modify' (be careful :)

You can have a list of loaded modules when you Click 'Modules' button.
Center in the dialog, you have relocation box.
When you rebuild import table, as i said, default is new section
offset but if you want you can modify it (to copy the new table in
existing section).
Start is the array thunk start, End is the end !!!! (excluded).

At bottom, Build and Save import table.
When you click 'Build', you must see APi list generated.
If a thunk value can't be found, it will be added in thunk error list.

SafeCast Button is use to fix code section.
API are differents with same thunk ! depend of call offset.
When fixed, Dialog must be show to save new fixed code section.

Last is plugin. Sometime thunk array are not filled with
real api offset (bffxxxx) but with indirect call or others tricks.
With plugin, you can process theses entries.
Select plugin and check.

For example, Risc SafeDisk dumper:

    PUSH 8DF82ADC                           
    XOR  DWORD PTR [ESP],3200CA11
    RET

Plugin function is executed before searching api.

process_add proc
    pushad
    mov ebx,dword ptr [eax+1]       ;RISK import tricks !!!
    mov eax,dword ptr [eax+8]       ;68DC2AF88D     PUSH 8DF82ADC                           
    xor eax,ebx                     ;81342411CA0032 XOR  DWORD PTR [ESP],3200CA11           
    mov add_,eax    
    popad
    mov eax,add_
    ret
process_add Endp

This plugin must be a dll with one exported function (name:process_add).
when called, process_add, eax is thunk value.
See existing plugin for example.

Voila .. It's not so powerful as revirgin :( but i hope ,in the future,
to code a plugin with can use Owl tracer.
He said to me that he was working on revamping Icedump as a vxd and
implementing some APIs !!

Please send me yours comments and plugins ;)
Attention, IT'S BETA and can crash anytime :))

Limitation:
Plugin dir must be in dll_loader directory.

Include 3 examples.

Dza crackme (try to unpack ;)
Thunks Offsets are: start:4030a0 end:403100 plugin: Telock71.

Safedisc_v2_05_30_Dumper.EXE
start:4050bc end:405124 plugin: Risk.

Cruncher2 (is it a protector ?) not include.
start:62130c end:621eb0 no plugin !!!

ASprotect V1.2 not include.
start:466118 end:4666dc plugin: ASprotect.

Pex V0.99
start:405000 end:4050c8 plugin: Pex.

Thxs to:
Sandman (RCE Teacher), Iczelion (ASM teacher,dll idea), Yoda (ForceLibrary),Elicz
Owl (how nice is Icedump), R!sc (Safedisc MASTER), Tsehp (Revirgin), Hz (beta test),
Kayaker (beta test), Analyst (friend) & all RCE members !!

History:
V1.0    First release
V1.1    Fill plugin lame bug corrected.
V1.2    Ordinal base bug fixed
        ASprotect V1 plugin
V1.2.1  Error msg on bad thunk
        SEH handler on rebuild (still buggy!)
V1.3    Error list created
V1.3.1  Plugin dir in registry
        Module list at start
V1.3.2  Fixed dll low_value bug (still crappy!)
        Add Pex v0.99 plugin
V1.3.3  Freelibrary added
        Click on plugin, check on
        Pecrypt102 plugin added
        Telock71 renamed (was not pecrypt)
V1.4.1  Dll low_value removed
        Dll detect code changed
        SEH handler seems to be fixed ;)
V1.5.1  Modify added
V1.6.1  SafeCast beta support
V1.7.1  SafeDisc2 support (Yeah!!!!)
        Progress Bar added
        Exit only free and exit dll
        On-the-fly loader added
V1.7.4  ASPROTECT Preapi added in right mouse button on windows
		ASPROTECT Preapi plugin
        Click on list api refresh addresse
		Armadillo_beta plugin added
V1.7.5	Plugin dir fixed
V2.0.0	Resource Rebuilder added
		Disasm Listview added
V2.0.2	First ordinal api bug fixed
		list API on Dialog added
		Disasm call ordinal done
V2.0.3  PE base added to allow DLL IT rebuilding
V2.0.3.1ASProtect 1.3 Plugin
		GetProc & HandleA added in right click
V2.1	Table Jump check added
V2.1.1	First Section info at startup in TableJumpCheck
V2.1.2	jmp,call,push,mov added in TableJumpCheck
V2.1.3	TableJumpCheck bug fixed
V2.2.0	Little dumper added
V2.3.0	Code Fixer added now it's SV tools !!!
V2.3.1	In Pelock fixer Code start & size can be changed
V2.3.2	Round bug fix
V2.3.3	Add resource export
V2.4.0	Add Normalize Ntdll.dll api
		add mov eax,XXXXXXXX in TableJumpCheck (A1XXXXXXXX)
V2.4.1	Add auto name idata save filename
V2.4.2	Fixed ListBox LBS_Notify Ex style	