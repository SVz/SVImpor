@echo off
\masm32\bin\ml /c /coff /Cp %1.asm
\masm32\bin\link /DLL /DEF:%1.def /SUBSYSTEM:WINDOWS /LIBPATH:\masm32\lib %1.obj
del %1.exp
del %1.obj
del %1.lib
dir %1.dll