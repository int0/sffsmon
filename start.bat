copy sffsmon.sys c:\
sc create sffsmon binpath= c:\sffsmon.sys type= kernel
net start sffsmon
sc delete sffsmon
del c:\sffsmon.sys
pause