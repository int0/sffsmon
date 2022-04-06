.data
hook_pattern	db 00Fh, 0B7h, 045h, 0D8h, 050h, 0FFh, 075h, 0E8h
cr_temp			dd 0
hooks			dd 32 dup (0)
.code
DisableWriteProtection proc
	

	.if cr_temp == 0
	;<<<<<<<<| Clear Write Protection Flag |<<<<<<<<<<<<<<<<<
		push eax
		
		cli
		mov eax,cr0
		mov cr_temp,eax ; Save flags
		and eax, 0FFFEFFFFh
		mov cr0,eax
		
		pop eax
	;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	.endif	
	ret

DisableWriteProtection endp
RestoreWriteProtection proc
	
	.if cr_temp != 0	
	;<<<<<<<<<| Restore Write Protection |<<<<<<<<<<<<<<<<<<<
		push eax
		
		mov eax,cr_temp
		mov cr0,eax
		sti
		
		xor eax,eax
		mov cr_temp,eax		
		pop eax
	;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
	.endif
	ret

RestoreWriteProtection endp
sffsout proc
.data?
buff	db 4096 dup (?)
ret_	dd ?
.code 
	movzx   eax,word ptr [ebp-28h]
	
	pushad
	pushfd
	
	mov edi,eax ; 
	
	invoke RtlZeroMemory,addr buff,sizeof buff
	
	add edi,edi	
	
	mov eax, dword ptr [ebp-18h]
	invoke memcpy,addr buff, eax, edi
	
	invoke DbgPrint,$CTA0("sffs: %ws\n"),addr buff
	
	popfd
	popad
	    
	push [esp]
	pop ret_
	
	mov [esp],eax
	
	jmp ret_	

sffsout endp

sffsfiles_log proc
; BBFA - v2.25
; BBDE - v2.27
pushad

	invoke strstr,edi,$CTA0("pf2a")
	.if eax == edi
		assume esi:ptr SYSTEM_MODULE_INFORMATION
		
		mov eax,[esi].Base
		lea ecx,[eax+0BBDEh]
		invoke RtlCompareMemory,ecx,addr hook_pattern, 8
		.if eax == 8
			
			mov eax,[esi].Base
			add eax,0BBDEh
			lea ebx,sffsout
			sub ebx,eax
			sub ebx,5
			
			lea ecx,hooks
			.while dword ptr [ecx] != 0				
				add ecx,4
			.endw
			mov [ecx],eax
			
			invoke DisableWriteProtection
			
			mov byte ptr [eax],0E8h
			mov [eax+1],ebx
			
			invoke RestoreWriteProtection
			
			lea eax,[esi].ImageName
			invoke DbgPrint,$CTA0("sffs: %s hooked.\n"),eax
			
			popad
			xor eax,eax
			inc eax
			ret		
		.endif		
		
		mov eax,[esi].Base
		lea ecx,[eax+0BBFAh]
		invoke RtlCompareMemory,ecx,addr hook_pattern, 8
		.if eax == 8
			
			mov eax,[esi].Base
			add eax,0BBFAh
			lea ebx,sffsout
			sub ebx,eax
			sub ebx,5
			
			lea ecx,hooks
			.while dword ptr [ecx] != 0				
				add ecx,4
			.endw
			mov dword ptr [ecx],eax
			
			invoke DisableWriteProtection
			
			mov byte ptr [eax],0E8h
			mov [eax+1],ebx
			
			invoke RestoreWriteProtection
			
			lea eax,[esi].ImageName
			invoke DbgPrint,$CTA0("sffs: %s hooked.\n"),eax	
			
			popad
			xor eax,eax
			inc eax
			ret		
		.endif
		
		lea eax,[esi].ImageName
		invoke DbgPrint,$CTA0("sffs: Unknown driver version found. %s \n"),eax
		
	.endif
	
	invoke strcmp,edi,$CTA0("sfvfs02.sys")
	.if eax == 0
		
		mov eax,[esi].Base
		lea ecx,[eax+0BBFAh]
		invoke RtlCompareMemory,ecx,addr hook_pattern, 8
		.if eax == 8
			
			mov eax,[esi].Base
			add eax,0BBFAh
			lea ebx,sffsout
			sub ebx,eax
			sub ebx,5
			
			lea ecx,hooks
			.while dword ptr [ecx] != 0				
				add ecx,4
			.endw
			mov dword ptr[ecx],eax
			
			invoke DisableWriteProtection
			
			mov byte ptr [eax],0E8h
			mov [eax+1],ebx
			
			invoke RestoreWriteProtection
			
			lea eax,[esi].ImageName
			invoke DbgPrint,$CTA0("sffs: %s hooked.\n"),eax	
			
			popad
			xor eax,eax
			inc eax
			ret		
		.endif
		
		mov eax,[esi].Base
		lea ecx,[eax+0BBDEh]
		invoke RtlCompareMemory,ecx,addr hook_pattern, 8
		.if eax == 8
			
			mov eax,[esi].Base
			add eax,0BBDEh
			lea ebx,sffsout
			sub ebx,eax
			sub ebx,5
			
			lea ecx,hooks
			.while dword ptr [ecx] != 0				
				add ecx,4
			.endw
			mov [ecx],eax
			
			invoke DisableWriteProtection
			
			mov byte ptr [eax],0E8h
			mov [eax+1],ebx
			
			invoke RestoreWriteProtection
			
			lea eax,[esi].ImageName
			invoke DbgPrint,$CTA0("sffs: %s hooked.\n"),eax
			
			popad
			xor eax,eax
			inc eax
			ret		
		.endif		
		
		lea eax,[esi].ImageName
		invoke DbgPrint,$CTA0("sffs: Unknown driver version found. %s \n"),eax
		
	.endif
	
	popad
	xor eax,eax
	ret
sffsfiles_log endp


appkeyout proc
;v2.27	
;.text:00012664                 mov     [eax+10h], edi
;.text:00012667                 mov     ecx, [esi]
;.text:00012669                 mov     [eax+8], ecx
;.text:0001266C                 mov     ecx, [esi+4]
;.text:0001266F                 mov     [eax+0Ch], ecx
;.text:00012672                 push    offset dword_15384
;.text:00012677                 mov     edx, eax
;.text:00012679                 mov     ecx, offset P
;.text:0001267E                 call    sub_110D4
;.text:00012683                 xor     eax, eax

;v2.21 
;.text:00012B6C                 mov     [eax+10h], edi
;.text:00012B6F                 mov     ecx, [esi]
;.text:00012B71                 mov     [eax+8], ecx
;.text:00012B74                 mov     ecx, [esi+4]
;.text:00012B77                 mov     [eax+0Ch], ecx
;.text:00012B7A                 push    offset Lock     ; Lock
;.text:00012B7F                 mov     edx, eax        ; ListEntry
;.text:00012B81                 mov     ecx, offset ListHead ; ListHead
;.text:00012B86                 call    ds:ExfInterlockedInsertTailList
;.text:00012B8C                 xor     eax, eax


	pushad
	pushfd
	
	
	mov eax, dword ptr [ esi ]
	mov ecx, dword ptr [ esi + 4 ]
	
	bswap eax
	bswap ecx

	invoke DbgPrint,$CTA0("appkey: %.08X %.08X\n"),eax,ecx
	
	popfd
	popad
	
	mov     dword ptr [ eax + 10h ], edi
    mov     ecx, dword ptr [ esi ]
	
	ret

appkeyout endp



TryToSetAppKeyHook proc HookAddr:DWORD
.data

appkey_hookpattern db 89h, 78h, 10h, 8Bh, 0Eh

.code	
	
		; v2.27
		
		mov eax,[esi].Base
		mov ecx,HookAddr
		lea ecx,[eax+ecx]
		invoke RtlCompareMemory,ecx,addr appkey_hookpattern, 5
		.if eax == 5
			
			mov eax,[esi].Base
			add eax,HookAddr
			lea ebx,appkeyout
			sub ebx,eax
			sub ebx,5
			
			lea ecx,hooks
			.while dword ptr [ecx] != 0				
				add ecx,4
			.endw
			mov dword ptr[ecx],eax
			
			invoke DisableWriteProtection
			
			mov byte ptr [eax],0E8h
			mov [eax+1],ebx
			
			invoke RestoreWriteProtection
			
			lea eax,[esi].ImageName
			invoke DbgPrint,$CTA0("appkey: %s hooked.\n"),eax	
			
			xor eax,eax
			inc eax
			ret		
		.endif
		
		xor eax,eax	
	
	ret

TryToSetAppKeyHook endp


appkey_log proc HookAddr:DWORD
LOCAL r :DWORD
	
	mov r,0
	
	pushfd
	pushad
	
	invoke strcmp,edi,$CTA0("sfvfs02.sys")
	.if eax == 0
		invoke TryToSetAppKeyHook, HookAddr
		mov r, eax
		jmp exit		
	.endif
	
	invoke strstr,edi,$CTA0("pf2a")
	.if eax == edi
		invoke TryToSetAppKeyHook, HookAddr
		mov r, eax
		jmp exit	
	.endif
	
	mov r,-1
	
exit:
	popad
	popfd
	mov eax, r
	ret

appkey_log endp


SetAppKeyHook proc
	
	invoke appkey_log, 2664h
	.if( eax == 0 )
		invoke appkey_log, 2B6Ch
		.if( eax == 0 )
			invoke appkey_log, 2662h
			.if( eax == 0 )
				invoke appkey_log, 252Ah				
			.endif			
		.endif
	.endif
	
	.if( eax == 0 )
		lea eax,[esi].ImageName
		invoke DbgPrint,$CTA0("appkey: Unknown driver version found. %s \n"),eax	
	.endif
	
	ret

SetAppKeyHook endp
