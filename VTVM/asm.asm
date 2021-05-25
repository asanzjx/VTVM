; masm assembly
; 

EXTERN MainVMExitHandler:PROC
EXTERN VM_Resumer:PROC

PUBLIC	EnableVMXOperation
PUBLIC	SaveHostState

EXTERN	HostRsp:QWORD
EXTERN	HostRbp:QWORD


PUBLIC	Get_GDT_Base
PUBLIC	GetCs
PUBLIC	GetDs
PUBLIC	GetEs
PUBLIC	GetFs
PUBLIC	GetSs
PUBLIC	GetGs
PUBLIC	GetLdtr

PUBLIC	GetTr
PUBLIC	Get_IDT_Base
PUBLIC	Get_GDT_Limit
PUBLIC	Get_IDT_Limit
PUBLIC	Get_RFLAGS

PUBLIC	VMExitHandler
PUBLIC	AsmVmcall
PUBLIC	GuestRun

.CODE

GuestRun PROC	PUBLIC	
	hlt
	hlt
	mov eax, 40000001h
	cpuid
	mov rcx, 1
	vmcall
	mov ecx, 0c0000082h
	rdmsr
	mov ecx, 0c0000080h
	rdmsr
	wrmsr	
	;mov dx, 5658h
	;in eax, dx
	int 3
	ret ; now return DriverEntry
GuestRun ENDP	
AsmVmcall PROC
    pushfq
    vmcall ; VmxVmcallHandler(UINT64 VmcallNumber, UINT64 OptionalParam1, UINT64 OptionalParam2, UINT64 OptionalParam3)
    popfq
    ret

AsmVmcall ENDP
SaveHostState PROC PUBLIC
	MOV HostRsp,rsp

	ret
SaveHostState ENDP 

EnableVMXOperation PROC	PUBLIC	
	push	rax	;save env
	xor	rax,rax
	mov	rax,cr4
	or	rax,02000h
	mov	cr4,rax
	pop rax
	ret
EnableVMXOperation ENDP	

Get_GDT_Base PROC PUBLIC
	local	gdtr[10]:byte
	sgdt	gdtr	
	mov	rax,qword ptr gdtr[2]
	ret
Get_GDT_Base ENDP

GetCs	PROC	
	mov rax,cs
	ret
GetCs	ENDP

GetDs PROC
	mov		rax, ds
	ret
GetDs ENDP

GetEs PROC
	mov		rax, es
	ret
GetEs ENDP

GetFs PROC
	mov		rax, fs
	ret
GetFs ENDP

GetSs PROC
	mov		rax, ss
	ret
GetSs ENDP

GetGs PROC
	mov		rax, gs
	ret
GetGs ENDP

GetLdtr PROC
	sldt	rax
	ret
GetLdtr ENDP

GetTr PROC
	str	rax
	ret
GetTr ENDP

Get_IDT_Base PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
Get_IDT_Base ENDP

Get_GDT_Limit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
Get_GDT_Limit ENDP

Get_IDT_Limit PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
Get_IDT_Limit ENDP

Get_RFLAGS PROC
	pushfq
	pop		rax
	ret
Get_RFLAGS ENDP

MSRRead PROC
	rdmsr				; MSR[ecx] --> edx:eax
	shl		rdx, 32
	or		rax, rdx
	ret
MSRRead ENDP

MSRWrite PROC
	mov		rax, rdx
	shr		rdx, 32
	wrmsr
	ret
MSRWrite ENDP

;------------------------------------------------------------------------

VMExitHandler PROC
	; push 0	; unaligned stack state
	pushfq
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax	


	mov rcx, rsp		;GuestRegs as the MainVMExitHandler param
	sub	rsp, 28h

	call	MainVMExitHandler
	add	rsp, 28h	

	; Check whether we have to turn off VMX or Not (the result is in RAX)
	CMP	al, 0
	JE		VMXOFFHandler
	
	pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
	popfq

	; sub rsp, 0100h ; to avoid error in future functions
	JMP VM_Resumer
	

VMExitHandler ENDP

VMXOFFHandler PROC

	; Turn VMXOFF
	VMXOFF

	INT		3

	;Restore the state
	pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
	popfq

	ret

	; Set guest RIP and RSP
	; MOV		RSP, gGuestRSP
	; JMP		gGuestRIP
VMXOFFHandler ENDP

;------------------------------------------------------------------------
; Error codes :

    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2

;------------------------------------------------------------------------

AsmInvept PROC PUBLIC

    invept  rcx, oword ptr [rdx]
    jz @jz
    jc @jc
    xor     rax, rax
    ret

    @jz: 
    mov     rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
    ret

    @jc:
    mov     rax, VMX_ERROR_CODE_FAILED
    ret

AsmInvept ENDP

AsmInvvpid PROC
        invvpid rcx, oword ptr [rdx]
        jz      @jz
        jc      @jc
        xor     rax, rax
        ret

@jz:    mov     rax, VMX_ERROR_CODE_FAILED_WITH_STATUS
        ret

@jc:    mov     rax, VMX_ERROR_CODE_FAILED
        ret
AsmInvvpid ENDP

PUBLIC Getx64NtoskrnlBase
Getx64NtoskrnlBase PROC
  push rbx
  mov rax, gs:[038h]
  mov rax, [rax+04h]
  shr rax,0Ch
  shl rax,0Ch
_find_nt_walk_page:
  mov rbx, [rax]
  cmp bx,05A4Dh
  je _found
  sub rax,1000h
  jmp _find_nt_walk_page
_found:
  pop rbx
  ret
Getx64NtoskrnlBase ENDP

PUBLIC Getx64NtoskrnlSize
Getx64NtoskrnlSize PROC
	xor rax, rax
	mov rax, rcx
	mov eax, dword ptr [rax+138h]
	ret
Getx64NtoskrnlSize ENDP

END
