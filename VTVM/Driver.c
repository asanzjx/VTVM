/*
file_name: Driver.c
Function:
	1. 
*/


#include "common.h"
#include "vm.h"
#include "EPT.h"
#include "dbg.h"
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define IOCTL1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)

//need to self define
typedef struct _DEVICE_EXTENSION {
	UNICODE_STRING SymLinkName;
} DEVICE_EXTENSION, * PDEVICE_EXTENSION;



int IsOpenVM = 0;
int IsExitVM;

UINT64 VA2PA(void* va) {
	//build-in support for 64-bit 
	return MmGetPhysicalAddress(va).QuadPart;
}

UINT64 PA2VA(UINT64 pa) {
	PHYSICAL_ADDRESS PhysicalAddr;
	PhysicalAddr.QuadPart = pa;
	return MmGetVirtualForPhysical(PhysicalAddr);
}

//close page protect
/*
void PageProtectClose()
{
	__asm {
		cli
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
	}
}

// open page protect
void PageProtectOpen()
{
	__asm {
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		sti
	}
}
*/

//bypass Driver check Sign
//在使用 ObCallBackxx 函数和 PsxxEx 函数的时候，在这些函数的内部实现中都会去调用 MmVerifyCallbackFunction() 来进行校验

/* DriverSection _LDR_DATA_TABLE_ENTRY
nt!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0xfffff800`04048890 - 0xfffffa80`03893af0 ]
   +0x010 InMemoryOrderLinks : _LIST_ENTRY [ 0xfffff880`03763000 - 0x00000000`0000009c ]
   +0x020 InInitializationOrderLinks : _LIST_ENTRY [ 0x00000000`00020000 - 0x00000000`00000000 ]
   +0x030 DllBase          : 0xfffff880`0375f000 Void
   +0x038 EntryPoint       : 0xfffff880`037601a0 Void
   +0x040 SizeOfImage      : 0x7000
   +0x048 FullDllName      : _UNICODE_STRING "\??\C:\kmdf\KmdfDemo.sys"
   +0x058 BaseDllName      : _UNICODE_STRING "KmdfDemo.sys"
   +0x068 Flags            : 0x49104000
   ...
* nt!MmVerifyCallbackFunction:
*	test byte ptr[rax + 68h], 20h	
*	...
*/



NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObj) {
	DbgPrint("[+]DriverUnload\r\n");
	PDEVICE_OBJECT pDevObj = pDriverObj->DeviceObject;
	NTSTATUS status = TRUE;

	//get device extension
	PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

	//DelProtect();

	//1.2 exit vm
	ExitVM();

	//del symbolic link
	UNICODE_STRING pLinkName = pDevExt->SymLinkName;
	IoDeleteSymbolicLink(&pLinkName);

	//del device
	IoDeleteDevice(pDevObj);

	return status;
}

NTSTATUS DefDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("[+]Enter DefDispatchRoutine\r\n");
	NTSTATUS status = STATUS_SUCCESS;
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS IoctlDispatchRoutine(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("[+]Enter IoctlDispatchRoutine\r\n");
	NTSTATUS status = STATUS_SUCCESS;

	// find I/O stack, just the IO_STACK_LOCATION ptr
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG in_size = stack->Parameters.DeviceIoControl.InputBufferLength;//input buf size
	ULONG out_size = stack->Parameters.DeviceIoControl.OutputBufferLength;//output buf size
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;//control code

	PVOID buffer = pIrp->AssociatedIrp.SystemBuffer;//buf ptr

	switch (code)
	{						// process request
	case IOCTL1:
		DbgPrint("[+]Get ioctl code 1, buf in_size:%d, out_size:%d:\r\n", in_size, out_size);
		DbgPrint(buffer);
		RtlFillMemory(buffer, out_size, 0xC0);
		
		break;
	default:
		DbgPrint("[-]Invalid variant");
		status = STATUS_INVALID_VARIANT;
		break;
	}

	// 完成IRP
	pIrp->IoStatus.Status = status;//设置IRP完成状态，会设置用户模式下的GetLastError
	pIrp->IoStatus.Information = out_size;//设置操作的字节
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);//完成IRP，不增加优先级
	return status;
}


int LoadVM() {
	//1. check is support vmx
	if (!IsSupportVM()) {
		DbgPrint("[-]VMX is not supported");
		return 0;
	}
	DbgPrint("\n[+]VMX is supported");

	CpuNums = KeQueryActiveProcessorCount(0);
	DbgPrint("\n[+]CpuNum:%d", CpuNums);
	if (CpuNums <= 0)	return 0;

	// Alloc vm global data
	g_VM_DATA_ptr = (PVM_GLOBAL_DATA)ExAllocatePoolWithTag(NonPagedPool, sizeof(VM_GLOBAL_DATA) * CpuNums, POOLTAG);
	if (!g_VM_DATA_ptr) {
		DbgPrint("[-]Alloc global vm data faild\n");
		return 0;
	}
	RtlZeroMemory(g_VM_DATA_ptr, sizeof(VM_GLOBAL_DATA) * CpuNums);

	//2. init ept
	//2.1 check ept feature
	if (!EptCheckFeatures()) {
		DbgPrint("[-]Not Support essenial EPT features\n");
		return FALSE;
	}
	//2.2 alloc global EPT state
	g_EPT_State_ptr = (PEPT_STATE)ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_STATE), POOLTAG);
	if (!g_EPT_State_ptr) {
		DbgPrint("[-]Alloc global ept state data faild\n");
		return 0;
	}
	RtlZeroMemory(g_EPT_State_ptr, sizeof(EPT_STATE));
	//2.3 build Bitmap
	if (!EptBuildBitmap()) {
		DbgPrint("\n[-]EPT build bitmap faild\n");
	}
	else {
		DbgPrint("\n[+]EPT build bitmap suscess\n");
	}

	//2.3 init pool manager
	
	if (!PoolManagerInitialize()){
		DbgPrint("Could not initialize pool manager");
		return FALSE;
	}
	

	//2.5 init EPT
	if (!EptInit()) {
		DbgPrint("[-]EPT init faild\n");
		return 0;
	}
	DbgPrint("\n[+]EPT inited\n");
	// 2.6 init ept page hook list
	PLIST_ENTRY ListHead = &(g_EPT_State_ptr->HookedPagesList);
	InitializeListHead(ListHead);
	//be careful multi cpu nums,here just do simple work for multi cps nums 
	int i = 0;
	for (i; i < CpuNums; i++) {
		//3. Enable VMX operation
		EnableVMXOperation();
		DbgPrint("\n[+]Enable VM");

		//4. Alloc vmxon and vmxcs data
		if(!AllocateVMXONRegion(&g_VM_DATA_ptr[i]))	goto ErrorReturn;
		if(!AllocateVMCSRegion(&g_VM_DATA_ptr[i]))	goto ErrorReturn;
		
		DbgPrint("[*]CPU:%d VMCS Region is allocated at  ===> %llx", i, g_VM_DATA_ptr[i].VMCS_REGION);
		DbgPrint("[*]CPU:%d VMXON Region is allocated at ===> %llx", i, g_VM_DATA_ptr[i].VMXON_REGION);

		//5. Allocate vm stack
		//These stacks will be used whenever a VM - Exit occurs.
		g_VM_DATA_ptr[i].VMStackVA = ExAllocatePoolWithTag(NonPagedPool, VMSTACK_SIZE, POOLTAG);
		if (g_VM_DATA_ptr[i].VMStackVA == NULL) {
			DbgPrint("[-]Error in allocating VM Stack\n");
			return 0;
		}
		RtlZeroMemory(g_VM_DATA_ptr[i].VMStackVA, VMSTACK_SIZE);

		//6. Allocate MSRBitMap
		g_VM_DATA_ptr[i].MSRBitMapVA = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
		if (g_VM_DATA_ptr[i].MSRBitMapVA == NULL) {
			DbgPrint("[-]Error in allocating VM Stack\n");
			return 0;
		}
		RtlZeroMemory(g_VM_DATA_ptr[i].MSRBitMapVA, PAGE_SIZE);
		g_VM_DATA_ptr[i].MSRBitMapPA = VA2PA(g_VM_DATA_ptr[i].MSRBitMapVA);

		//7. setup vmcs
		if (!ClearVMCSRegion(&g_VM_DATA_ptr[i])) goto ErrorReturn;
		if (!LoadVMCSPtr(&g_VM_DATA_ptr[i])) goto ErrorReturn;

		SetupVMCS(&g_VM_DATA_ptr[i]);

		//8. launch vm
		// KIRQL OldIrql = KeRaiseIrqlToDpcLevel();
		__vmx_vmwrite(GUEST_RSP, (ULONG64)HostRsp);     //setup guest rsp
		__vmx_vmwrite(GUEST_RIP, (ULONG64)GuestRun);     //setup guest rip
		//DbgBreakPoint();
		g_VM_DATA_ptr[i].HasLaunched = TRUE;
		DbgPrint("[+]vmx launch\n");
		g_VM_DATA_ptr[i].IsOnVmRootMode = FALSE;
		__vmx_vmlaunch();	// now enter guest

		// KeLowerIrql(OldIrql);

		//if all is sucessed, will never be here
		ULONG64 ErrorCode = 0;
		__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
		__vmx_off();
		g_VM_DATA_ptr[i].HasLaunched = FALSE;
		//g_VM_DATA_ptr[i].IsOnVmRootMode = FALSE;
		DbgPrint("\n[-] VMLAUNCH Error : 0x%llx\n", ErrorCode);
		DbgBreakPoint();
	}
ErrorReturn:
	DbgPrint("\n[-] Fail to setup VMCS !\n");
	return FALSE;
}

int ExitVM() {
	int i = 0;
	
	if (CpuNums <= 0 || !g_VM_DATA_ptr)	return 0;
	for (i; i < CpuNums; i++) {
		if (g_VM_DATA_ptr[i].HasLaunched) {
			DbgBreakPoint();
			__vmx_off();
			
		};
		if (g_VM_DATA_ptr[i].VMXON_VA != NULL) {
			MmFreeContiguousMemory(g_VM_DATA_ptr[i].VMXON_VA);
		}

		if (g_VM_DATA_ptr[i].VMCS_VA != NULL) {
			MmFreeContiguousMemory(g_VM_DATA_ptr[i].VMCS_VA);
		}

		//free vmstack va
		if (g_VM_DATA_ptr[i].VMStackVA != NULL) {
			ExFreePoolWithTag(g_VM_DATA_ptr[i].VMStackVA, POOLTAG);
		}

		if (g_VM_DATA_ptr[i].MSRBitMapVA != NULL) {
			ExFreePoolWithTag(g_VM_DATA_ptr[i].MSRBitMapVA, POOLTAG);
		}
		
	}

	PoolManagerUninitialize();

	// free ept page table
	if (g_EPT_State_ptr->EptPageTable != NULL) {
		MmFreeContiguousMemory(g_EPT_State_ptr->EptPageTable);
	}

	// free ept state 
	if (g_EPT_State_ptr != NULL) {
		ExFreePoolWithTag(g_EPT_State_ptr, POOLTAG);
	}

	//free global vm ptr
	if (g_VM_DATA_ptr != NULL) {
		ExFreePoolWithTag(g_VM_DATA_ptr, POOLTAG);
	}

	
	
	return 1;
}

NTSTATUS DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	DbgPrint("\n[+] DrvCreate Called !\n");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj = NULL;
	PDEVICE_EXTENSION pDevExt;
	UNICODE_STRING ustrLinkName;

	RtlInitUnicodeString(&ustrDevName, L"\\Device\\AnTiProtect");
	DbgPrint("[+]DriverEntry\r\n");

	//1. reg DriverUnload() and Dispatch function
	pDriverObj->DriverUnload = DriverUnload;
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DefDispatchRoutine;
	pDriverObj->MajorFunction[IRP_MJ_WRITE] = DefDispatchRoutine;
	pDriverObj->MajorFunction[IRP_MJ_READ] = DefDispatchRoutine;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatchRoutine;

	//2. Create device
	status = IoCreateDevice(pDriverObj, sizeof(DEVICE_EXTENSION), &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))	return status;

	RtlInitUnicodeString(&ustrLinkName, L"\\??\\AnTiProtectLink");
	//3. create link name
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-]Create Symbolic link field");
		IoDeleteDevice(pDevObj);
		return status;
	}

	// 4.for user program
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->SymLinkName = ustrLinkName;

	// vm start
	HostCr3 = __readcr3();
	SaveHostState();
	DbgPrint("\n[+]Saved host state, Current id:0x%x", PsGetCurrentProcessId());
	if (!LoadVM()) {
		DbgPrint("\n[-]Load VM faild\n");
		goto Ret;
	}

GuestRet:
	DbgPrint("\n=====================================================\n");
	DbgPrint("[+]Load VM End");
	// for guest rip test
	GuestRun();
	SyscalHook();

Ret:
	return STATUS_SUCCESS;
}



