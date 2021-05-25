#include "vm.h"
#include "hooks.h"
#include "EptPageHook.h"
void InjectInterruption(INTERRUPT_TYPE InterruptionType, EXCEPTION_VECTORS Vector, BOOLEAN DeliverErrorCode, ULONG32 ErrorCode) {
	INTERRUPT_INFO interrupt_info = { 0 };
	interrupt_info.Valid = TRUE;
	interrupt_info.InterruptType = InterruptionType;
	interrupt_info.Vector = Vector;
	interrupt_info.DeliverCode = DeliverErrorCode;
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, interrupt_info.Flags);

	if (DeliverErrorCode) {
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
	}
}

void InjectBreakpoint() {
	InjectInterruption(INTERRUPT_TYPE_SOFTWARE_EXCEPTION, EXCEPTION_VECTOR_BREAKPOINT, FALSE, 0);
	UINT32 ExitInstrLength;
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstrLength);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ExitInstrLength);
}

// set the monitor trap flag, if set, after vmresume either instrunction vm-exit
void SetMonitorTrapFlag(BOOLEAN set) {
	ULONG CpuBasedVMExecControls = 0;
	
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &CpuBasedVMExecControls);
	if (set) {
		CpuBasedVMExecControls |= CPU_BASED_MONITOR_TRAP_FLAG;
	}else {
		CpuBasedVMExecControls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
	}
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, CpuBasedVMExecControls);
}

ULONG64 GetSysFuncAddr(INT32 ApiNumber) {
	ULONG kernelSize = 0;
	ULONG64 kernelBase;
	const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
	const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
	BOOLEAN found = FALSE;

	LONG relativeOffset = 0;
	ULONG_PTR addressAfterPattern;
	ULONG_PTR address;
	SSDTStruct* SSDT;
	ULONG_PTR SSDTbase;

	//1. get ntoskrnl base addr and size
	kernelBase = Getx64NtoskrnlBase();
	if (kernelBase == 0)	return 0;
	kernelSize = Getx64NtoskrnlSize(kernelBase);
	if (kernelSize == 0)	return 0;

	//2. Find KiSystemServiceStart by pattern, win7,win10
	ULONG KiSSSOffset;
	for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++){
		if (RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize){
			found = TRUE;
			break;
		}
	}

	addressAfterPattern = kernelBase + KiSSSOffset + signatureSize;
	address = addressAfterPattern + 7; // Skip lea r10,[nt!KeServiceDescriptorTable]

	if ((*(unsigned char*)address == 0x4c) &&
		(*(unsigned char*)(address + 1) == 0x8d) &&
		(*(unsigned char*)(address + 2) == 0x1d)){
		relativeOffset = *(LONG*)(address + 3);
	}

	if (relativeOffset == 0)	return FALSE;

	//3. find nt ssdt struct and ServiceTable
	SSDT = (SSDTStruct*)(address + relativeOffset + 7);
	SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
	if (!SSDTbase){
		DbgPrint("\n[-]ServiceTable not found");
		return 0;
	}

	//4. get sys func addr
	return (PVOID)((SSDT->pServiceTable[ApiNumber] >> 4) + SSDTbase);
}

NTSTATUS(*NtCreateFileOrig)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);

/* Hook function that hooks NtCreateFile */
NTSTATUS NtCreateFileHook(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
)
{
	HANDLE kFileHandle;
	NTSTATUS ConvertStatus;
	UNICODE_STRING kObjectName;
	ANSI_STRING FileNameA;

	kObjectName.Buffer = NULL;

	__try
	{

		ProbeForRead(FileHandle, sizeof(HANDLE), 1);
		ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
		ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
		ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);

		kFileHandle = *FileHandle;
		kObjectName.Length = ObjectAttributes->ObjectName->Length;
		kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
		kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, 0xA);
		RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);

		ConvertStatus = RtlUnicodeStringToAnsiString(&FileNameA, ObjectAttributes->ObjectName, TRUE);
		DbgPrint("NtCreateFile called for : %s", FileNameA.Buffer);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}

	if (kObjectName.Buffer)
	{
		ExFreePoolWithTag(kObjectName.Buffer, 0xA);
	}


	return NtCreateFileOrig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
		ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

void SyscalHook() {
	// visit https://j00ru.vexillium.org/syscalls/nt/64/ for finding NtCreateFile's Syscall number for win version
	//INT32 ApiNum = 0x0055;	// win10
	INT32 ApiNum = 0x0052;
	PVOID FuncAddr = GetSysFuncAddr(ApiNum);
	if (FuncAddr == 0) {
		DbgPrint("\n[-]Not Find Sys Func addr");
		return;
	}
	PKTHREAD pKthread = KeGetCurrentThread();
	DbgBreakPoint();
	//EptPageHook(pKthread, NULL, NULL, TRUE, TRUE, FALSE);	// test read/write
	// EptPageHook or other ways
	DbgPrint("\n[+]Find Sys Func addr:0x%llx\n", FuncAddr);
	if (EptPageHook(FuncAddr, NtCreateFileHook, (PVOID*)&NtCreateFileOrig, FALSE, FALSE, TRUE)){
		DbgPrint("\n[+]Hook appkied to address of API Number : 0x%x at %llx\n", ApiNum, FuncAddr);
	}

	DbgBreakPoint();
}