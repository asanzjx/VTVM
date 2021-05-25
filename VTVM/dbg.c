#include "dbg.h"
#include "EPT.h"
#include "vm.h"
#include "EptPageHook.h"

ULONG64 GetFuncAddrByName(char *func_name) {
	ULONG64 ntos_base_addr = Getx64NtoskrnlBase();
	short MZSignature = *(short *)ntos_base_addr;
	if (MZSignature != 0x5a4d) {
		DbgPrint("\n[-]not ntos pe");
		DbgBreakPoint();
	}

	long AddrOfPeHeaderOffset = *(long *)(ntos_base_addr + 0x3c);
	DWORD32 PeSignature = *(DWORD32*)(ntos_base_addr + AddrOfPeHeaderOffset);
	if (PeSignature != 0x4550) {
		DbgPrint("\n[-]not ntos pe header");
		DbgBreakPoint();
	}

	DWORD32 rva_of_export_offset = *(DWORD32*)(ntos_base_addr + 0x170);
	DWORD32 num_of_names = *(DWORD32*)(ntos_base_addr + rva_of_export_offset + 0x18);
	DWORD32 addr_of_func_offset = *(DWORD32*)(ntos_base_addr + rva_of_export_offset + 0x1c);
	DWORD32 addr_of_name_offset = *(DWORD32*)(ntos_base_addr + rva_of_export_offset + 0x20);

	ULONG64 addr_of_func = ntos_base_addr + addr_of_func_offset;
	ULONG64 addr_of_name = ntos_base_addr + addr_of_name_offset;
	DWORD32 addr_func = 0;
	for (size_t i = 0; i < num_of_names; i++)
	{
		DWORD32 export_func_name_offset = *(DWORD32*)(addr_of_name + i * 4);
		char* export_func_name = (char*)(addr_of_name + export_func_name_offset);
		DbgPrint(export_func_name);
		break;
		DbgBreakPoint();
	}



	return NULL;
}


ULONG64 DbgGetFuncAddr(IN PCWSTR FuncName) {
	UNICODE_STRING unicodeFuncName;
	
	RtlInitUnicodeString(&unicodeFuncName, FuncName);
	PVOID FuncAddr = MmGetSystemRoutineAddress(&unicodeFuncName);
	if (MmIsAddressValid(FuncAddr)) {
		return (ULONG64)FuncAddr;
	}
	else {
		//continue search func by export table
		GetFuncAddrByName(FuncName);
		DbgBreakPoint();
		return NULL;
	}
}

ULONG64 pfPsGetProcessDebugPort() {
	DbgPrint("\n[+]hooked PsGetProcessDebugPort");

	return 0x1f000f;
}

// handle attach
BOOLEAN HandleAttach() {
	char* PsGetProcessDebugPort_addr = (char*)DbgGetFuncAddr(L"DbgBreakPoint");
	PsGetProcessDebugPort_addr = (char *)DbgGetFuncAddr(L"PsGetProcessDebugPort");
	DbgBreakPoint();
	EptHookWriteAbsoluteJump(PsGetProcessDebugPort_addr, pfPsGetProcessDebugPort);
	DbgBreakPoint();
	
}