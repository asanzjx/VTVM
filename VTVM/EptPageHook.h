#pragma once

#include "common.h"
#include "EPT.h"

#define PAGE_ATTRIB_READ	0x2       
#define PAGE_ATTRIB_WRITE	0x4       
#define PAGE_ATTRIB_EXEC	0x8 


//////////////////////////////////////////////////
//				 Spinlock Funtions				//
//////////////////////////////////////////////////
inline BOOLEAN SpinlockTryLock(volatile LONG* Lock);
inline void SpinlockLock(volatile LONG* Lock);
inline void SpinlockUnlock(volatile LONG* Lock);

typedef enum _INVEPT_TYPE{
	INVEPT_SINGLE_CONTEXT = 0x00000001,
	INVEPT_ALL_CONTEXTS = 0x00000002
}INVEPT_TYPE;

typedef struct _INVEPT_DESC
{
	UINT64 EptPointer;
	UINT64  Reserved;
}INVEPT_DESC, * PINVEPT_DESC;

// Invept Functions
unsigned char Invept(UINT32 Type, INVEPT_DESC* Descriptor);
unsigned char InveptAllContexts();
unsigned char InveptSingleContext(UINT64 EptPonter);
unsigned char InveptSingleContext(UINT64 EptPonter);



// Vmx-root lock for changing EPT PML1 Entry and Invalidating TLB
volatile LONG Pml1ModificationAndInvalidationLock;

extern NTSTATUS inline  AsmVmcall(unsigned long long VmcallNumber, unsigned long long OptionalParam1, unsigned long long OptionalParam2, long long OptionalParam3);

void EptSetPML1AndInvalidateTLB(PEPT_PML1_ENTRY EntryAddress, EPT_PML1_ENTRY EntryValue, INVEPT_TYPE InvalidationType);
VOID EptHookWriteAbsoluteJump(PCHAR TargetBuffer, SIZE_T TargetAddress);
BOOLEAN EptHookInstructionMemory(PEPT_HOOKED_PAGE_DETAIL Hook, PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction);

BOOLEAN EptSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, PVOID PreAllocatedBuffer, SIZE_T PhysicalAddress, ULONG CoreIndex);

BOOLEAN EptPerformPageHook(PVOID TargetAddress, PVOID HookFunction, PVOID* OrigFunction, BOOLEAN UnsetRead, BOOLEAN UnsetWrite, BOOLEAN UnsetExecute);
VOID InvalidateEptByVmcall(UINT64 Context);
BOOLEAN EptPageHook(PVOID TargetAddress, PVOID HookFunction, PVOID* OrigFunction, BOOLEAN SetHookForRead, BOOLEAN SetHookForWrite, BOOLEAN SetHookForExec);