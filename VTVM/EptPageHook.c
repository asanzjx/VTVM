#include "EptPageHook.h"
#include "vm.h"



/* Invoke the Invept instruction */
unsigned char Invept(UINT32 Type, INVEPT_DESC* Descriptor)
{
	if (!Descriptor)
	{
		INVEPT_DESC ZeroDescriptor = { 0 };
		Descriptor = &ZeroDescriptor;
	}

	return AsmInvept(Type, Descriptor);
}

/* Invalidates a single context in ept cache table */
unsigned char InveptSingleContext(UINT64 EptPointer)
{
	INVEPT_DESC Descriptor = { 0 };
	Descriptor.EptPointer = EptPointer;
	Descriptor.Reserved = 0;
	return Invept(INVEPT_SINGLE_CONTEXT, &Descriptor);
}

/* Invalidates all contexts in ept cache table */
unsigned char InveptAllContexts()
{
	return Invept(INVEPT_ALL_CONTEXTS, NULL);
}


void EptSetPML1AndInvalidateTLB(PEPT_PML1_ENTRY EntryAddress, EPT_PML1_ENTRY EntryValue, INVEPT_TYPE InvalidationType) {
	// acquire the lock
	SpinlockLock(&Pml1ModificationAndInvalidationLock);
	// set the value
	EntryAddress->All = EntryValue.All;

	// invalidate the cache
	if (InvalidationType == INVEPT_SINGLE_CONTEXT){
		InveptSingleContext(g_EPT_State_ptr->EptPointer.All);
	}else{
		InveptAllContexts();
	}
	// release the lock
	SpinlockUnlock(&Pml1ModificationAndInvalidationLock);
}

/* Split 2MB (LargePage) into 4kb pages */
BOOLEAN EptSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, PVOID PreAllocatedBuffer, SIZE_T PhysicalAddress, ULONG CoreIndex){

	PVMM_EPT_DYNAMIC_SPLIT NewSplit;
	EPT_PML1_ENTRY EntryTemplate;
	SIZE_T EntryIndex;
	PEPT_PML2_ENTRY TargetEntry;
	EPT_PML2_POINTER NewPointer;

	// Find the PML2 entry that's currently used
	TargetEntry = EptGetPml2Entry(EptPageTable, PhysicalAddress);
	if (!TargetEntry)
	{
		DbgPrint("An invalid physical address passed");
		return FALSE;
	}

	// If this large page is not marked a large page, that means it's a pointer already.
	// That page is therefore already split.
	if (!TargetEntry->Fields.LargePage){
		return TRUE;
	}

	// Allocate the PML1 entries 
	NewSplit = (PVMM_EPT_DYNAMIC_SPLIT)PreAllocatedBuffer;
	if (!NewSplit){
		DbgPrint("\[-]Failed to allocate dynamic split memory");
		return FALSE;
	}
	RtlZeroMemory(NewSplit, sizeof(VMM_EPT_DYNAMIC_SPLIT));


	// Point back to the entry in the dynamic split for easy reference for which entry that dynamic split is for.
	NewSplit->Entry = TargetEntry;

	// Make a template for RWX 
	EntryTemplate.All = 0;
	EntryTemplate.Fields.Read = 1;
	EntryTemplate.Fields.Write = 1;
	EntryTemplate.Fields.Execute = 1;

	// Copy the template into all the PML1 entries 
	__stosq((SIZE_T*)&NewSplit->PML1[0], EntryTemplate.All, VMM_EPT_PML1E_COUNT);

	// Set the page frame numbers for identity mapping.
	for (EntryIndex = 0; EntryIndex < VMM_EPT_PML1E_COUNT; EntryIndex++){
		// Convert the 2MB page frame number to the 4096 page entry number plus the offset into the frame. 
		NewSplit->PML1[EntryIndex].Fields.PhysicalAddress = ((TargetEntry->Fields.PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + EntryIndex;
	}

	// Allocate a new pointer which will replace the 2MB entry with a pointer to 512 4096 byte entries. 
	NewPointer.All = 0;
	NewPointer.Fields.Write = 1;
	NewPointer.Fields.Read = 1;
	NewPointer.Fields.Execute = 1;
	NewPointer.Fields.PhysicalAddress = (SIZE_T)VA2PA(&NewSplit->PML1[0]) / PAGE_SIZE;

	// Now, replace the entry in the page table with our new split pointer.
	RtlCopyMemory(TargetEntry, &NewPointer, sizeof(NewPointer));
	return TRUE;
}

/* Write an absolute x64 jump to an arbitrary address to a buffer. */
VOID EptHookWriteAbsoluteJump(PCHAR TargetBuffer, SIZE_T TargetAddress)
{
	/* mov r15, Target */
	TargetBuffer[0] = 0x49;
	TargetBuffer[1] = 0xBB;

	/* Target */
	*((PSIZE_T)&TargetBuffer[2]) = TargetAddress;

	/* push r15 */
	TargetBuffer[10] = 0x41;
	TargetBuffer[11] = 0x53;

	/* ret */
	TargetBuffer[12] = 0xC3;
}

BOOLEAN EptHookInstructionMemory(PEPT_HOOKED_PAGE_DETAIL Hook, PVOID TargetFunction, PVOID HookFunction, PVOID* OrigFunction) {
	//SIZE_T SizeOfHookedInstructions;
	SIZE_T OffsetIntoPage;
	int SizeOfHookedInstructions;
	OffsetIntoPage = ADDRMASK_EPT_PML1_OFFSET((SIZE_T)TargetFunction);
	DbgPrint("OffsetIntoPage: 0x%llx", OffsetIntoPage);

	if ((OffsetIntoPage + 13) > PAGE_SIZE - 1)
	{
		DbgPrint("Function extends past a page boundary. We just don't have the technology to solve this.....");
		return FALSE;
	}

	/* Determine the number of instructions necessary to overwrite using Length Disassembler Engine */
	/*
	for (SizeOfHookedInstructions = 0;
		SizeOfHookedInstructions < 13;
		SizeOfHookedInstructions += LDE(TargetFunction, 64))
	{
		// Get the full size of instructions necessary to copy
	}
	*/
	SizeOfHookedInstructions = insn_len_x86_64((void*)TargetFunction);
	DbgPrint("\n[+]Number of bytes of instruction mem: %d", SizeOfHookedInstructions);
	//DbgBreakPoint();

	/* Build a trampoline */

	/* Allocate some executable memory for the trampoline */
	Hook->Trampoline = PoolManagerRequestPool(EXEC_TRAMPOLINE, TRUE, MAX_EXEC_TRAMPOLINE_SIZE);

	if (!Hook->Trampoline)
	{
		DbgPrint("Could not allocate trampoline function buffer.");
		return FALSE;
	}

	/* Copy the trampoline instructions in. */
	RtlCopyMemory(Hook->Trampoline, TargetFunction, SizeOfHookedInstructions);

	/* Add the absolute jump back to the original function. */
	EptHookWriteAbsoluteJump(&Hook->Trampoline[SizeOfHookedInstructions], (SIZE_T)TargetFunction + SizeOfHookedInstructions);

	DbgPrint("Trampoline: 0x%llx", Hook->Trampoline);
	DbgPrint("HookFunction: 0x%llx", HookFunction);

	/* Let the hook function call the original function */
	*OrigFunction = Hook->Trampoline;

	/* Write the absolute jump to our shadow page memory to jump to our hook. */
	EptHookWriteAbsoluteJump(&Hook->FakePageContents[OffsetIntoPage], (SIZE_T)HookFunction);

	return TRUE;
}


BOOLEAN EptPerformPageHook(PVOID TargetAddress, PVOID HookFunction, PVOID* OrigFunction, BOOLEAN UnsetRead, BOOLEAN UnsetWrite, BOOLEAN UnsetExecute) {

	EPT_PML1_ENTRY ChangedEntry;
	INVEPT_DESCRIPTOR Descriptor;
	SIZE_T PhysicalAddress;
	PVOID VirtualTarget;
	PVOID TargetBuffer;
	PEPT_PML1_ENTRY TargetPage;
	PEPT_HOOKED_PAGE_DETAIL HookedPage;
	ULONG LogicalCoreIndex;

	// 1. Check whether we are in VMX Root Mode or Not 
	LogicalCoreIndex = KeGetCurrentProcessorIndex();

	if (g_VM_DATA_ptr[LogicalCoreIndex].IsOnVmRootMode && !g_VM_DATA_ptr[LogicalCoreIndex].HasLaunched){
		return FALSE;
	}

	VirtualTarget = PAGE_ALIGN(TargetAddress);
	PhysicalAddress = (SIZE_T)VA2PA(VirtualTarget);

	if (!PhysicalAddress){
		DbgPrint("\n[-]Target address could not be mapped to physical memory");
		return FALSE;
	}

	// 2. Request Pool
	TargetBuffer = PoolManagerRequestPool(SPLIT_2MB_PAGING_TO_4KB_PAGE, TRUE, sizeof(VMM_EPT_DYNAMIC_SPLIT));

	if (!TargetBuffer){
		DbgPrint("[-]There is no pre-allocated buffer available");
		return FALSE;
	}

	// 3. Get TargetBuffer's page-table profile
	if (!EptSplitLargePage(g_EPT_State_ptr->EptPageTable, TargetBuffer, PhysicalAddress, LogicalCoreIndex)){
		DbgPrint("Could not split page for the address : 0x%llx", PhysicalAddress);
		return FALSE;
	}

	TargetPage = EptGetPml1Entry(g_EPT_State_ptr->EptPageTable, PhysicalAddress);

	// Ensure the target is valid. 
	if (!TargetPage){
		DbgPrint("Failed to get PML1 entry of the target address");
		return FALSE;
	}

	// Save the original permissions of the page 
	ChangedEntry = *TargetPage;

	/* Execution is treated differently */
	if (UnsetRead) ChangedEntry.Fields.Read = 0;
	else ChangedEntry.Fields.Read = 1;

	if (UnsetWrite)ChangedEntry.Fields.Write = 0;
	else ChangedEntry.Fields.Write = 1;

	// 4. Get Hooked Page, and set profile
	/* Save the detail of hooked page to keep track of it */
	HookedPage = PoolManagerRequestPool(TRACKING_HOOKED_PAGES, TRUE, sizeof(EPT_HOOKED_PAGE_DETAIL));

	if (!HookedPage){
		DbgPrint("There is no pre-allocated pool for saving hooked page details");
		return FALSE;
	}

	// Save the virtual address
	HookedPage->VirtualAddress = TargetAddress;

	// Save the physical address
	HookedPage->PhysicalBaseAddress = PhysicalAddress;

	// Fake page content physical address
	HookedPage->PhysicalBaseAddressOfFakePageContents = (SIZE_T)VA2PA(&HookedPage->FakePageContents[0]) / PAGE_SIZE;

	// Save the entry address
	HookedPage->EntryAddress = TargetPage;

	// Save the orginal entry
	HookedPage->OriginalEntry = *TargetPage;

	// If it's Execution hook then we have to set extra fields
	if (UnsetExecute){
		// Show that entry has hidden hooks for execution
		HookedPage->IsExecutionHook = TRUE;

		// In execution hook, we have to make sure to unset read, write because
		// an EPT violation should occur for these cases and we can swap the original page
		ChangedEntry.Fields.Read = 0;
		ChangedEntry.Fields.Write = 0;
		ChangedEntry.Fields.Execute = 1;

		// Also set the current pfn to fake page
		ChangedEntry.Fields.PhysicalAddress = HookedPage->PhysicalBaseAddressOfFakePageContents;

		// Copy the content to the fake page
		RtlCopyBytes(&HookedPage->FakePageContents, VirtualTarget, PAGE_SIZE);

		// Create Hook
		if (!EptHookInstructionMemory(HookedPage, TargetAddress, HookFunction, OrigFunction)){
			DbgPrint("\n[-]Could not build the hook.");
			return FALSE;
		}
	}

	// Save the modified entry
	HookedPage->ChangedEntry = ChangedEntry;

	// 5. Add it to the list, *list must be init
	PLIST_ENTRY ListHead = &(g_EPT_State_ptr->HookedPagesList);
	PLIST_ENTRY Entry = &(HookedPage->PageHookList);
	
	InitializeListHead(Entry);
	InsertHeadList(ListHead, Entry);
	//DbgBreakPoint();
	
	/***********************************************************/
	// 6. Apply the hook to EPT
	// if not launched, there is no need to modify it on a safe environment
	// g_VM_DATA_ptr[LogicalCoreIndex].HasLaunched?
	if (g_VM_DATA_ptr[LogicalCoreIndex].IsOnVmRootMode) EptSetPML1AndInvalidateTLB(TargetPage, ChangedEntry, INVEPT_SINGLE_CONTEXT);
	else TargetPage->All = ChangedEntry.All;

	return TRUE;
}

VOID InvalidateEptByVmcall(UINT64 Context) {
	if (Context == NULL) AsmVmcall(VMCALL_INVEPT_ALL_CONTEXTS, NULL, NULL, NULL);
	else AsmVmcall(VMCALL_INVEPT_SINGLE_CONTEXT, Context, NULL, NULL);
}


BOOLEAN EptPageHook(PVOID TargetAddress, PVOID HookFunction, PVOID* OrigFunction, BOOLEAN SetHookForRead, BOOLEAN SetHookForWrite, BOOLEAN SetHookForExec) {
	IA32_VMX_EPT_VPID_CAP_REGISTER VpidRegister;
	UINT32 PageHookMask = 0;

	VpidRegister.Flags = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
	//1. check if support Execute, read
	if (SetHookForExec && !VpidRegister.ExecuteOnlyPages) {
		DbgPrint("\n[-]VpidRegister.ExecuteOnlyPages not support");
		return FALSE;
	}
	if (SetHookForWrite && !SetHookForRead)	return FALSE;

	//2. set page hook mask
	if (SetHookForRead) PageHookMask |= PAGE_ATTRIB_READ;
	if (SetHookForWrite)	PageHookMask |= PAGE_ATTRIB_WRITE;
	if (SetHookForExec)	PageHookMask |= PAGE_ATTRIB_EXEC;
	if (PageHookMask == 0){
		// nothing to hook
		DbgPrint("\n[+]Nothing to hook");
		return FALSE;
	}

	//3.Check whether we are in VMX Root Mode or Not 
	if (g_VM_DATA_ptr[KeGetCurrentProcessorIndex()].IsOnVmRootMode) {
		// 4.1 in root-mode, EptPerformPageHook
		 if (EptPerformPageHook(TargetAddress, HookFunction, OrigFunction, SetHookForRead, SetHookForWrite, SetHookForExec))  DbgPrint("\n[+] Hook applied, in vm root mode");
		else return FALSE;
	}else {
		// 4.2 in guest mode, by vmcall
		// Move Attribute Mask to the upper 32 bits of the VMCALL Number 
		UINT64 VmcallNumber = ((UINT64)PageHookMask) << 32 | VMCALL_CHANGE_PAGE_ATTRIB;
		if (!AsmVmcall(VmcallNumber, TargetAddress, HookFunction, OrigFunction)) return FALSE;
		DbgPrint("\n[+]Hook page from root mode");

		// Now we have to notify all the core to invalidate their EPT
		if (!g_VM_DATA_ptr[KeGetCurrentProcessorIndex()].IsOnVmRootMode) {
			// Now we have to notify all the core to invalidate their EPT
			KeIpiGenericCall(InvalidateEptByVmcall, g_EPT_State_ptr->EptPointer.All);
		}else DbgPrint("\n[-]Unable to notify all cores to invalidate their TLB caches as you called hook on vmx-root mode.");
	}
	DbgPrint("\n[+]Hook had installed");
	return TRUE;

}