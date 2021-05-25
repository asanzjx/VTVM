#include "common.h"
#include "EPT.h"

/*
PEPTP InitEPTPtr() {
	//1. make sure the thread run in the low irql,wdm macros
	PAGED_CODE();

	//DbgBreakPoint();

	//2. Allocate EPTP
	PEPTP EPTPointer = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!EPTPointer) {
		return NULL;
	}
	RtlZeroMemory(EPTPointer, PAGE_SIZE);

	//3. Allocate EPT PML4
	PEPT_PML4E EPT_PML4 = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!EPT_PML4) {
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PML4, PAGE_SIZE);

	//4. Allocate EPT_PDPT
	PEPT_PDPTE EPT_PDPT = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
	if (!EPT_PDPT) {
		ExFreePoolWithTag(EPT_PML4, POOLTAG);
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PDPT, PAGE_SIZE);

	//5. Allocate EPT Page-Directory
	PEPT_PDE EPT_PD = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!EPT_PD) {
		ExFreePoolWithTag(EPT_PDPT, POOLTAG);
		ExFreePoolWithTag(EPT_PML4, POOLTAG);
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PD, PAGE_SIZE);

	//5. Allocate blank page table
	//	Allocate EPT Page-Table
	PEPT_PTE EPT_PT = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);

	if (!EPT_PT) {
		ExFreePoolWithTag(EPT_PD, POOLTAG);
		ExFreePoolWithTag(EPT_PDPT, POOLTAG);
		ExFreePoolWithTag(EPT_PML4, POOLTAG);
		ExFreePoolWithTag(EPTPointer, POOLTAG);
		return NULL;
	}
	RtlZeroMemory(EPT_PT, PAGE_SIZE);

	return EPTPointer;
}
*/

/* Check whether EPT features are present or not */
BOOLEAN EptCheckFeatures(){
	//check MTRR and VPID
	IA32_VMX_EPT_VPID_CAP_REGISTER VpidReg;
	IA32_MTRR_DEF_TYPE_REGISTER MTRRDefType;
	MTRRDefType.Flags = __readmsr(MSR_IA32_MTRR_DEF_TYPE);
	VpidReg.Flags = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	if (!MTRRDefType.Fields.MtrrEnable){
		DbgPrint("[-]MTRR not support\n");
		return FALSE;
	}

	if (!VpidReg.PageWalkLength4 || !VpidReg.MemoryTypeWriteBack || !VpidReg.Pde2MbPages) {
		DbgPrint("[-]Vpid feature not support\n");
		return FALSE;
	}

	if (!VpidReg.AdvancedVmexitEptViolationsInformation) {
		DbgPrint("[-]cpu not support Advanced Vmexit Ept Violation\n");
	}

	DbgPrint("\n[+]All Ept Features suppored");
	return TRUE;
}


BOOLEAN EptBuildBitmap() {
	IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
	IA32_MTRR_PHYSBASE_REGISTER CurrentPhysBase;
	IA32_MTRR_PHYSMASK_REGISTER CurrentPhysMask;
	PMTRR_RANGE_DESCRIPTOR Descriptor;
	ULONG CurrentRegister;
	ULONG NumberOfBitsInMask;

	MTRRCap.Flags = __readmsr(MSR_IA32_MTRR_CAPABILITIES);

	for (CurrentRegister = 0; CurrentRegister < MTRRCap.VariableRangeCount; CurrentRegister++)
	{
		// For each dynamic register pair
		CurrentPhysBase.Flags = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (CurrentRegister * 2));
		CurrentPhysMask.Flags = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (CurrentRegister * 2));

		// Is the range enabled?
		if (CurrentPhysMask.Valid){
			// We only need to read these once because the ISA dictates that MTRRs are to be synchronized between all processors
			// during BIOS initialization.
			Descriptor = &g_EPT_State_ptr->MemoryRanges[g_EPT_State_ptr->NumberOfEnabledMemoryRanges++];

			// Calculate the base address in bytes
			Descriptor->PhysicalBaseAddress = CurrentPhysBase.PageFrameNumber * PAGE_SIZE;

			// Calculate the total size of the range
			// The lowest bit of the mask that is set to 1 specifies the size of the range
			_BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.PageFrameNumber * PAGE_SIZE);

			// Size of the range in bytes + Base Address
			Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

			// Memory Type (cacheability attributes)
			Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Type;

			if (Descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
			{
				/* This is already our default, so no need to store this range.
				 * Simply 'free' the range we just wrote. */
				g_EPT_State_ptr->NumberOfEnabledMemoryRanges--;
			}
			DbgPrint("\n[+]MTRR Range: Base=0x%llx End=0x%llx Type=0x%x", Descriptor->PhysicalBaseAddress, Descriptor->PhysicalEndAddress, Descriptor->MemoryType);
		}
	}
	DbgPrint("\n[+]Total MTRR Ranges Committed: %d", g_EPT_State_ptr->NumberOfEnabledMemoryRanges);

	return TRUE;
}

/* Set up PML2 Entries */
VOID EptSetupPML2Entry(PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber){
	SIZE_T AddressOfPage;
	SIZE_T CurrentMtrrRange;
	SIZE_T TargetMemoryType;

	NewEntry->Fields.PageFrameNumber = PageFrameNumber;

	// Size of 2MB page * PageFrameNumber == AddressOfPage (physical memory). 
	AddressOfPage = PageFrameNumber * SIZE_2_MB;
	if (PageFrameNumber == 0){
		NewEntry->Fields.EPTMemoryType = MEMORY_TYPE_UNCACHEABLE;
		return;
	}

	// Default memory type is always WB for performance. 
	TargetMemoryType = MEMORY_TYPE_WRITE_BACK;

	// For each MTRR range 
	for (CurrentMtrrRange = 0; CurrentMtrrRange < g_EPT_State_ptr->NumberOfEnabledMemoryRanges; CurrentMtrrRange++){
		// If this page's address is below or equal to the max physical address of the range 
		if (AddressOfPage <= g_EPT_State_ptr->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress){
			// And this page's last address is above or equal to the base physical address of the range 
			if ((AddressOfPage + SIZE_2_MB - 1) >= g_EPT_State_ptr->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress){
				TargetMemoryType = g_EPT_State_ptr->MemoryRanges[CurrentMtrrRange].MemoryType;
				if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
				{
					// If this is going to be marked uncacheable, then we stop the search as UC always takes precedent. 
					break;
				}
			}
		}
	}

	// Finally, commit the memory type to the entry. 
	NewEntry->Fields.EPTMemoryType = TargetMemoryType;
}


BOOLEAN EptInit() {
	PVMM_EPT_PAGE_TABLE PageTable;
	EPTP EPTP;

	// 1.alloc PageTable
	// Allocate all paging structures as 4KB aligned pages 
	PHYSICAL_ADDRESS MaxSize;
	PVOID Output;

	// Allocate address anywhere in the OS's memory space
	MaxSize.QuadPart = MAXULONG64;
	PageTable = MmAllocateContiguousMemory((sizeof(VMM_EPT_PAGE_TABLE) / PAGE_SIZE) * PAGE_SIZE, MaxSize);

	if (!PageTable) {
		DbgPrint("\n[-]Unable to allocate PageTable for EPT");
		return FALSE;
	}
	RtlZeroMemory(PageTable, sizeof(VMM_EPT_PAGE_TABLE));
	// Initialize the dynamic split list which holds all dynamic page splits 
	InitializeListHead(&PageTable->DynamicSplitList);

	// Mark the first 512GB PML4 entry as present, which allows us to manage up to 512GB of discrete paging structures. 
	PageTable->PML4[0].Fields.PhysicalAddress = (SIZE_T)VA2PA(&PageTable->PML3[0]) / PAGE_SIZE;
	PageTable->PML4[0].Fields.Read = 1;
	PageTable->PML4[0].Fields.Write = 1;
	PageTable->PML4[0].Fields.Execute = 1;

	EPT_PDPTE PDPTE;
	SIZE_T EntryIndex = 0;
	PDPTE.All = 0;
	PDPTE.Fields.Read = 1;
	PDPTE.Fields.Write = 1;
	PDPTE.Fields.Execute = 1;
	__stosq((SIZE_T*)&PageTable->PML3[0], PDPTE.All, VMM_EPT_PML3E_COUNT);
	for (EntryIndex; EntryIndex < VMM_EPT_PML3E_COUNT; EntryIndex++){
		// Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
		// NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
		PageTable->PML3[EntryIndex].Fields.PhysicalAddress = (SIZE_T)VA2PA(&PageTable->PML2[EntryIndex][0]) / PAGE_SIZE;
	}

	EPT_PDE_2MB PDE_2MB;
	SIZE_T EntryGroupIndex;
	PDE_2MB.All = 0;
	PDE_2MB.Fields.Read = 1;
	PDE_2MB.Fields.Write = 1;
	PDE_2MB.Fields.Execute = 1;
	PDE_2MB.Fields.LargePage = 1;
	__stosq((SIZE_T*)&PageTable->PML2[0], PDE_2MB.All, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

	// For each of the 512 collections of 512 2MB PML2 entries 
	for (EntryGroupIndex = 0; EntryGroupIndex < VMM_EPT_PML3E_COUNT; EntryGroupIndex++){
		// For each 2MB PML2 entry in the collection 
		for (EntryIndex = 0; EntryIndex < VMM_EPT_PML2E_COUNT; EntryIndex++){
			// Setup the memory type and frame number of the PML2 entry. 
			 EptSetupPML2Entry(&PageTable->PML2[EntryGroupIndex][EntryIndex], (EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex);
		}
	}

	EPTP.All = 0;
	EPTP.Fields.MemoryType = MEMORY_TYPE_WRITE_BACK;
	EPTP.Fields.PageWalkLength = 3;
	EPTP.Fields.DirtyAndAceessEnabled = FALSE;
	EPTP.Fields.PML4Address = (SIZE_T)VA2PA(&PageTable->PML4) / PAGE_SIZE;

	g_EPT_State_ptr->EptPointer = EPTP;
	g_EPT_State_ptr->EptPageTable = PageTable;

	///////////////////////// Example Test /////////////////////////
	// EptPageHook(ExAllocatePoolWithTag, FALSE);
	////////////////////////////////////////////////////////////////


	return TRUE;
}

/* Get the PML1 entry for this physical address if the page is split. Return NULL if the address is invalid or the page wasn't already split. */
PEPT_PML1_ENTRY EptGetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress){
	SIZE_T Directory, DirectoryPointer, PML4Entry;
	PEPT_PML2_ENTRY PML2;
	PEPT_PML1_ENTRY PML1;
	PEPT_PML2_POINTER PML2Pointer;

	Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
	DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
	PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

	// Addresses above 512GB are invalid because it is > physical address bus width 
	if (PML4Entry > 0)	return NULL;

	PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];

	// Check to ensure the page is split 
	if (PML2->Fields.LargePage)	return NULL;

	// Conversion to get the right PageFrameNumber.
	// These pointers occupy the same place in the table and are directly convertable.
	PML2Pointer = (PEPT_PML2_POINTER)PML2;

	// If it is, translate to the PML1 pointer 
	PML1 = (PEPT_PML1_ENTRY)PA2VA((PVOID)(PML2Pointer->Fields.PhysicalAddress * PAGE_SIZE));

	if (!PML1) return NULL;

	// Index into PML1 for that address 
	PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

	return PML1;
}

PEPT_PML2_ENTRY EptGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress){
	SIZE_T Directory, DirectoryPointer, PML4Entry;
	PEPT_PML2_ENTRY PML2;

	Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
	DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
	PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

	// Addresses above 512GB are invalid because it is > physical address bus width 
	if (PML4Entry > 0) return NULL;

	PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];
	return PML2;
}