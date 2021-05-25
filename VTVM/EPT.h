#pragma once

/*
* EPT.h 
*/

#include "common.h"

// The number of 512GB PML4 entries in the page table/
#define VMM_EPT_PML4E_COUNT 512

// The number of 1GB PDPT entries in the page table per 512GB PML4 entry.
#define VMM_EPT_PML3E_COUNT 512

// Then number of 2MB Page Directory entries in the page table per 1GB PML3 entry.
#define VMM_EPT_PML2E_COUNT 512

// Then number of 4096 byte Page Table entries in the page table per 2MB PML2 entry when dynamically split.
#define VMM_EPT_PML1E_COUNT 512

// Integer 2MB
#define SIZE_2_MB ((SIZE_T)(512 * PAGE_SIZE))

// Offset into the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_OFFSET(_VAR_) (_VAR_ & 0xFFFULL)

// Index of the 1st paging structure (4096 byte)
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)

// Index of the 2nd paging structure (2MB)
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)

// Index of the 3rd paging structure (1GB)
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)

// Index of the 4th paging structure (512GB)
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)


// See Table 24-8. Format of Extended-Page-Table Pointer
typedef union _EPTP {
	ULONG64 All;
	struct {
		UINT64 MemoryType : 3; // bit 2:0 (0 = Uncacheable (UC); 6 = Write - back(WB))
		UINT64 PageWalkLength : 3; // bit 5:3 (This value is 1 less than the EPT page-walk length) 
		UINT64 DirtyAndAceessEnabled : 1; // bit 6  (Setting this control to 1 enables accessed and dirty flags for EPT)
		UINT64 Reserved1 : 5; // bit 11:7 
		UINT64 PML4Address : 36;
		UINT64 Reserved2 : 16;
	}Fields;
}EPTP, * PEPTP;

// See Table 28-1. 
typedef union _EPT_PML4E {
	ULONG64 All;
	struct {
		UINT64 Read : 1; // bit 0
		UINT64 Write : 1; // bit 1
		UINT64 Execute : 1; // bit 2
		UINT64 Reserved1 : 5; // bit 7:3 (Must be Zero)
		UINT64 Accessed : 1; // bit 8
		UINT64 Ignored1 : 1; // bit 9
		UINT64 ExecuteForUserMode : 1; // bit 10
		UINT64 Ignored2 : 1; // bit 11
		UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
		UINT64 Reserved2 : 4; // bit 51:N
		UINT64 Ignored3 : 12; // bit 63:52
	}Fields;
}EPT_PML4E, * PEPT_PML4E;

// See Table 28-3
typedef union _EPT_PDPTE {
	ULONG64 All;
	struct {
		UINT64 Read : 1; // bit 0
		UINT64 Write : 1; // bit 1
		UINT64 Execute : 1; // bit 2
		UINT64 Reserved1 : 5; // bit 7:3 (Must be Zero)
		UINT64 Accessed : 1; // bit 8
		UINT64 Ignored1 : 1; // bit 9
		UINT64 ExecuteForUserMode : 1; // bit 10
		UINT64 Ignored2 : 1; // bit 11
		UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
		UINT64 Reserved2 : 4; // bit 51:N
		UINT64 Ignored3 : 12; // bit 63:52
	}Fields;
}EPT_PDPTE, * PEPT_PDPTE;

// See Table 28-5
typedef union _EPT_PDE {
	ULONG64 All;
	struct {
		UINT64 Read : 1; // bit 0
		UINT64 Write : 1; // bit 1
		UINT64 Execute : 1; // bit 2
		UINT64 Reserved1 : 5; // bit 7:3 (Must be Zero)
		UINT64 Accessed : 1; // bit 8
		UINT64 Ignored1 : 1; // bit 9
		UINT64 ExecuteForUserMode : 1; // bit 10
		UINT64 Ignored2 : 1; // bit 11
		UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
		UINT64 Reserved2 : 4; // bit 51:N
		UINT64 Ignored3 : 12; // bit 63:52
	}Fields;
}EPT_PDE, * PEPT_PDE;

// See Table 28-6
typedef union _EPT_PTE {
	ULONG64 All;
	struct {
		UINT64 Read : 1; // bit 0
		UINT64 Write : 1; // bit 1
		UINT64 Execute : 1; // bit 2
		UINT64 EPTMemoryType : 3; // bit 5:3 (EPT Memory type)
		UINT64 IgnorePAT : 1; // bit 6
		UINT64 Ignored1 : 1; // bit 7
		UINT64 AccessedFlag : 1; // bit 8	
		UINT64 DirtyFlag : 1; // bit 9
		UINT64 ExecuteForUserMode : 1; // bit 10
		UINT64 Ignored2 : 1; // bit 11
		UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
		UINT64 Reserved : 4; // bit 51:N
		UINT64 Ignored3 : 11; // bit 62:52
		UINT64 SuppressVE : 1; // bit 63
	}Fields;
}EPT_PTE, * PEPT_PTE;

typedef union _EPT_PDE_2MB {
	ULONG64 All;
	struct {
		UINT64 Read : 1; // bit 0
		UINT64 Write : 1; // bit 1
		UINT64 Execute : 1; // bit 2
		UINT64 EPTMemoryType : 3; // bit 5:3 (EPT Memory type)
		UINT64 IgnorePAT : 1; // bit 6
		UINT64 LargePage : 1; // bit 7
		UINT64 AccessedFlag : 1; // bit 8	
		UINT64 DirtyFlag : 1; // bit 9
		UINT64 ExecuteForUserMode : 1; // bit 10
		UINT64 Reserved1 : 10; // bit 11
		UINT64 PageFrameNumber : 27;
		UINT64 Reserved2 : 15; // bit 51:N
		UINT64 SuppressVE : 1; // bit 63
	}Fields;
}EPT_PDE_2MB, * PEPT_PDE_2MB;

typedef EPT_PML4E EPT_PML4_POINTER, * PEPT_PML4_POINTER;
typedef EPT_PDPTE EPT_PML3_POINTER, * PEPT_PML3_POINTER;
typedef EPT_PDE_2MB EPT_PML2_ENTRY, * PEPT_PML2_ENTRY;
typedef EPT_PDE EPT_PML2_POINTER, * PEPT_PML2_POINTER;
typedef EPT_PTE EPT_PML1_ENTRY, * PEPT_PML1_ENTRY;

typedef struct _VMM_EPT_PAGE_TABLE{
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4_POINTER PML4[VMM_EPT_PML4E_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML2_ENTRY PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];
	LIST_ENTRY DynamicSplitList;
} VMM_EPT_PAGE_TABLE, * PVMM_EPT_PAGE_TABLE;

typedef struct _MTRR_RANGE_DESCRIPTOR
{
	SIZE_T PhysicalBaseAddress;
	SIZE_T PhysicalEndAddress;
	UCHAR MemoryType;
} MTRR_RANGE_DESCRIPTOR, * PMTRR_RANGE_DESCRIPTOR;

typedef struct _EPT_STATE{
	LIST_ENTRY HookedPagesList;
	// Physical memory ranges described by the BIOS in the MTRRs. Used to build the EPT identity mapping.
	MTRR_RANGE_DESCRIPTOR MemoryRanges[9];
	ULONG NumberOfEnabledMemoryRanges;
	EPTP   EptPointer;
	PVMM_EPT_PAGE_TABLE EptPageTable; // Page table entries for EPT entry
} EPT_STATE, * PEPT_STATE;

typedef struct _INVEPT_DESCRIPTOR
{
	UINT64 EptPointer;
	UINT64 Reserved; // Must be zero.
} INVEPT_DESCRIPTOR, * PINVEPT_DESCRIPTOR;

PEPT_STATE g_EPT_State_ptr;

//implement in EPT.c
//PEPTP InitEPTPtr();
BOOLEAN EptCheckFeatures();
BOOLEAN EptBuildBitmap();
VOID EptSetupPML2Entry(PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber);
BOOLEAN EptInit();

PEPT_PML1_ENTRY EptGetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress);
PEPT_PML2_ENTRY EptGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress);