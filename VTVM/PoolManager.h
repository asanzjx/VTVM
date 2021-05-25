#pragma once
#include "common.h"
#include "EPT.h"

#define MAX_EXEC_TRAMPOLINE_SIZE	100
#define NumberOfPreAllocatedBuffers				10

typedef enum {
	TRACKING_HOOKED_PAGES,
	EXEC_TRAMPOLINE,
	SPLIT_2MB_PAGING_TO_4KB_PAGE,

} POOL_ALLOCATION_INTENTION;

typedef struct _POOL_TABLE
{
	UINT64 Address; // Should be the start of the list as we compute it as the start address
	SIZE_T  Size;
	POOL_ALLOCATION_INTENTION Intention;
	LIST_ENTRY PoolsList;
	BOOLEAN  IsBusy;
	BOOLEAN  ShouldBeFreed;

} POOL_TABLE, * PPOOL_TABLE;


typedef struct _REQUEST_NEW_ALLOCATION
{
	SIZE_T Size0;
	UINT32 Count0;
	POOL_ALLOCATION_INTENTION Intention0;

	SIZE_T Size1;
	UINT32 Count1;
	POOL_ALLOCATION_INTENTION Intention1;

	SIZE_T Size2;
	UINT32 Count2;
	POOL_ALLOCATION_INTENTION Intention2;

	SIZE_T Size3;
	UINT32 Count3;
	POOL_ALLOCATION_INTENTION Intention3;

	SIZE_T Size4;
	UINT32 Count4;
	POOL_ALLOCATION_INTENTION Intention4;

	SIZE_T Size5;
	UINT32 Count5;
	POOL_ALLOCATION_INTENTION Intention5;

	SIZE_T Size6;
	UINT32 Count6;
	POOL_ALLOCATION_INTENTION Intention6;

	SIZE_T Size7;
	UINT32 Count7;
	POOL_ALLOCATION_INTENTION Intention7;

	SIZE_T Size8;
	UINT32 Count8;
	POOL_ALLOCATION_INTENTION Intention8;

	SIZE_T Size9;
	UINT32 Count9;
	POOL_ALLOCATION_INTENTION Intention9;

} REQUEST_NEW_ALLOCATION, * PREQUEST_NEW_ALLOCATION;

typedef struct _VMM_EPT_DYNAMIC_SPLIT{
	DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];
	union{
		PEPT_PML2_ENTRY Entry;
		PEPT_PML2_POINTER Pointer;
	};
	LIST_ENTRY DynamicSplitList;
} VMM_EPT_DYNAMIC_SPLIT, * PVMM_EPT_DYNAMIC_SPLIT;

// Structure for each hooked instance
typedef struct _EPT_HOOKED_PAGE_DETAIL{
	LIST_ENTRY PageHookList;	// must be in first?
	DECLSPEC_ALIGN(PAGE_SIZE) CHAR FakePageContents[PAGE_SIZE];
	// LIST_ENTRY PageHookList;
	UINT64 VirtualAddress;
	SIZE_T PhysicalBaseAddress;
	SIZE_T PhysicalBaseAddressOfFakePageContents;
	PEPT_PML1_ENTRY EntryAddress;
	EPT_PML1_ENTRY OriginalEntry;
	EPT_PML1_ENTRY ChangedEntry;
	PCHAR Trampoline;
	BOOLEAN IsExecutionHook;
} EPT_HOOKED_PAGE_DETAIL, * PEPT_HOOKED_PAGE_DETAIL;

REQUEST_NEW_ALLOCATION* RequestNewAllocation;		// If sb wants allocation from vmx root, adds it's request to this structure
volatile LONG LockForRequestAllocation;
volatile LONG LockForReadingPool;
BOOLEAN IsNewRequestForAllocationRecieved;			// We set it when there is a new allocation
PLIST_ENTRY ListOfAllocatedPoolsHead;				// Create a list from all pools


//////////////////////////////////////////////////
//                   Functions		  			//
//////////////////////////////////////////////////

// Initializes the Pool Manager and pre-allocate some pools
BOOLEAN PoolManagerInitialize();
// Should be called in PASSIVE_LEVEL (vmx non-root), it tries to see whether a new pool request is available, if availabe then allocates it
BOOLEAN PoolManagerCheckAndPerformAllocation();
// If we have request to allocate new pool, we can call this function (should be called from vmx-root), it stores the requests 
// somewhere then when it's safe (IRQL PASSIVE_LEVEL) it allocates the requested pool
BOOLEAN PoolManagerRequestAllocation(SIZE_T Size, UINT32 Count, POOL_ALLOCATION_INTENTION Intention);
// From vmx-root if we need a safe pool address immediately we call it, it also request a new pool if we set RequestNewPool to TRUE
// next time it's safe the pool will be allocated
UINT64 PoolManagerRequestPool(POOL_ALLOCATION_INTENTION Intention, BOOLEAN RequestNewPool, UINT32 Size);
// De-allocate all the allocated pools
VOID PoolManagerUninitialize();