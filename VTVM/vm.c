#include "common.h"
#include "vm.h"
#include "EPT.h"
#include "EptPageHook.h"

int IsSupportVM() {
	CPUID_DATA cpuid_data = {0};

	//1. cpuid vmx bit check
	__cpuid((int*)&cpuid_data, 1);
	if ((cpuid_data.ecx & (1 << 5)) == 0)	return 0;

	//2. bios msr vmx check and change
	IA32_FEATURE_CONTROL_MSR MSRControl = { 0 };

	MSRControl.All = __readmsr(MSR_IA32_FEATURE_CONTROL);
	if (MSRControl.Fields.Lock == 0) {
		MSRControl.Fields.Lock = 1;
		MSRControl.Fields.EnableVmxon = 1;
		__writemsr(MSR_IA32_FEATURE_CONTROL, MSRControl.All);
	}
	else if (MSRControl.Fields.EnableVmxon == 0) {
		DbgPrint("[-]CPU %d %s:VMX EnableVmxon lock off in BIOS", CPU_IDX, __FUNCDNAME__);
		return 0;
	}

	return 1;
	
}



int AllocateVMXONRegion(IN PVM_GLOBAL_DATA vmState_ptr) {
	DbgPrint("\n[+]Current IRQL:%d", KeGetCurrentIrql());

	if (vmState_ptr == NULL) {
		DbgPrint("\n[-]vmState_ptr is NULL");
		return 0;
	}

	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;

	int VMXONSize = 2 * VMXON_SIZE;

	//1. malloc memory
	BYTE* Buffer = MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	//BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

	if (Buffer == NULL) {
		DbgPrint("[*] Error : Couldn't Allocate Buffer for VMXON Region.");
		return FALSE;// ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	}

	//2. Virtual address to Physical address
	//UINT64 PhysicalBuffer = VirtualAddress_to_PhysicallAddress(Buffer);
	UINT64 PhysicalBuffer = VA2PA(Buffer);

	// 3. zero-out memory 
	RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);
	UINT64 alignedPhysicalBuffer = (BYTE*)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) &~ (ALIGNMENT_PAGE_SIZE - 1));

	UINT64 alignedVirtualBuffer = (BYTE*)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) &~ (ALIGNMENT_PAGE_SIZE - 1));

	DbgPrint("[*] Virtual allocated buffer for VMXON at %llx", Buffer);
	DbgPrint("[*] Virtual aligned allocated buffer for VMXON at %llx", alignedVirtualBuffer);
	DbgPrint("[*] Aligned physical buffer allocated for VMXON at %llx", alignedPhysicalBuffer);

	// 4. get IA32_VMX_BASIC_MSR RevisionId

	IA32_VMX_BASIC_MSR basic = { 0 };
	basic.All = __readmsr(MSR_IA32_VMX_BASIC);

	DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

	// 5. Changing Revision Identifier
	*(UINT64*)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;

	//6. execute vmx on
	/* windows kernel don't support C++ exceept */
	try{
		//DbgBreakPoint();	// for debug
		int vmx_on_status = __vmx_on(&alignedPhysicalBuffer);
		if (vmx_on_status) {
			DbgPrint("[*] VMXON failed with status %d\n", vmx_on_status);
			return FALSE;
		}
	}except (EXCEPTION_EXECUTE_HANDLER){
		ULONG ExceptCode = GetExceptionCode();
		DbgPrint("[-] VMXON failed with except code 0x%lx\n", ExceptCode);
		DbgBreakPoint();	// for debug
		return FALSE;
	}
	
	

	vmState_ptr->VMXON_REGION = alignedPhysicalBuffer;
	vmState_ptr->VMXON_VA = Buffer;
	return TRUE;
}

int AllocateVMCSRegion(IN PVM_GLOBAL_DATA vmState_ptr) {
	DbgPrint("\n[+]Current IRQL:%d", KeGetCurrentIrql());
	if (vmState_ptr == NULL) {
		DbgPrint("\n[-]vmState_ptr is NULL");
		return 0;
	}

	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;

	//1. malloc memory
	int VMCSSize = 2 * VMCS_SIZE;
	unsigned char* Buffer = MmAllocateContiguousMemory(VMCSSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	//BYTE* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT_PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

	//2. Virtual to Physical 
	UINT64 PhysicalBuffer = VA2PA(Buffer);
	if (Buffer == NULL) {
		DbgPrint("[*] Error : Couldn't Allocate Buffer for VMCS Region.");
		return FALSE;// ntStatus = STATUS_INSUFFICIENT_RESOURCES;
	}
	//3. zero-out memory 
	RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT_PAGE_SIZE);
	UINT64 alignedPhysicalBuffer = (unsigned char*)((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	UINT64 alignedVirtualBuffer = (unsigned char*)((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));



	DbgPrint("[*] Virtual allocated buffer for VMCS at %llx", Buffer);
	DbgPrint("[*] Virtual aligned allocated buffer for VMCS at %llx", alignedVirtualBuffer);
	DbgPrint("[*] Aligned physical buffer allocated for VMCS at %llx", alignedPhysicalBuffer);

	//4. get IA32_VMX_BASIC_MSR RevisionId
	IA32_VMX_BASIC_MSR basic = { 0 };
	basic.All = __readmsr(MSR_IA32_VMX_BASIC);

	DbgPrint("[*] MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);


	//5. Changing Revision Identifier
	*(UINT64*)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;

	//6. vmx ptrld
	try {
		
		int status = __vmx_vmptrld(&alignedPhysicalBuffer);
		if (status)
		{
			DbgPrint("[*] VMCS failed with status %d\n", status);
			return FALSE;
		}
	}except(EXCEPTION_EXECUTE_HANDLER) {
		ULONG ExceptCode = GetExceptionCode();
		DbgPrint("[-] VMCS failed with except code 0x%lx\n", ExceptCode);
		DbgBreakPoint();	// for debug
		return FALSE;
	}

	vmState_ptr->VMCS_REGION = alignedPhysicalBuffer;
	vmState_ptr->VMCS_VA = Buffer;
	return TRUE;
}

int AllocateVMStack(IN PVM_GLOBAL_DATA vmState_ptr) {
	// Allocate stack for the vm exit handle
	UINT64 VMStackVA = ExAllocatePoolWithTag(NonPagedPool, VMSTACK_SIZE, POOLTAG);
	vmState_ptr->VMStackVA = VMStackVA;

	if (vmState_ptr->VMStackVA == 0) {
		DbgPrint("[-]Error in allocating vm stack\n");
		return 0;
	}
	RtlZeroMemory(vmState_ptr->VMStackVA, VMSTACK_SIZE);
	DbgPrint("[+]vm stack allocate faild\n");
	return 1;
}



UINT64 VMPTRST(){
	PHYSICAL_ADDRESS vmcspa;
	vmcspa.QuadPart = 0;
	__vmx_vmptrst((unsigned __int64*)&vmcspa);

	DbgPrint("[*] VMPTRST %llx\n", vmcspa);

	return 0;
}

int ClearVMCSRegion(IN PVM_GLOBAL_DATA vmState_ptr) {
	// Clear the state of the VMCS to inactive
	int status = __vmx_vmclear(&vmState_ptr->VMCS_REGION);

	DbgPrint("[+] VMCS VMCLAEAR Status is : %d\n", status);
	if (status){
		// Otherwise terminate the VMX
		DbgPrint("[-] VMCS failed to clear with status %d\n", status);
		__vmx_off();
		return FALSE;
	}
	return TRUE;
}


int LoadVMCSPtr(IN PVM_GLOBAL_DATA vmState_ptr) {
	int status = __vmx_vmptrld(&vmState_ptr->VMCS_REGION);

	DbgPrint("[+]Load VMCS, vmptrld Status is : %d\n", status);
	if (status){
		DbgPrint("[-] VMCS failed with status %d\n", status);
		return FALSE;
	}

	return TRUE;
}


int GetSegmentDescriptor(IN PSEGMENT_SELECTOR SegmentSelector, IN USHORT Selector, IN PUCHAR GdtBase) {
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4) {
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10)) { // LA_ACCESSED
		ULONG64 tmp;
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G) {
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}

int SetGuestSelector(IN PVOID GDT_Base, IN ULONG Segment_Register, IN USHORT Selector) {
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            uAccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, GDT_Base);
	uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segment_Register * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segment_Register * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segment_Register * 2, uAccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segment_Register * 2, SegmentSelector.BASE);

	return TRUE;
}

ULONG AdjustControls(IN ULONG Ctl, IN ULONG Msr) {
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

void FillGuestSelectorData(__in PVOID GdtBase, __in ULONG Segreg, __in USHORT Selector) {
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            uAccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}


/* Set Bits for a special address (used on MSR Bitmaps) */
void SetBit(PVOID Addr, UINT64 bit, BOOLEAN Set) {

	UINT64 byte;
	UINT64 temp;
	UINT64 n;
	BYTE* Addr2;

	byte = bit / 8;
	temp = bit % 8;
	n = 7 - temp;

	Addr2 = Addr;

	if (Set)
	{
		Addr2[byte] |= (1 << n);
	}
	else
	{
		Addr2[byte] &= ~(1 << n);
	}
}

/* Get Bits of a special address (used on MSR Bitmaps) */
void GetBit(PVOID Addr, UINT64 bit) {

	UINT64 byte, k;
	BYTE* Addr2;

	byte = 0;
	k = 0;
	byte = bit / 8;
	k = 7 - bit % 8;

	Addr2 = Addr;

	return Addr2[byte] & (1 << k);
}

/* Set bits in Msr Bitmap */
BOOLEAN SetMsrBitmap(ULONG MsrNum, INT ProcessorID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{
	PUCHAR bitMapReadLow = g_VM_DATA_ptr[ProcessorID].MSRBitMapVA;       // read 0x00000000 - 0x00001FFF
	if (!MmIsAddressValid(bitMapReadLow)) {
		DbgPrint("\n[-]MSRBitMapVA is invalid");
		DbgBreakPoint();
	}
	PUCHAR bitMapReadHigh = bitMapReadLow + 1024;   // read 0xC0000000 - 0xC0001FFF
	PUCHAR bitMapWriteLow = bitMapReadHigh + 1024;	// write 0x00000000 - 0x00001FFF
	PUCHAR bitMapWriteHigh = bitMapWriteLow + 1024;	// write 0xC0000000 - 0xC0001FFF

	if (!ReadDetection && !WriteDetection)
	{
		// Invalid Command
		return FALSE;
	}

	if (MsrNum <= 0x00001FFF)
	{
		if (ReadDetection)
		{
			RTL_BITMAP bitMapReadLowHeader = { 0 };
			RtlInitializeBitMap(&bitMapReadLowHeader, (PULONG)bitMapReadLow, 1024);
			RtlSetBit(&bitMapReadLowHeader, MsrNum);
		}
		if (WriteDetection)
		{
			RTL_BITMAP bitMapWriteLowHeader = { 0 };
			RtlInitializeBitMap(&bitMapWriteLowHeader, (PULONG)bitMapWriteLow, 1024);
			RtlSetBit(&bitMapWriteLowHeader, MsrNum);
		}
	}
	else if ((0xC0000000 <= MsrNum) && (MsrNum <= 0xC0001FFF))
	{
		if (ReadDetection)
		{
			RTL_BITMAP bitMapReadHighHeader = { 0 };
			RtlInitializeBitMap(&bitMapReadHighHeader, (PULONG)bitMapReadHigh, 1024);
			RtlSetBit(&bitMapReadHighHeader, MsrNum - 0xC0000000);
		}
		if (WriteDetection)
		{
			RTL_BITMAP bitMapWriteHighHeader = { 0 };
			RtlInitializeBitMap(&bitMapWriteHighHeader, (PULONG)bitMapWriteHigh, 1024);
			RtlSetBit(&bitMapWriteHighHeader, MsrNum - 0xC0000000);
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}
/* Set bits in I/O Bitmap */
BOOLEAN SetIOBitmap(ULONG IOPortNum, INT ProcessorID)
{
	ULONG64 IO_BitmapVA = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * 2, POOLTAG);
	RtlZeroMemory(IO_BitmapVA, PAGE_SIZE * 2);
	RTL_BITMAP bitMapHeader = { 0 };
	RtlInitializeBitMap(&bitMapHeader, (PULONG)IO_BitmapVA, PAGE_SIZE);
	//IN AL, 21H; // read data from 21h prot to AL
	//OUT 21H, AL; // write data of AL to 21h prot
	RtlSetBit(&bitMapHeader, 0x5658);	// vmware check
	/*DbgBreakPoint();*/
	__vmx_vmwrite(IO_BITMAP_A, VA2PA(IO_BitmapVA));
}
/*
save the state of Host and guest
*/
int SetupVMCS(IN PVM_GLOBAL_DATA vmState_ptr) {
	DbgPrint("\n[SetupVMCS()]...");
	int status = 0;

	UINT64 GDTBase = 0;

	SEGMENT_SELECTOR SegmentSelector = { 0 };

	// 1. save host selector
	// Q:Why & 0xf8, the intel cpu must be cleared when you execute vmlaunch 
	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

	// 2. VMCS_LINK_POINTER should be 0xffffffffffffffff, for $KB VMCS
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

	// 3. IA32_DEBUGCTL for GUEST_IA32_DEBUGCTL. don't use so set the value(host) 
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	// 4. TSC Count-time
	/* Time-stamp counter offset */
	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	// 5. configure segment registers and gdt for host
	GDTBase = Get_GDT_Base();
	FillGuestSelectorData((PVOID)GDTBase, ES, GetEs());
	FillGuestSelectorData((PVOID)GDTBase, CS, GetCs());
	FillGuestSelectorData((PVOID)GDTBase, SS, GetSs());
	FillGuestSelectorData((PVOID)GDTBase, DS, GetDs());
	FillGuestSelectorData((PVOID)GDTBase, FS, GetFs());
	FillGuestSelectorData((PVOID)GDTBase, GS, GetGs());
	FillGuestSelectorData((PVOID)GDTBase, LDTR, GetLdtr());
	FillGuestSelectorData((PVOID)GDTBase, TR, GetTr());

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state

	//CPU_BASED_ACTIVATE_SECONDARY_CONTROLS for advoid lots of MSRs access
	//__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_IO_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
	// __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));

	//CPU_BASED_CTL2_RDTSCP to Enable RDTSCP
	//CPU_BASED_CTL2_ENABLE_INVPCID to Enable INVPCID, win 10 1809
	//CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS to Enable XSAVE XRSTORS, win 10 1809

	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP |
		CPU_BASED_CTL2_ENABLE_EPT | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));


	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	
	// orign code
	///*
	__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));
	//*/
	/*
	// load the EFER MSR
	__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_EFER, MSR_IA32_VMX_ENTRY_CTLS));
	__vmx_vmwrite(VMCS_GUEST_IA32_EFER, __readmsr(MSR_EFER));
	// save the EFER MSR
	__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_SAVE_EFER, MSR_IA32_VMX_EXIT_CTLS));
	*/

	//CR3 - Target Controls
	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);


	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_DR7, 0x400);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	//__vmx_vmwrite(HOST_CR3, __readcr3());	// change cr3 to HostCr3
	__vmx_vmwrite(HOST_CR3, HostCr3);
	__vmx_vmwrite(HOST_CR4, __readcr4());


	__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);

	__vmx_vmwrite(CR0_READ_SHADOW, 0);
	__vmx_vmwrite(CR4_READ_SHADOW, 0);


	// segment 
	__vmx_vmwrite(GUEST_GDTR_BASE, Get_GDT_Base());
	__vmx_vmwrite(GUEST_IDTR_BASE, Get_IDT_Base());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, Get_GDT_Limit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, Get_IDT_Limit());

	__vmx_vmwrite(GUEST_RFLAGS, Get_RFLAGS());

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)Get_GDT_Base());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, Get_GDT_Base());
	__vmx_vmwrite(HOST_IDTR_BASE, Get_IDT_Base());

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	// 7.7 set MSR Bitmaps
	//SetMsrBitmap(MSR_LSTAR, CPU_IDX, TRUE, TRUE);
	//SetMsrBitmap(MSR_EFER, CPU_IDX, TRUE, TRUE);

	__vmx_vmwrite(MSR_BITMAP, vmState_ptr->MSRBitMapPA);
	// 7.8 Set up EPT 
	__vmx_vmwrite(EPT_POINTER, g_EPT_State_ptr->EptPointer.All);

	// 7.9 vm exit, host exec 
	__vmx_vmwrite(HOST_RSP, ((ULONG64)vmState_ptr->VMStackVA + VMSTACK_SIZE - 1));
	__vmx_vmwrite(HOST_RIP, (ULONG64)VMExitHandler);	// a callback function, for handle vm exit

	// 8. for interrupt/exception
	//__vmx_vmwrite(EXCEPTION_BITMAP, 0x8);	// #bp
	//__vmx_vmwrite(EXCEPTION_BITMAP, 72);	// #bp and #ud
	/*
	MSR_IA32_EFER msr_ia32_efer;
	msr_ia32_efer.All = __readmsr(MSR_EFER);
	msr_ia32_efer.Fields.SCE = 0;
	__vmx_vmwrite(MSR_EFER, msr_ia32_efer.All);
	__vmx_vmwrite(EXCEPTION_BITMAP, 64);	// #bp
	*/
	//9. set I/O Bitmaps, 8k size, I/O Bitmap A: 0~0x7ffff; I/O Btimap B: 0x8000~0xffff
	
		
	status = TRUE;
	DbgPrint("\n[+]SetupVMCS() Success\n");

	return status;
}

// handle vm exit of the control register access, MOV from CR3/CR8, MOV to CR0/1/3/4/8
// more detail informations, see intel manual v3b of the sdm, chapter 22
// https://community.intel.com/t5/Software-Archive/Avoiding-vmexit-on-control-register-accesses/td-p/783570
void HandleCrAccess(PGUEST_REGS GuestRegs, ULONG ExitQualification) {
	PMOV_CR MovCrExitQualificationPtr = (PMOV_CR)&ExitQualification;
	PULONG64 RegPtr;
	UINT64 GuestRsp = 0;

	RegPtr = (PULONG64)&(GuestRegs->rax) + MovCrExitQualificationPtr->Fields.Register;

	//repair guest rsp
	// * windows uses "mov cr3,rsp" to meltdown mitigation 
	if (MovCrExitQualificationPtr->Fields.Register == 4) {
		__vmx_vmread(GUEST_RSP, &GuestRsp);
		*RegPtr = GuestRsp;
	}
	switch (MovCrExitQualificationPtr->Fields.AccessType){
		case TYPE_MOV_TO_CR:
			switch (MovCrExitQualificationPtr->Fields.ControlRegister){
				case 0:
					//mov to cr0 case vm exit but not cr0 mask is 0
					__vmx_vmwrite(GUEST_CR0, *RegPtr);
					__vmx_vmwrite(CR0_READ_SHADOW, *RegPtr);
					break;
				case 3:
					__vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));
					
					// DbgPrint("\n[-]cr need more handle to...todo\n");
					// DbgBreakPoint();
					// InveptSingleContext(EptState->EptPointer.Flags); (changed, look for "Update 1" at the 8th part for more detail)
					//InvvpidSingleContext(VPID_TAG);
					break;
				case 4:
					__vmx_vmwrite(GUEST_CR4, *RegPtr);
					__vmx_vmwrite(CR4_READ_SHADOW, *RegPtr);

					break;
				default:
					DbgPrint("\n[-]Unsupported mov to register %d in handle cr access\n", MovCrExitQualificationPtr->Fields.ControlRegister);
					break;
			}
			break;
		case TYPE_MOV_FROM_CR:
			switch (MovCrExitQualificationPtr->Fields.ControlRegister){
				case 0:
					__vmx_vmread(GUEST_CR0, RegPtr);
					break;
				case 3:
					__vmx_vmread(GUEST_CR3, RegPtr);
					break;
				case 4:
					// mov from cr4 never causes a VM exit?
					__vmx_vmread(GUEST_CR4, RegPtr);
					break;
				case 8:

					break;
				default:
					DbgPrint("\n[-]Unsupported mov from register %d in handle cr access\n", MovCrExitQualificationPtr->Fields.ControlRegister);
					break;
			}
			break;
		default:
			DbgPrint("[-]Unsupported operation %d in handle cr access", MovCrExitQualificationPtr->Fields.AccessType);
			break;
	}
}

void HandleCPUID(PGUEST_REGS state){
	INT32 cpu_info[4];
	ULONG Mode = 0;
	__vmx_vmread(GUEST_CS_SELECTOR, &Mode);
	Mode = Mode & RPL_MASK;

	//
	if ((state->rax == 0x41414141) && (state->rcx == 0x42424242) && Mode == DPL_SYSTEM){
		return ; // Indicates we have to turn off VMX
	}

	// Otherwise, issue the CPUID to the logical processor based on the indexes
	// on the VP's GPRs.
	__cpuidex(cpu_info, (INT32)state->rax, (INT32)state->rcx);

	// Check if this was CPUID 1h, which is the features request.
	if (state->rax == 1){
		// Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
		// reserved for this indication.
		cpu_info[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
	}else if (state->rax == HYPERV_CPUID_INTERFACE){
		// Return our interface identifier
		cpu_info[0] = 'VTVM'; // [H]yper[v]isor [F]rom [S]cratch
		DbgPrint("\n[+]handle test cpuid");
	}

	// Copy the values from the logical processor registers into the VP GPRs.
	state->rax = cpu_info[0];
	state->rbx = cpu_info[1];
	state->rcx = cpu_info[2];
	state->rdx = cpu_info[3];

	//return FALSE; // Indicates we don't have to turn off VMX
}


void HandleMSRRead(PGUEST_REGS GuestRegs) {
	MSR msr = { 0 };
	ULONG MSR_Num = (ULONG)GuestRegs->rcx;
	ULONG64 GuestRip;
	// RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
	// 
	// The "use MSR bitmaps" VM-execution control is 0.
	// The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
	// The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
	//   where n is the value of ECX.
	// The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
	//   where n is the value of ECX & 00001FFFH.

	if ((MSR_Num <= 0x00001FFF) || ((0xC0000000 <= MSR_Num) && (MSR_Num <= 0xC0001FFF)))
	{
		switch (MSR_Num)
		{
		case MSR_EFER:
			// read EFER MSR
			__vmx_vmread(GUEST_RIP, &GuestRip);
			DbgPrint("\n[+]Catch Read EFER MSR Hit (Process Id : 0x%x) at : 0x%llx ", PsGetCurrentProcessId(), GuestRip);
			MSR_IA32_EFER msr_ia32_efer;
			msr_ia32_efer.All = __readmsr(MSR_EFER);

			DbgPrint("\n[+]Host EFER MSR SCE bit 0x%x", msr_ia32_efer.Fields.SCE);
			__vmx_vmread(VMCS_GUEST_IA32_EFER, &(msr_ia32_efer));
			DbgPrint("\n[+]Guest EFER MSR SCE bit 0x%x", msr_ia32_efer.Fields.SCE);
			msr_ia32_efer.Fields.SCE = 0;
			__vmx_vmwrite(VMCS_GUEST_IA32_EFER, msr_ia32_efer.All);


			DbgBreakPoint();
			break;
		default:
			break;
		}
		msr.Content = MSRRead(MSR_Num);
		
	}
	else
	{
		msr.Content = 0;
	}

	GuestRegs->rax = msr.Low;
	GuestRegs->rdx = msr.High;
}

void HandleMSRWrite(PGUEST_REGS GuestRegs){
	MSR msr = { 0 };
	ULONG MSR_Num = (ULONG)GuestRegs->rcx;
	ULONG64 GuestRip;
	// Check for sanity of MSR 
	if ((MSR_Num <= 0x00001FFF) || ((0xC0000000 <= MSR_Num) && (MSR_Num <= 0xC0001FFF)))
	{
		switch (MSR_Num)
		{
		case MSR_EFER:
			// write EFER MSR
			__vmx_vmread(GUEST_RIP, &GuestRip);
			DbgPrint("\n[+]Catch write EFER MSR Hit (Process Id : 0x%x) at : 0x%llx ", PsGetCurrentProcessId(), GuestRip);
			MSR_IA32_EFER msr_ia32_efer;
			msr_ia32_efer.All = __readmsr(MSR_EFER);
			msr_ia32_efer.Fields.SCE = 1;
			//__vmx_vmwrite(MSR_EFER, msr_ia32_efer.All);
			__vmx_vmwrite(VMCS_GUEST_IA32_EFER, msr_ia32_efer.All);
			DbgBreakPoint();
			break;
		default:
			break;
		}
		msr.Low = (ULONG)GuestRegs->rax;
		msr.High = (ULONG)GuestRegs->rdx;
		MSRWrite((ULONG)GuestRegs->rcx, msr.Content);
	}

}

/*
* 
*/
BOOLEAN HandleVMCALL(PGUEST_REGS GuestRegs) {
	ULONG64 VmcallNumber = GuestRegs->rcx;
	ULONG64 OptionalParam1 = GuestRegs->rdx;
	UINT64 OptionalParam2 = GuestRegs->r8;
	UINT64 OptionalParam3 = GuestRegs->r9;

	BOOLEAN HookResult;
	BOOLEAN UnsetExec, UnsetWrite, UnsetRead;
	switch (GuestRegs->rcx & 0xffffffff){
	case VMCALL_TEST:
		DbgPrint("\n[+][Root]Just for test vmcall");
		GuestRegs->rax = 1;
		break;
	case VMCALL_VMXOFF:
		DbgPrint("\n[+][Root]recv vmcall vmoff");
		// todo...
		break;
	case VMCALL_CHANGE_PAGE_ATTRIB: {
		// Upper 32 bits of the Vmcall contains the attribute mask
		UINT32 AttributeMask = (UINT32)((VmcallNumber & 0xFFFFFFFF00000000LL) >> 32);

		UnsetExec = UnsetWrite = UnsetRead = FALSE;

		if (AttributeMask & PAGE_ATTRIB_READ) UnsetRead = TRUE;
		if (AttributeMask & PAGE_ATTRIB_WRITE) UnsetWrite = TRUE;
		if (AttributeMask & PAGE_ATTRIB_EXEC) UnsetExec = TRUE;
		HookResult = EptPerformPageHook(OptionalParam1 /* TargetAddress */, OptionalParam2 /* Hook Function*/,
			OptionalParam3 /* OrigFunction */, UnsetRead, UnsetWrite, UnsetExec);

		if (HookResult)	GuestRegs->rax = 1;
		else {
			GuestRegs->rax = 0;
			return FALSE;
		}
		break;
	}
	case VMCALL_INVEPT_ALL_CONTEXTS:
		InveptAllContexts();
		break;
	case VMCALL_INVEPT_SINGLE_CONTEXT:
		InveptAllContexts(OptionalParam1);
		break;
	default:
		DbgPrint("\n[-]Unknown vmcall number");
		return FALSE;
		break;
	}

	return TRUE;
}

BOOLEAN HandleEptViolation(PGUEST_REGS GuestRegs) {
	VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification;
	ULONG64 GuestPA = 0;
	ULONG64 GuestRip;
	SIZE_T GuestPhysicalAddress;
	PLIST_ENTRY TempList = 0;
	PEPT_PML1_ENTRY TargetPage;

	ULONG64 ExactAccessedAddress;

	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPA);
	__vmx_vmread(EXIT_QUALIFICATION, &(ViolationQualification.All));
	__vmx_vmread(GUEST_RIP, &GuestRip);
	GuestPhysicalAddress = PAGE_ALIGN(GuestPA);

	if (!GuestPhysicalAddress){
		DbgPrint("[-]Target address could not be mapped to physical memory");
		DbgBreakPoint();
		return FALSE;
	}

	// handle hooked page
	TempList = &(g_EPT_State_ptr->HookedPagesList);
	PLIST_ENTRY ListHead = &(g_EPT_State_ptr->HookedPagesList);
	// 1.query hooked page list
	while (ListHead != TempList->Flink) {
		TempList = TempList->Flink;
		PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);
		ULONG64 AlignedVirtualAddress = PAGE_ALIGN(HookedEntry->VirtualAddress);
		ULONG64 AlignedPhysicalAddress = PAGE_ALIGN(GuestPhysicalAddress);

		if (HookedEntry->PhysicalBaseAddress == AlignedPhysicalAddress) {
			ExactAccessedAddress = AlignedVirtualAddress + GuestPhysicalAddress - AlignedPhysicalAddress;
			if (!ViolationQualification.Fields.EptExecutable && ViolationQualification.Fields.ExecuteAccess){
				DbgPrint("\n[+]Guest RIP : 0x%llx tries to execute the page at : 0x%llx", GuestRip, ExactAccessedAddress);

			}else if (!ViolationQualification.Fields.EptWriteable && ViolationQualification.Fields.WriteAccess){
				DbgPrint("\n[+]Guest RIP : 0x%llx tries to write on the page at :0x%llx", GuestRip, ExactAccessedAddress);
			}else if (!ViolationQualification.Fields.EptReadable && ViolationQualification.Fields.ReadAccess){
				DbgPrint("\n[+]Guest RIP : 0x%llx tries to read the page at :0x%llx", GuestRip, ExactAccessedAddress);
			}else{
				// there was an unexpected ept violation
				DbgPrint("\n[-]Invalid page swapping logic in hooked page, there was an unexpected ept violation");
				return FALSE;
			}
			//DbgBreakPoint();	//for test

			EptSetPML1AndInvalidateTLB(HookedEntry->EntryAddress, HookedEntry->OriginalEntry, INVEPT_SINGLE_CONTEXT);
			g_VM_DATA_ptr[KeGetCurrentProcessorNumber()].MtfEptHookRestorePoint = HookedEntry;

			// We have to set Monitor trap flag and give it the HookedEntry to work with
			SetMonitorTrapFlag(TRUE);
		}
	}
	// redo the instruction
	g_VM_DATA_ptr[KeGetCurrentProcessorNumber()].IncrementRip = FALSE;

	/*
	TargetPage = EptGetPml1Entry(g_EPT_State_ptr->EptPageTable, GuestPhysicalAddress);
	if (!TargetPage) {
		DbgPrint("\n[-]Failed to get PML1 entry for target address");
		return FALSE;
	}

	
	if (!ViolationQualification.Fields.EptExecutable && ViolationQualification.Fields.ExecuteAccess){
		TargetPage->Fields.Execute = 1;

		 InveptAllContexts();
		INVEPT_DESCRIPTOR Descriptor;

		Descriptor.EptPointer = g_EPT_State_ptr->EptPointer.All;
		Descriptor.Reserved = 0;
		AsmInvept(1, &Descriptor);

		// Redo the instruction 
		//g_VM_DATA_ptr[KeGetCurrentProcessorNumber()].IncrementRip = FALSE; //todo

		DbgPrint("\n[+]Set the Execute Access of a page (PFN = 0x%llx) to 1", TargetPage->Fields.PhysicalAddress);

		return TRUE;
	}
	*/

	

	return TRUE;
	

}
#define IS_SYSRET_INSTRUCTION(Code) \
    (*((PUINT8)(Code) + 0) == 0x48 && \
     *((PUINT8)(Code) + 1) == 0x0F && \
     *((PUINT8)(Code) + 2) == 0x07)
#define IS_SYSCALL_INSTRUCTION(Code) \
    (*((PUINT8)(Code) + 0) == 0x0F && \
     *((PUINT8)(Code) + 1) == 0x05)
/*
* 1. handle vm exit by exit reason
* 2. restore to guest next instruction
*/
int MainVMExitHandler(PGUEST_REGS GuestRegs) {
	ULONG Rflags = 0;
	ULONG ExitReason = 0;
	ULONG ExitQualification = 0;
	ULONG ExitInsLen = 0;
	//rip is 64 bits
	ULONG64 CurrentGuestRIP = 0;
	ULONG64 CurrentGuestRsp = 0;
	ULONG CurrentCpuIndex = KeGetCurrentProcessorIndex();

	__vmx_vmread(VM_EXIT_REASON, &ExitReason);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInsLen);
	__vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);
	__vmx_vmread(GUEST_RIP, &CurrentGuestRIP);
	__vmx_vmread(GUEST_RSP, &CurrentGuestRsp);

	ExitReason &= 0xffff;
	g_VM_DATA_ptr[CurrentCpuIndex].IsOnVmRootMode = TRUE;
	g_VM_DATA_ptr[CurrentCpuIndex].IncrementRip = TRUE;
	//DbgPrint("\n[+]VM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
	//DbgPrint("[+]EXIT_QUALIFICATION 0x%x\n", ExitQualification);

	//DbgBreakPoint();
	//See intel manual 25.1.2
	switch (ExitReason) {
		// vm instruction exit
		case EXIT_REASON_VMCLEAR:
		case EXIT_REASON_VMPTRLD:
		case EXIT_REASON_VMPTRST:
		case EXIT_REASON_VMREAD:
		case EXIT_REASON_VMRESUME:
		case EXIT_REASON_VMWRITE:
		case EXIT_REASON_VMXOFF:
			DbgPrint("\n[+]vmx off");
			return FALSE;
		case EXIT_REASON_VMXON:
		case EXIT_REASON_VMLAUNCH: {
			DbgPrint("[-]Another vm operate, EXIT_REASON:0x%llx, CurrentRip:0x%llx", ExitReason, CurrentGuestRIP);
			DbgBreakPoint();
			__vmx_vmread(GUEST_RFLAGS, &Rflags);
			//if cf = 1, vm instruction faild
			__vmx_vmwrite(GUEST_RFLAGS, Rflags | 0x1);

			break;
		}
		case EXIT_REASON_VMCALL:
			HandleVMCALL(GuestRegs);
			break;
		case EXIT_REASON_CPUID:
			HandleCPUID(GuestRegs);
			break;
		case EXIT_REASON_HLT:
			//DbgPrint("[+]Detact HLT ... \n");
			break;
		case EXIT_REASON_CR_ACCESS:
			//DbgPrint("[+]Detact cr access\n");
			HandleCrAccess(GuestRegs, ExitQualification);
			break;
		case EXIT_REASON_IO_INSTRUCTION:
			DbgPrint("\n[+]Catch I/O Hit (Process Id : 0x%x) at : 0x%llx ", PsGetCurrentProcessId(), CurrentGuestRIP);
			break;
		// handle msr read/write
		case EXIT_REASON_MSR_READ: {
			ULONG ECX = GuestRegs->rcx & 0xffffffff;
			//DbgPrint("[*] RDMSR (based on bitmap) : 0x%llx\n", ECX);
			HandleMSRRead(GuestRegs);
			break;
		}
		case EXIT_REASON_MSR_LOADING:
			DbgPrint("[*] MSR_LOADING");
			break;
		case EXIT_REASON_MSR_WRITE: {
			ULONG ECX = GuestRegs->rcx & 0xffffffff;
			//DbgPrint("[*] WRMSR (based on bitmap) : 0x%llx\n", ECX);
			HandleMSRWrite(GuestRegs);
			break;
		}
		case EXIT_REASON_TRIPLE_FAULT:
			// Close Page? meltdown error 
			DbgBreakPoint();
			break;
		case EXIT_REASON_EPT_VIOLATION:
			// EPT violation
			HandleEptViolation(GuestRegs);
			break;
		case EXIT_REASON_EPT_MISCONFIG:
			// EPT misconfig
			DbgPrint("[-]EPT Misconfiguration!");
			//DbgPrint("[-]A field in the EPT paging structure was invalid, Faulting guest address : 0x%llx", GuestAddress);
			DbgBreakPoint();
			break;
		case EXIT_REASON_EXCEPTION_NMI: {
			// for Interrupt/Exception hook
			VMEXIT_INTERRUPT_INFO vmexit_intr_info;
			__vmx_vmread(VM_EXIT_INTR_INFO, &vmexit_intr_info);
			
			if (vmexit_intr_info.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION && vmexit_intr_info.Vector == EXCEPTION_VECTOR_BREAKPOINT){
				// Send the user
				DbgPrint("\n[+]Catch Breakpoint Hit (Process Id : 0x%x) at : 0x%llx ", PsGetCurrentProcessId(), CurrentGuestRIP);
				//DbgBreakPoint();
				// re-inject #BP,pass to the guest
				InjectBreakpoint();
				g_VM_DATA_ptr[CurrentCpuIndex].IncrementRip = FALSE;
			}
			else if (vmexit_intr_info.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION && vmexit_intr_info.Vector == EXCEPTION_VECTOR_UNDEFINED_OPCODE) {
				//is syscall/sysret
				if (IS_SYSCALL_INSTRUCTION(CurrentGuestRIP))
				{
					DbgPrint("\n[+]Catch #UD (Process Id : 0x%x) sysret at : 0x%llx ", PsGetCurrentProcessId(), CurrentGuestRIP);
					ULONG64 guest_cr3;
					__vmx_vmread(GUEST_CR3, &guest_cr3);
					if (guest_cr3 & 0xfff) {
						DbgPrint("\n[+]pcid??todo...");
					}

					//emulate syscall

					DbgBreakPoint();
				}
				else if (IS_SYSRET_INSTRUCTION(CurrentGuestRIP)) {
					DbgPrint("\n[+]Catch #UD (Process Id : 0x%x) sysret at : 0x%llx ", PsGetCurrentProcessId(), CurrentGuestRIP);
					// handle KVAS, user mode is a table, kernel mode is a table
					ULONG64 guest_cr3;
					__vmx_vmread(GUEST_CR3, &guest_cr3);
					if (guest_cr3 & 0xfff) {
						DbgPrint("\n[+]pcid??todo...");
					}

					/*
					//emulate sysret, todo 
					//1. load rip from rcx
					__vmx_vmwrite(GUEST_RIP, GuestRegs->rcx);

					//2. Load RFLAGS from R11.Clear RF, VM, reserved bits.
					//ULONG64 RFLAGS = (GuestRegs->r11 & ~ (X86_FLAGS_RF | X86_FLAGS_VM | X86_FLAGS_RESERVED_BITS)) | X86_FLAGS_FIXED;
					ULONG64 RFLAGS = (GuestRegs->r11 & ~0x17);
					__vmx_vmwrite(GUEST_RFLAGS, RFLAGS);
					SEGMENT_ATTRIBUTES Cs, Ss;
					// 3.cs ss
					ULONG STAR_Value = __readmsr(MSR_STAR);
					Cs.Selector = (UINT16)(((STAR_Value >> 48) + 16) | 3);    // (STAR[63:48]+16) | 3 (* RPL forced to 3 *)
					Cs.Base = 0;                                            // Flat segment
					Cs.Limit = (UINT32)~0;                                  // 4GB limit
					Cs.Attributes = 0xAFB;                                  // L+DB+P+S+DPL3+Code
					__vmx_vmwrite(GUEST_CS_SELECTOR, Cs);
					VmcsWriteSegment(X86_REG_CS, &Cs);
					Ss.Selector = (UINT16)(((MsrValue >> 48) + 8) | 3);     // (STAR[63:48]+8) | 3 (* RPL forced to 3 *)
					Ss.Base = 0;                                            // Flat segment
					Ss.Limit = (UINT32)~0;                                  // 4GB limit
					Ss.Attributes = 0xCF3;                                  // G+DB+P+S+DPL3+Data
					VmcsWriteSegment(X86_REG_SS, &Ss);
					*/

					DbgBreakPoint();
				}
				else {
					// re-inject #UD, pass to the guest
					InjectInterruption(INTERRUPT_TYPE_HARDWARE_EXCEPTION, EXCEPTION_VECTOR_UNDEFINED_OPCODE, FALSE, 0);
					UINT32 ExitInstrLength;
					__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstrLength);
					__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, ExitInstrLength);
					g_VM_DATA_ptr[KeGetCurrentProcessorIndex()].IncrementRip = FALSE;
				}

			}
			else{
				
				DbgPrint("\n[+]Catch InterruptionType:%d, Vector:%d\n", vmexit_intr_info.InterruptionType, vmexit_intr_info.Vector);
				DbgPrint("\n[+]Expected event not handled");
				DbgBreakPoint();
			}

			break;
		}
		case EXIT_REASON_MONITOR_TRAP_FLAG:
			/* Monitor Trap Flag */
			if (g_VM_DATA_ptr[CurrentCpuIndex].MtfEptHookRestorePoint)
			{
				//DbgPrint("\n[+]EXIT_REASON_MONITOR_TRAP_FLAG, handle EptPageHook");
				// restore the hooked state
				PEPT_HOOKED_PAGE_DETAIL HookedEntry = g_VM_DATA_ptr[CurrentCpuIndex].MtfEptHookRestorePoint;
				EptSetPML1AndInvalidateTLB(HookedEntry->EntryAddress, HookedEntry->ChangedEntry, INVEPT_SINGLE_CONTEXT);
				// Set it to NULL
				g_VM_DATA_ptr[CurrentCpuIndex].MtfEptHookRestorePoint = NULL;
			}
			else
			{
				DbgPrint("\n[-]Why MTF occured ?!");
				DbgBreakPoint();
			}

			// Redo the instruction 
			g_VM_DATA_ptr[CurrentCpuIndex].IncrementRip = FALSE;
			SetMonitorTrapFlag(FALSE);
			
			break;
		case EXIT_REASON_INVALID_GUEST_STATE:
			DbgPrint("\n[-]Invalid guest state");
			DbgBreakPoint();
			break;
		default:
			DbgPrint("\n[-]Unhandler vm exit: 0x%llx", ExitReason);
			DbgBreakPoint();	// for debug
			//IsExitVM = 1;
			return FALSE;
			break;
	}

	// 2. restore to next guest instruction or not()
	if (g_VM_DATA_ptr[CurrentCpuIndex].IncrementRip) {
		__vmx_vmwrite(GUEST_RIP, CurrentGuestRIP + ExitInsLen);
	}
	g_VM_DATA_ptr[CurrentCpuIndex].IsOnVmRootMode = FALSE;
	return TRUE;
}

void VM_Resumer(){
	// * be careful, don't set vm state or EXIT_REASON_TRIPLE_FAULT bsod
	__vmx_vmresume();
	
	// if VMRESUME succeed will never execute next !
	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	//g_VM_DATA_ptr[KeGetCurrentProcessorIndex()].IsOnVmRootMode = FALSE;
	__vmx_off();
	//g_VM_DATA_ptr[KeGetCurrentProcessorIndex()].HasLaunched = FALSE;
	DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

	// It's such a bad error because we don't where to go !
	// prefer to break
	DbgBreakPoint();
}
