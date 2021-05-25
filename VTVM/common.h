#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <intrin.h>
#include "GetInsLen.h"
#include "PoolManager.h"

#define CPU_IDX	(KeGetCurrentProcessorNumberEx( NULL ))

// MTRR Physical Base MSRs
#define MSR_IA32_MTRR_PHYSBASE0 0x00000200
#define MSR_IA32_MTRR_PHYSBASE1 0x00000202
#define MSR_IA32_MTRR_PHYSBASE2 0x00000204
#define MSR_IA32_MTRR_PHYSBASE3 0x00000206
#define MSR_IA32_MTRR_PHYSBASE4 0x00000208
#define MSR_IA32_MTRR_PHYSBASE5 0x0000020A
#define MSR_IA32_MTRR_PHYSBASE6 0x0000020C
#define MSR_IA32_MTRR_PHYSBASE7 0x0000020E
#define MSR_IA32_MTRR_PHYSBASE8 0x00000210
#define MSR_IA32_MTRR_PHYSBASE9 0x00000212

// MTRR Physical Mask MSRs
#define MSR_IA32_MTRR_PHYSMASK0 0x00000201
#define MSR_IA32_MTRR_PHYSMASK1 0x00000203
#define MSR_IA32_MTRR_PHYSMASK2 0x00000205
#define MSR_IA32_MTRR_PHYSMASK3 0x00000207
#define MSR_IA32_MTRR_PHYSMASK4 0x00000209
#define MSR_IA32_MTRR_PHYSMASK5 0x0000020B
#define MSR_IA32_MTRR_PHYSMASK6 0x0000020D
#define MSR_IA32_MTRR_PHYSMASK7 0x0000020F
#define MSR_IA32_MTRR_PHYSMASK8 0x00000211
#define MSR_IA32_MTRR_PHYSMASK9 0x00000213

// Memory Types, Memory Types that can be encoded in MTRRs
#define MEMORY_TYPE_UNCACHEABLE 0x00000000
#define MEMORY_TYPE_WRITE_COMBINING 0x00000001
#define MEMORY_TYPE_WRITE_THROUGH 0x00000004
#define MEMORY_TYPE_WRITE_PROTECTED 0x00000005
#define MEMORY_TYPE_WRITE_BACK 0x00000006
#define MEMORY_TYPE_INVALID 0x000000FF


#define MSR_IA32_MTRR_DEF_TYPE 0x000002FF // MTRR Def MSR
#define MSR_IA32_MTRR_CAPABILITIES 0x000000FE // MTRR Capabilities MSR

#define MSR_APIC_BASE                       0x01B
#define MSR_IA32_FEATURE_CONTROL            0x03A

#define MSR_IA32_VMX_BASIC                  0x480
#define MSR_IA32_VMX_PINBASED_CTLS          0x481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x482
#define MSR_IA32_VMX_EXIT_CTLS              0x483
#define MSR_IA32_VMX_ENTRY_CTLS             0x484
#define MSR_IA32_VMX_MISC                   0x485
#define MSR_IA32_VMX_CR0_FIXED0             0x486
#define MSR_IA32_VMX_CR0_FIXED1             0x487
#define MSR_IA32_VMX_CR4_FIXED0             0x488
#define MSR_IA32_VMX_CR4_FIXED1             0x489
#define MSR_IA32_VMX_VMCS_ENUM              0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x490
#define MSR_IA32_VMX_VMFUNC                 0x491

#define MSR_IA32_SYSENTER_CS                0x174
#define MSR_IA32_SYSENTER_ESP               0x175
#define MSR_IA32_SYSENTER_EIP               0x176
#define MSR_IA32_DEBUGCTL                   0x1D9

/* CPU model specific register (MSR) numbers */
/* x86-64 specific MSRs */
#define MSR_EFER	0xc0000080 /* extended feature register */
#define MSR_STAR	0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR	0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR	0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK	0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE	0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE	0xc0000101 /* 64bit GS base */
#define MSR_KERNEL_GS_BASE	0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX	0xc0000103 /* Auxiliary TSC */

// PIN-Based Execution
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT				 0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING						 0x00000004
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI						 0x00000010
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER				 0x00000020 
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS        0x00000040


#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_CTL2_ENABLE_EPT			0x2
#define CPU_BASED_CTL2_RDTSCP				0x8
#define CPU_BASED_CTL2_ENABLE_VPID			0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST	0x80
#define CPU_BASED_CTL2_VIRTUAL_INTERRUPT_DELIVERY	0x200
#define CPU_BASED_CTL2_ENABLE_INVPCID		0x1000
#define CPU_BASED_CTL2_ENABLE_VMFUNC		0x2000
#define CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS	0x100000

typedef enum _CPU_VENDOR {
	cpu_other = 0,
	cpu_intel,
	cpu_amd
}CPU_VENDOR;

typedef union _IA32_VMX_EPT_VPID_CAP_REGISTER{
	struct{
		UINT64 ExecuteOnlyPages : 1;
		UINT64 Reserved1 : 5;
		UINT64 PageWalkLength4 : 1;
		UINT64 Reserved2 : 1;
		UINT64 MemoryTypeUncacheable : 1;
		UINT64 Reserved3 : 5;
		UINT64 MemoryTypeWriteBack : 1;
		UINT64 Reserved4 : 1;
		UINT64 Pde2MbPages : 1;
		UINT64 Pdpte1GbPages : 1;
		UINT64 Reserved5 : 2;
		UINT64 Invept : 1;
		UINT64 EptAccessedAndDirtyFlags : 1;
		UINT64 AdvancedVmexitEptViolationsInformation : 1;
		UINT64 Reserved6 : 2;
		UINT64 InveptSingleContext : 1;
		UINT64 InveptAllContexts : 1;
		UINT64 Reserved7 : 5;
		UINT64 Invvpid : 1;
		UINT64 Reserved8 : 7;
		UINT64 InvvpidIndividualAddress : 1;
		UINT64 InvvpidSingleContext : 1;
		UINT64 InvvpidAllContexts : 1;
		UINT64 InvvpidSingleContextRetainGlobals : 1;
		UINT64 Reserved9 : 20;
	};
	UINT64 Flags;
} IA32_VMX_EPT_VPID_CAP_REGISTER, * PIA32_VMX_EPT_VPID_CAP_REGISTER;

// MSR_IA32_MTRR_DEF_TYPE
typedef union _IA32_MTRR_DEF_TYPE_REGISTER {
	UINT64 Flags;
	struct {
		UINT64 DefaultMemoryType : 3;
		UINT64 Reserved1 : 7;
		UINT64 FixedRangeMtrrEnable : 1;
		UINT64 MtrrEnable : 1;
		UINT64 Reserved2 : 52;
	}Fields;
}IA32_MTRR_DEF_TYPE_REGISTER, * PIA32_MTRR_DEF_TYPE_REGISTER;

// MSR_IA32_MTRR_CAPABILITIES
typedef union _IA32_MTRR_CAPABILITIES_REGISTER
{
	UINT64 Flags;
	struct{
		UINT64 VariableRangeCount : 8;
		UINT64 FixedRangeSupported : 1;
		UINT64 Reserved1 : 1;
		UINT64 WcSupported : 1;
		UINT64 SmrrSupported : 1;
		UINT64 Reserved2 : 52;
	};
} IA32_MTRR_CAPABILITIES_REGISTER, * PIA32_MTRR_CAPABILITIES_REGISTER;

// MSR_IA32_MTRR_PHYSBASE(0-9)
typedef union _IA32_MTRR_PHYSBASE_REGISTER{
	UINT64 Flags;
	struct{
		/* [Bits 7:0] Specifies the memory type for the range.*/
		UINT64 Type : 8;
		UINT64 Reserved1 : 4;
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved2 : 16;
	};
} IA32_MTRR_PHYSBASE_REGISTER, * PIA32_MTRR_PHYSBASE_REGISTER;


// MSR_IA32_MTRR_PHYSMASK(0-9).
typedef union _IA32_MTRR_PHYSMASK_REGISTER
{
	struct{
		/* [Bits 7:0] Specifies the memory type for the range. */
		UINT64 Type : 8;
		UINT64 Reserved1 : 3;
		UINT64 Valid : 1;
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved2 : 16;
	};

	UINT64 Flags;
} IA32_MTRR_PHYSMASK_REGISTER, * PIA32_MTRR_PHYSMASK_REGISTER;

//describes the state of our virtual machine
typedef struct _VM_GLOBAL_DATA {
	//CPU_VENDOR CPUVendor;
	BOOLEAN HasLaunched;
	BOOLEAN IsOnVmRootMode;
	BOOLEAN IncrementRip;
	UINT64 VMXON_REGION;
	UINT64 VMXON_VA;
	UINT64 VMCS_REGION;
	UINT64 VMCS_VA;
	UINT64 VMStackVA;
	UINT64 MSRBitMapVA; // MSRBitMap Virtual Address
	UINT64 MSRBitMapPA; // MSRBitMap Physical Address
	PEPT_HOOKED_PAGE_DETAIL MtfEptHookRestorePoint;
}VM_GLOBAL_DATA, * PVM_GLOBAL_DATA;

//ExAllocatePool PoolTag
#define POOLTAG	0x5654564d	// "VTVM"
#define RPL_MASK                3
#define DPL_USER                3
#define DPL_SYSTEM              0

#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define HYPERV_CPUID_INTERFACE                  0x40000001
#define HYPERV_CPUID_VERSION                    0x40000002
#define HYPERV_CPUID_FEATURES                   0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO           0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS           0x40000005

#define HYPERV_HYPERVISOR_PRESENT_BIT           0x80000000
#define HYPERV_CPUID_MIN                        0x40000005
#define HYPERV_CPUID_MAX                        0x4000ffff

// Global Descriptor Table Address,GDT


// Interrupt Descriptor Table, IDT

// Segment Registers
enum SEGREGS
{
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR
};

typedef union SEGMENT_ATTRIBUTES
{
	USHORT UCHARs;
	struct
	{
		USHORT TYPE : 4;              /* 0;  Bit 40-43 */
		USHORT S : 1;                 /* 4;  Bit 44 */
		USHORT DPL : 2;               /* 5;  Bit 45-46 */
		USHORT P : 1;                 /* 7;  Bit 47 */

		USHORT AVL : 1;               /* 8;  Bit 52 */
		USHORT L : 1;                 /* 9;  Bit 53 */
		USHORT DB : 1;                /* 10; Bit 54 */
		USHORT G : 1;                 /* 11; Bit 55 */
		USHORT GAP : 4;

	} Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEGMENT_SELECTOR
{
	USHORT SEL;
	SEGMENT_ATTRIBUTES ATTRIBUTES;
	ULONG32 LIMIT;
	ULONG64 BASE;
} SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
	USHORT LIMIT0;
	USHORT BASE0;
	UCHAR  BASE1;
	UCHAR  ATTR0;
	UCHAR  LIMIT1ATTR1;
	UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

typedef union _MSR
{
	struct
	{
		ULONG Low;
		ULONG High;
	};

	ULONG64 Content;
} MSR, * PMSR;

typedef union _MSR_IA32_EFER {
	ULONG64 All;
	struct {
		ULONG64 SCE : 1;	// R/W syscall enable
		ULONG64 Reserved1 : 7;	// reserved
		ULONG64 LME : 1;	// R/W IA32e Mode enable
		ULONG64 Reserved2 : 1;
		ULONG64 LMA : 1; // R IA32e Mode active when set
		ULONG64 NXE : 1; // R/W enable page access
		ULONG64 Reserved3;
	}Fields;
}MSR_IA32_EFER, * PMSR_IA32_EFER;
/*
// Segment sector
typedef union _SEGMENT_SELECTOR {
	USHORT Selector;
	struct {
		USHORT RPL : 2;	// request private level
		USHORT T1 : 1;
		USHORT index : 13; 
	}SelectorDescriptor;
}SEGMENT_SELECTOR;


// Segment description
typedef union _SEGMENT_DESCRIPTOR {
	ULONG64 SegDes;
	struct {
		ULONG64 limit0 : 16;
		ULONG64 Base0 : 16;
		ULONG64 Base1 : 8;
		ULONG64 Type : 4;
		ULONG64 S : 1;
		ULONG64 DPL : 2;
		ULONG64 P : 1;
		ULONG64 limit1 : 4;
		ULONG64 AVL : 1;
		ULONG64 L : 1;
		ULONG64 DB : 1;
		ULONG64 G : 1;
		ULONG64 GAP : 4;
		ULONG64 Base2 : 8;
	}Field;
}SEGMENT_DESCRIPTOR;
*/


/* global variable */
int CpuNums;
PVM_GLOBAL_DATA g_VM_DATA_ptr;


//implment in Driver.c
int LoadVM();
int ExitVM();

//implement in KernelAPIDemo.c, just for test
// void QueryCPU();
UINT64 VA2PA(void* va);
UINT64 PA2VA(UINT64 pa);

void MDL_Demo();

NTSTATUS NTAPI NtTraceControl(ULONG FunctionCode, PVOID InBuffer, ULONG InBufferLen, PVOID OutBuffer, ULONG OutBufferLen, PULONG ReturnLength);
//NTSTATUS NTAPI ZwTraceControl(ULONG FunctionCode, PVOID InBuffer, ULONG InBufferLen, PVOID OutBuffer, ULONG OutBufferLen, PULONG ReturnLength);
ULONG64 GetSyscallEntry();
BOOLEAN SearchAddrByPattern(IN const unsigned char* pattern, IN ULONG pattern_size, OUT UINT64* ret_addr);
NTSTATUS InfinityModifyTraceSettings(IN int Operation);
ULONG64 Fake_Cklc_etw_func();
BOOLEAN InfinityHook_Demo();
//defines Windows - specific types and structures


typedef struct _WNODE_HEADER{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union{
		ULONG64 HistoricalContext;  // Logger use
		struct{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER, * PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER	Wnode;
	ULONG			BufferSize;
	ULONG			MinimumBuffers;
	ULONG			MaximumBuffers;
	ULONG			MaximumFileSize;
	ULONG			LogFileMode;
	ULONG			FlushTimer;
	ULONG			EnableFlags;
	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

#define EtwpStartTrace		1
#define EtwpStopTrace		2
#define EtwpQueryTrace		3
#define EtwpUpdateTrace		4
#define EtwpFlushTrace		5

// RFLAGS
typedef union _EFLAGS
{
	ULONG_PTR All;
	struct
	{
		ULONG CF : 1;           // [0] Carry flag
		ULONG Reserved1 : 1;    // [1] Always 1
		ULONG PF : 1;           // [2] Parity flag
		ULONG Reserved2 : 1;    // [3] Always 0
		ULONG AF : 1;           // [4] Borrow flag
		ULONG Reserved3 : 1;    // [5] Always 0
		ULONG ZF : 1;           // [6] Zero flag
		ULONG SF : 1;           // [7] Sign flag
		ULONG TF : 1;           // [8] Trap flag
		ULONG IF : 1;           // [9] Interrupt flag
		ULONG DF : 1;           // [10]
		ULONG OF : 1;           // [11]
		ULONG IOPL : 2;         // [12-13] I/O privilege level
		ULONG NT : 1;           // [14] Nested task flag
		ULONG Reserved4 : 1;    // [15] Always 0
		ULONG RF : 1;           // [16] Resume flag
		ULONG VM : 1;           // [17] Virtual 8086 mode
		ULONG AC : 1;           // [18] Alignment check
		ULONG VIF : 1;          // [19] Virtual interrupt flag
		ULONG VIP : 1;          // [20] Virtual interrupt pending
		ULONG ID : 1;           // [21] Identification flag
		ULONG Reserved5 : 10;   // [22-31] Always 0
	} Fields;
} EFLAGS, * PEFLAGS;

// CR0
typedef union _CR0_REG
{
	ULONG_PTR All;
	struct
	{
		ULONG PE : 1;           // [0] Protected Mode Enabled
		ULONG MP : 1;           // [1] Monitor Coprocessor FLAG
		ULONG EM : 1;           // [2] Emulate FLAG
		ULONG TS : 1;           // [3] Task Switched FLAG
		ULONG ET : 1;           // [4] Extension Type FLAG
		ULONG NE : 1;           // [5] Numeric Error
		ULONG Reserved1 : 10;   // [6-15]
		ULONG WP : 1;           // [16] Write Protect
		ULONG Reserved2 : 1;    // [17]
		ULONG AM : 1;           // [18] Alignment Mask
		ULONG Reserved3 : 10;   // [19-28]
		ULONG NW : 1;           // [29] Not Write-Through
		ULONG CD : 1;           // [30] Cache Disable
		ULONG PG : 1;           // [31] Paging Enabled
	} Fields;
} CR0_REG, * PCR0_REG;

// CR4
typedef union _CR4_REG
{
	ULONG_PTR All;
	struct
	{
		ULONG VME : 1;          // [0] Virtual Mode Extensions
		ULONG PVI : 1;          // [1] Protected-Mode Virtual Interrupts
		ULONG TSD : 1;          // [2] Time Stamp Disable
		ULONG DE : 1;           // [3] Debugging Extensions
		ULONG PSE : 1;          // [4] Page Size Extensions
		ULONG PAE : 1;          // [5] Physical Address Extension
		ULONG MCE : 1;          // [6] Machine-Check Enable
		ULONG PGE : 1;          // [7] Page Global Enable
		ULONG PCE : 1;          // [8] Performance-Monitoring Counter Enable
		ULONG OSFXSR : 1;       // [9] OS Support for FXSAVE/FXRSTOR
		ULONG OSXMMEXCPT : 1;   // [10] OS Support for Unmasked SIMD Exceptions
		ULONG Reserved1 : 2;    // [11-12]
		ULONG VMXE : 1;         // [13] Virtual Machine Extensions Enabled
		ULONG SMXE : 1;         // [14] SMX-Enable Bit
		ULONG Reserved2 : 2;    // [15-16]
		ULONG PCIDE : 1;        // [17] PCID Enable
		ULONG OSXSAVE : 1;      // [18] XSAVE and Processor Extended States-Enable
		ULONG Reserved3 : 1;    // [19]
		ULONG SMEP : 1;         // [20] Supervisor Mode Execution Protection Enable
		ULONG SMAP : 1;         // [21] Supervisor Mode Access Protection Enable
	} Fields;
} CR4_REG, * PCR4_REG;

// Patch Guard
//http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool_entry.htm
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;
typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

NTSTATUS ZwQuerySystemInformation(ULONG64 SystemInformationClass, PSYSTEM_BIGPOOL_INFORMATION SystemInformation, ULONG64 SystemInformationLength, ULONG64* ReturnLength);

ULONG64 g_NT_BASE;
ULONG64 g_PTE_BASE;
ULONG64 g_PDE_BASE;
ULONG64 g_PPE_BASE;
ULONG64 g_PXE_BASE;

NTSTATUS ScanBigPool();
void PGTestDemo();

