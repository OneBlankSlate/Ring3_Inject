#pragma once
#include<iostream>
#include<tchar.h>
#include<Windows.h>
#include<TlHelp32.h>
#include<vector> 



typedef LONG KPRIORITY;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
	ULONG PadPadAlignment;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; //VISTA
	ULONG HardFaultCount; //WIN7
	ULONG NumberOfThreadsHighWatermark; //WIN7
	ULONGLONG CycleTime; //WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;

	//
	// This part corresponds to VM_COUNTERS_EX.
	// NOTE: *NOT* THE SAME AS VM_COUNTERS!
	//
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;

	//
	// This part corresponds to IO_COUNTERS
	//
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION TH[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS;



typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef struct _PEB
{                                                                 /* win32/win64 */
	BOOLEAN                      InheritedAddressSpace;             /* 000/000 */
	BOOLEAN                      ReadImageFileExecOptions;          /* 001/001 */
	BOOLEAN                      BeingDebugged;                     /* 002/002 */
	BOOLEAN                      SpareBool;                         /* 003/003 */
	HANDLE                       Mutant;                            /* 004/008 */
	HMODULE                      ImageBaseAddress;                  /* 008/010 */
	PVOID                        LdrData;                           /* 00c/018 */
	_RTL_USER_PROCESS_PARAMETERS ProcessParameters;                 /* 010/020 */
	PVOID                        SubSystemData;                     /* 014/028 */
	HANDLE                       ProcessHeap;                       /* 018/030 */
	PRTL_CRITICAL_SECTION        FastPebLock;                       /* 01c/038 */
	PVOID /*PPEBLOCKROUTINE*/    FastPebLockRoutine;                /* 020/040 */
	PVOID /*PPEBLOCKROUTINE*/    FastPebUnlockRoutine;              /* 024/048 */
	ULONG                        EnvironmentUpdateCount;            /* 028/050 */
	PVOID                        KernelCallbackTable;               /* 02c/058 */
	ULONG                        Reserved[2];                       /* 030/060 */
	PVOID /*PPEB_FREE_BLOCK*/    FreeList;                          /* 038/068 */
	ULONG                        TlsExpansionCounter;               /* 03c/070 */
	PVOID                        TlsBitmap;                         /* 040/078 */
	ULONG                        TlsBitmapBits[2];                  /* 044/080 */
	PVOID                        ReadOnlySharedMemoryBase;          /* 04c/088 */
	PVOID                        ReadOnlySharedMemoryHeap;          /* 050/090 */
	PVOID* ReadOnlyStaticServerData;          /* 054/098 */
	PVOID                        AnsiCodePageData;                  /* 058/0a0 */
	PVOID                        OemCodePageData;                   /* 05c/0a8 */
	PVOID                        UnicodeCaseTableData;              /* 060/0b0 */
	ULONG                        NumberOfProcessors;                /* 064/0b8 */
	ULONG                        NtGlobalFlag;                      /* 068/0bc */
	LARGE_INTEGER                CriticalSectionTimeout;            /* 070/0c0 */
	SIZE_T                       HeapSegmentReserve;                /* 078/0c8 */
	SIZE_T                       HeapSegmentCommit;                 /* 07c/0d0 */
	SIZE_T                       HeapDeCommitTotalFreeThreshold;    /* 080/0d8 */
	SIZE_T                       HeapDeCommitFreeBlockThreshold;    /* 084/0e0 */
	ULONG                        NumberOfHeaps;                     /* 088/0e8 */
	ULONG                        MaximumNumberOfHeaps;              /* 08c/0ec */
	PVOID* ProcessHeaps;                      /* 090/0f0 */
	PVOID                        GdiSharedHandleTable;              /* 094/0f8 */
	PVOID                        ProcessStarterHelper;              /* 098/100 */
	PVOID                        GdiDCAttributeList;                /* 09c/108 */
	PVOID                        LoaderLock;                        /* 0a0/110 */
	ULONG                        OSMajorVersion;                    /* 0a4/118 */
	ULONG                        OSMinorVersion;                    /* 0a8/11c */
	ULONG                        OSBuildNumber;                     /* 0ac/120 */
	ULONG                        OSPlatformId;                      /* 0b0/124 */
	ULONG                        ImageSubSystem;                    /* 0b4/128 */
	ULONG                        ImageSubSystemMajorVersion;        /* 0b8/12c */
	ULONG                        ImageSubSystemMinorVersion;        /* 0bc/130 */
	ULONG                        ImageProcessAffinityMask;          /* 0c0/134 */
	HANDLE                       GdiHandleBuffer[28];               /* 0c4/138 */
	ULONG                        unknown[6];                        /* 134/218 */
	PVOID                        PostProcessInitRoutine;            /* 14c/230 */
	PVOID                        TlsExpansionBitmap;                /* 150/238 */
	ULONG                        TlsExpansionBitmapBits[32];        /* 154/240 */
	ULONG                        SessionId;                         /* 1d4/2c0 */
	ULARGE_INTEGER               AppCompatFlags;                    /* 1d8/2c8 */
	ULARGE_INTEGER               AppCompatFlagsUser;                /* 1e0/2d0 */
	PVOID                        ShimData;                          /* 1e8/2d8 */
	PVOID                        AppCompatInfo;                     /* 1ec/2e0 */
	UNICODE_STRING               CSDVersion;                        /* 1f0/2e8 */
	PVOID                        ActivationContextData;             /* 1f8/2f8 */
	PVOID                        ProcessAssemblyStorageMap;         /* 1fc/300 */
	PVOID                        SystemDefaultActivationData;       /* 200/308 */
	PVOID                        SystemAssemblyStorageMap;          /* 204/310 */
	SIZE_T                       MinimumStackCommit;                /* 208/318 */
	PVOID* FlsCallback;                       /* 20c/320 */
	LIST_ENTRY                   FlsListHead;                       /* 210/328 */
	PVOID                        FlsBitmap;                         /* 218/338 */
	ULONG                        FlsBitmapBits[4];                  /* 21c/340 */
} PEB, * PPEB;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	MaxProcessInfoClass
} PROCESSINFOCLASS;
typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;




#define PAGE_SIZE 0x1000
typedef HMODULE(WINAPI* LPFN_LOADLIBRARYW)(LPCWSTR lpLibFileName);
typedef HMODULE(WINAPI* LPFN_LOADLIBRARYA)(LPCSTR lpLibFileName);
typedef NTSTATUS(NTAPI* LPFN_NtQueryInformationProcess)(IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(NTAPI* LPFN_NtProtectVirtualMemory)(IN HANDLE ProcessHandle,
	IN OUT PVOID* UnsafeBaseAddress,
	IN OUT SIZE_T* UnsafeNumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG UnsafeOldAccessProtection);


#ifdef _WIN64
UINT8	__ShellCode[0x100] = {
	0x48,0x83,0xEC,0x28,	// sub rsp ,28h   //rcx rdx r8 r9  对齐 

	0x48,0x8D,0x0d,			// [+4] lea rcx,    
	0x00,0x00,0x00,0x00,	// [+7] DllFullPathOffset = [+43] - [+4] - 7
	// call 跳偏移，到地址，解*号
	0xff,0x15,				// [+11]
	0x00,0x00,0x00,0x00,	// [+13] LoadLibraryAddressOffset

	0x48,0x83,0xc4,0x28,	// [+17] add rsp,28h

	// jmp 跳偏移，到地址，解*号
	0xff,0x25,				// [+21]
	0x00,0x00,0x00,0x00,	// [+23] Jmp Rip

	// 存放原先的 rip
	0x00,0x00,0x00,0x00,	// [+27]   //
	0x00,0x00,0x00,0x00,	// [+31]

	// 跳板 loadlibrary地址
	0x00,0x00,0x00,0x00,	// [+35] 
	0x00,0x00,0x00,0x00,	// [+39]

	// 存放dll完整路径
	//	0x00,0x00,0x00,0x00,	// [+43]
	//	0x00,0x00,0x00,0x00		// [+47]
	//	......
};

#else
UINT8	__ShellCode[0x100] = {
	0x60,					// [+0] pusha   //其入栈顺序是:EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
	0x9c,					// [+1] pushf
	0x68,					// [+2] push
	0x00,0x00,0x00,0x00,	// [+3] ShellCode + 
	0xff,0x15,				// [+7] call	
	0x00,0x00,0x00,0x00,	// [+9] LoadLibrary Addr  Addr
	0x9d,					// [+13] popf
	0x61,					// [+14] popa
	0xff,0x25,				// [+15] jmp
	0x00,0x00,0x00,0x00,	// [+17] jmp  eip

	// eip 地址
	0x00,0x00,0x00,0x00,	// [+21]
	//LoadLibrary地址
	0x00,0x00,0x00,0x00,	// [+25] 
	//DllFullPath 
	0x00,0x00,0x00,0x00		// [+29] 


};
#endif