#include "Remote_ManualMapping.h"

struct ShellCode_t
{
	LPVOID pLoadLibraryA; // required to load additional libraries
	LPVOID pGetProcAddress; // required to get it's process address to fix up iat
	LPVOID pModuleAddress; // address of mapped module
};

DWORD Shellcode(LPVOID param)
{
	auto sc = (ShellCode_t*)param;

	typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR lpLibFileName);
	auto fncLoadLibraryA = (tLoadLibraryA)sc->pLoadLibraryA;

	typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	auto fncGetProcAddress = (tGetProcAddress)sc->pGetProcAddress;

	auto header = reinterpret_cast<PIMAGE_DOS_HEADER>(sc->pModuleAddress);
	auto ntheader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD64>(sc->pModuleAddress) + header->e_lfanew);

	// go through IAT of mapped module
	{
		auto importsDirectory = ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<DWORD64>(sc->pModuleAddress) + importsDirectory.VirtualAddress);

		// iterate through each import
		while (importDescriptor->Name != 0)
		{
			auto libName = reinterpret_cast<LPCSTR>(reinterpret_cast<DWORD64>(sc->pModuleAddress) + importDescriptor->Name);

			// load it's required module if not done yet
			auto hModule = fncLoadLibraryA(libName);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(reinterpret_cast<DWORD64>(sc->pModuleAddress) + importDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(reinterpret_cast<DWORD64>(sc->pModuleAddress) + importDescriptor->FirstThunk);

			if (!pThunkRef)
			{
				pThunkRef = pFuncRef;
			}

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = (ULONG_PTR)fncGetProcAddress(hModule, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<DWORD64>(sc->pModuleAddress) + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)fncGetProcAddress(hModule, pImport->Name);
				}
			}

			++importDescriptor;
		}
	}

	// call entry point
	typedef BOOL(WINAPI* tDllMain)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	auto ep = reinterpret_cast<tDllMain>(reinterpret_cast<DWORD64>(sc->pModuleAddress) + ntheader->OptionalHeader.AddressOfEntryPoint);
	if (!ep(reinterpret_cast<HINSTANCE>(sc->pModuleAddress), DLL_PROCESS_ATTACH, nullptr))
	{
		return 1;
	}

	return 0;
}

bool tInjector::method::ManualMapping(const char* TargetProcessName, const char* TargetModulePath)
{
	auto pid = tInjector::helper::GetProcessIdByName(TargetProcessName);
	if (!pid)
	{
		tInjector::logln("Process not found");
		return false;
	}

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
	{
		tInjector::logln("OpenProcess failed with code: %d", GetLastError());
		return false;
	}

	FILE* f = nullptr;
	auto err = fopen_s(&f, TargetModulePath, "rb");
	if (err != 0)
	{
		CloseHandle(hProcess);

		tInjector::logln("fopen failed");
		return false;
	}

	// read module
	size_t fileSize = 0;
	{
		// set ptr to the end of file
		fseek(f, 0, SEEK_END);

		// get file size
		fileSize = ftell(f);

		// set ptr back to beginning of file
		fseek(f, 0, SEEK_SET);
	}

	// need to declare them here because of goto
	LPVOID pMappedModule = nullptr;
	LPVOID pShellCodeParam = nullptr;
	LPVOID pShellcode = nullptr;
	DWORD exitCode = 1;

	PIMAGE_DOS_HEADER header = nullptr;
	PIMAGE_NT_HEADERS ntheader = nullptr;

	// allocate space for module
	BYTE* pModule = (BYTE*)malloc(fileSize * sizeof(BYTE) + 1);
	if (!pModule)
	{
		tInjector::logln("malloc failed");
		goto free;
	}

	fread(reinterpret_cast<void*>(pModule), fileSize, 1, f);
	pModule[fileSize] = 0;

	header = reinterpret_cast<PIMAGE_DOS_HEADER>(pModule);
	ntheader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD64>(pModule) + header->e_lfanew);

	// Allocate & Write Module to target process
	{
		pMappedModule = VirtualAllocEx(hProcess, nullptr, ntheader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pMappedModule)
		{
			tInjector::logln("VirtualAllocEx failed");
			goto free;
		}

		// write header first
		if (!WriteProcessMemory(hProcess, pMappedModule, pModule, tInjector::helper::GetPEHeaderSize(ntheader), nullptr))
		{
			tInjector::logln("WriteProcessMemory failed");
			goto free;
		}

		// write module sections
		auto pSectionHeader = IMAGE_FIRST_SECTION(ntheader);
		for (WORD i = 0; i < ntheader->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
		{
			if (pSectionHeader->SizeOfRawData != 0)
			{
				if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(pMappedModule) + pSectionHeader->VirtualAddress), pModule + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
				{
					tInjector::logln("WriteProcessMemory failed");
					goto free;
				}
			}
		}
	}

	// Allocate & Write Shellcode parameter
	{
		ShellCode_t param = { 0 };
		param.pLoadLibraryA = &LoadLibraryA;
		param.pGetProcAddress = &GetProcAddress;
		param.pModuleAddress = pMappedModule;

		pShellCodeParam = VirtualAllocEx(hProcess, nullptr, sizeof(ShellCode_t), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellCodeParam)
		{
			tInjector::logln("VirtualAllocEx failed");
			goto free;
		}

		if (!WriteProcessMemory(hProcess, pShellCodeParam, &param, sizeof(ShellCode_t), nullptr))
		{
			tInjector::logln("WriteProcessMemory failed");
			goto free;
		}
	}

	// Allocate & Write Shellcode
	{
		pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pShellcode)
		{
			tInjector::logln("VirtualAllocEx failed");
			goto free;
		}

		if (!WriteProcessMemory(hProcess, pShellcode, Shellcode, 0x1000, nullptr))
		{
			tInjector::logln("WriteProcessMemory failed");
			goto free;
		}
	}

	// Create remote thread to execute Shellcode
	{
		auto hRT = CreateRemoteThread(hProcess, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pShellCodeParam, NULL, nullptr);
		if (!hRT)
		{
			tInjector::logln("CreateRemoteThread failed with code: %d", GetLastError());

			goto free;
		}

		WaitForSingleObject(hRT, INFINITE);
		GetExitCodeThread(hRT, &exitCode);

		if (!exitCode)
		{
			tInjector::logln("Successfully injected module: %s", TargetModulePath);
		}
		else
		{
			tInjector::logln("Injection failed with error: %d", GetLastError());
		}

		CloseHandle(hRT);
	}

free:
	fclose(f);

	if (pModule)
	{
		free(pModule);
		pModule = 0;
	}

	CloseHandle(hProcess);

	return false;
}