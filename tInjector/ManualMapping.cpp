#include "ManualMapping.h"

enum class EShellCodeRet
{
    SHELLCODE_UNKOWN = 0,
    SHELLCODE_SUCCESS,
    SHELLCODE_FAILED
};

struct ShellCode_t
{
	LPVOID pLoadLibraryA; // required to load additional libraries
	LPVOID pGetProcAddress; // required to get it's process address to fix up iat
	LPVOID pModuleAddress; // address of mapped module
    EShellCodeRet ret;
};

/*tDWORD ShellCode(LPVOID param)
{
	auto sc = (ShellCode_t*)param;

	typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR lpLibFileName);
	auto fncLoadLibraryA = (tLoadLibraryA)sc->pLoadLibraryA;

	typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	auto fncGetProcAddress = (tGetProcAddress)sc->pGetProcAddress;

	auto header = reinterpret_cast<PIMAGE_DOS_HEADER>(sc->pModuleAddress);
	auto ntheader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<tDWORD>(sc->pModuleAddress) + header->e_lfanew);

	// walk through IAT and load up it's required library & resolve it's process address
	{
		auto importsDirectory = ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<tDWORD>(sc->pModuleAddress) + importsDirectory.VirtualAddress);

		// iterate through each import
		while (importDescriptor->Name != 0)
		{
			auto libName = reinterpret_cast<LPCSTR>(reinterpret_cast<tDWORD>(sc->pModuleAddress) + importDescriptor->Name);

			// load it's required module if not done yet
			auto hModule = fncLoadLibraryA(libName);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(reinterpret_cast<tDWORD>(sc->pModuleAddress) + importDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(reinterpret_cast<tDWORD>(sc->pModuleAddress) + importDescriptor->FirstThunk);

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
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(reinterpret_cast<tDWORD>(sc->pModuleAddress) + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)fncGetProcAddress(hModule, pImport->Name);
				}
			}

			++importDescriptor;
		}
	}

	// call entry point
	typedef BOOL(WINAPI* tDllMain)(HINSTANCE hinstDLL, tDWORD fdwReason, LPVOID lpvReserved);
	auto ep = reinterpret_cast<tDllMain>(reinterpret_cast<tDWORD>(sc->pModuleAddress) + ntheader->OptionalHeader.AddressOfEntryPoint);
	if (!ep(reinterpret_cast<HINSTANCE>(sc->pModuleAddress), DLL_PROCESS_ATTACH, nullptr))
	{
        sc->ret = EShellCodeRet::SHELLCODE_FAILED;
		return 1;
	}

    sc->ret = EShellCodeRet::SHELLCODE_SUCCESS;
	return 0;
}*/

// it's the above function
static BYTE m_ShellCode[] =
{
        0x48, 0x89, 0x4C, 0x24, 0x08,
        0x55,
        0x48, 0x81, 0xEC, 0xD0, 0x00, 0x00, 0x00,
        0x48, 0x8D, 0x6C, 0x24, 0x20,
        0x48, 0x8B, 0x85, 0xC0, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x45, 0x00,
        0x48, 0x8B, 0x45, 0x00,
        0x48, 0x8B, 0x00,
        0x48, 0x89, 0x45, 0x08,
        0x48, 0x8B, 0x45, 0x00,
        0x48, 0x8B, 0x40, 0x08,
        0x48, 0x89, 0x45, 0x10,
        0x48, 0x8B, 0x45, 0x00,
        0x48, 0x8B, 0x40, 0x10,
        0x48, 0x89, 0x45, 0x18,
        0x48, 0x8B, 0x45, 0x18,
        0x48, 0x63, 0x40, 0x3C,
        0x48, 0x8B, 0x4D, 0x00,
        0x48, 0x03, 0x41, 0x10,
        0x48, 0x89, 0x45, 0x20,
        0xB8, 0x08, 0x00, 0x00, 0x00,
        0x48, 0x6B, 0xC0, 0x01,
        0x48, 0x8B, 0x4D, 0x20,
        0x48, 0x8B, 0x84, 0x01, 0x88, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x45, 0x28,
        0x8B, 0x45, 0x28,
        0x48, 0x8B, 0x4D, 0x00,
        0x48, 0x03, 0x41, 0x10,
        0x48, 0x89, 0x45, 0x30,
        0x48, 0x8B, 0x45, 0x30,
        0x83, 0x78, 0x0C, 0x00,
        0x0F, 0x84, 0xF1, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x45, 0x30,
        0x8B, 0x40, 0x0C,
        0x48, 0x8B, 0x4D, 0x00,
        0x48, 0x03, 0x41, 0x10,
        0x48, 0x89, 0x45, 0x38,
        0x48, 0x8B, 0x4D, 0x38,
        0xFF, 0x55, 0x08,
        0x48, 0x89, 0x45, 0x40,
        0x48, 0x8B, 0x45, 0x30,
        0x8B, 0x00,
        0x48, 0x8B, 0x4D, 0x00,
        0x48, 0x03, 0x41, 0x10,
        0x48, 0x89, 0x45, 0x48,
        0x48, 0x8B, 0x45, 0x30,
        0x8B, 0x40, 0x10,
        0x48, 0x8B, 0x4D, 0x00,
        0x48, 0x03, 0x41, 0x10,
        0x48, 0x89, 0x45, 0x50,
        0x48, 0x83, 0x7D, 0x48, 0x00,
        0x75, 0x08,
        0x48, 0x8B, 0x45, 0x50,
        0x48, 0x89, 0x45, 0x48,
        0xEB, 0x18,
        0x48, 0x8B, 0x45, 0x48,
        0x48, 0x83, 0xC0, 0x08,
        0x48, 0x89, 0x45, 0x48,
        0x48, 0x8B, 0x45, 0x50,
        0x48, 0x83, 0xC0, 0x08,
        0x48, 0x89, 0x45, 0x50,
        0x48, 0x8B, 0x45, 0x48,
        0x48, 0x83, 0x38, 0x00,
        0x74, 0x6A,
        0x48, 0x8B, 0x45, 0x48,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x48, 0x8B, 0x00,
        0x48, 0x23, 0xC1,
        0x48, 0x85, 0xC0,
        0x74, 0x20,
        0x48, 0x8B, 0x45, 0x48,
        0x48, 0x8B, 0x00,
        0x48, 0x25, 0xFF, 0xFF, 0x00, 0x00,
        0x48, 0x8B, 0xD0,
        0x48, 0x8B, 0x4D, 0x40,
        0xFF, 0x55, 0x10,
        0x48, 0x8B, 0x4D, 0x50,
        0x48, 0x89, 0x01,
        0xEB, 0x2C,
        0x48, 0x8B, 0x45, 0x00,
        0x48, 0x8B, 0x40, 0x10,
        0x48, 0x8B, 0x4D, 0x48,
        0x48, 0x03, 0x01,
        0x48, 0x89, 0x45, 0x58,
        0x48, 0x8B, 0x45, 0x58,
        0x48, 0x83, 0xC0, 0x02,
        0x48, 0x8B, 0xD0,
        0x48, 0x8B, 0x4D, 0x40,
        0xFF, 0x55, 0x10,
        0x48, 0x8B, 0x4D, 0x50,
        0x48, 0x89, 0x01,
        0xE9, 0x74, 0xFF, 0xFF, 0xFF,
        0x48, 0x8B, 0x45, 0x30,
        0x48, 0x83, 0xC0, 0x14,
        0x48, 0x89, 0x45, 0x30,
        0xE9, 0x01, 0xFF, 0xFF, 0xFF,
        0x48, 0x8B, 0x45, 0x20,
        0x8B, 0x40, 0x28,
        0x48, 0x8B, 0x4D, 0x00,
        0x48, 0x03, 0x41, 0x10,
        0x48, 0x89, 0x45, 0x60,
        0x45, 0x33, 0xC0,
        0xBA, 0x01, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x45, 0x00,
        0x48, 0x8B, 0x48, 0x10,
        0xFF, 0x55, 0x60,
        0x85, 0xC0,
        0x75, 0x12,
        0x48, 0x8B, 0x45, 0x00,
        0xC7, 0x40, 0x18, 0x02, 0x00, 0x00, 0x00,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xEB, 0x0D,
        0x48, 0x8B, 0x45, 0x00,
        0xC7, 0x40, 0x18, 0x01, 0x00, 0x00, 0x00,
        0x33, 0xC0,
        0x48, 0x8D, 0xA5, 0xB0, 0x00, 0x00, 0x00,
        0x5D,
        0xC3,
};

bool tInjector::method::ManualMapping(const char* TargetProcessName, const char* TargetModulePath, tInjector::InjectionMethod Method, unsigned m_opt)
{
    LPVOID pMappedModule = nullptr;
    LPVOID pShellCodeThreadHijack = nullptr;
    LPVOID pTargetShellCodeThreadHijack = nullptr;
    LPVOID pTargetRtlRestoreContextThreadHijack = nullptr;
    LPVOID pTargetShellCodeParam = nullptr;
    LPVOID pTargetShellCode = nullptr;
    DWORD exitCode = 1;

    PIMAGE_DOS_HEADER header = nullptr;
    PIMAGE_NT_HEADERS ntheader = nullptr;

    ShellCode_t sc = { 0 };
    sc.ret = EShellCodeRet::SHELLCODE_UNKOWN;

	auto pid = tInjector::helper::GetProcessIdByName(TargetProcessName);
	if (!pid)
	{
		tInjector::logln("Process not found mm");
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
	ntheader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<tDWORD>(pModule) + header->e_lfanew);

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
				if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<tDWORD>(pMappedModule) + pSectionHeader->VirtualAddress), pModule + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
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

        pTargetShellCodeParam = VirtualAllocEx(hProcess, nullptr, sizeof(ShellCode_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pTargetShellCodeParam)
		{
			tInjector::logln("VirtualAllocEx failed");
			goto free;
		}

		if (!WriteProcessMemory(hProcess, pTargetShellCodeParam, &param, sizeof(ShellCode_t), nullptr))
		{
			tInjector::logln("WriteProcessMemory failed");
			goto free;
		}
	}

	// Allocate & Write Shellcode
	{
        pTargetShellCode = VirtualAllocEx(hProcess, nullptr, tInjector_ARRLEN(m_ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetShellCode)
		{
			tInjector::logln("VirtualAllocEx failed");
			goto free;
		}

		if (!WriteProcessMemory(hProcess, pTargetShellCode, m_ShellCode, tInjector_ARRLEN(m_ShellCode), nullptr))
		{
			tInjector::logln("WriteProcessMemory failed");
			goto free;
		}
	}

    switch (Method)
    {
    case tInjector::InjectionMethod::CreateRemoteThread:
    {
        // Create remote thread to execute Shellcode
        {
            auto hRT = CreateRemoteThread(hProcess, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(pTargetShellCode), pTargetShellCodeParam, NULL, nullptr);
            if (!hRT)
            {
                tInjector::logln("CreateRemoteThread failed with code: %d", GetLastError());
                goto free;
            }

            WaitForSingleObject(hRT, INFINITE);
            GetExitCodeThread(hRT, &exitCode);

            if (!exitCode)
            {
                while (sc.ret == EShellCodeRet::SHELLCODE_UNKOWN)
                {
                    if (ReadProcessMemory(hProcess, pTargetShellCodeParam, &sc, sizeof(ShellCode_t), nullptr))
                    {
                        if (sc.ret == EShellCodeRet::SHELLCODE_SUCCESS)
                        {
                            if (m_opt & OPT_ERASE_PE_HEADER)
                            {
                                auto m_erase_pe_header = option::erase_pe_header(hProcess, pMappedModule, tInjector::helper::GetPEHeaderSize(ntheader));
                                tInjector::logln(m_erase_pe_header ? "removed pe header" : "failed to remove pe header");
                            }

                            tInjector::logln("Successfully injected module: %s", TargetModulePath);
                            break;
                        }
                        else if (sc.ret == EShellCodeRet::SHELLCODE_FAILED)
                        {
                            tInjector::logln("Injection failed with error: %d", GetLastError());
                            break;
                        }
                    }

                    Sleep(100);
                }
            }
            else
            {
                tInjector::logln("Injection failed with error: %d", GetLastError());
            }

            CloseHandle(hRT);
        }

        break;
    }

    case tInjector::InjectionMethod::ThreadHijacking:
    {
        auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (!hSnap)
        {
            tInjector::logln("CreateToolhelp32Snapshot failed");
            goto free;
        }

        THREADENTRY32 entry = { 0 };
        entry.dwSize = sizeof(entry);

        HANDLE hThread = nullptr;
        if (Thread32First(hSnap, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID == pid)
                {
                    hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
                    if (hThread) break;
                }
            } while (Thread32Next(hSnap, &entry));
        }

        CloseHandle(hSnap);

        if (!hThread)
        {
            tInjector::logln("No Thread found to hijack");
            goto free;
        }

        if (SuspendThread(hThread) == -1)
        {
            tInjector::logln("SuspendThread failed with code: %d", GetLastError());
            CloseHandle(hThread);
            goto free;
        }

        CONTEXT c = { 0 };
        c.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &c))
        {
            tInjector::logln("GetThreadContext failed with code: %d", GetLastError());
            CloseHandle(hThread);
            goto free;
        }

        {
            pTargetRtlRestoreContextThreadHijack = VirtualAllocEx(hProcess, nullptr, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pTargetRtlRestoreContextThreadHijack)
            {
                tInjector::logln("VirtualAllocEx failed with code: %d", GetLastError());
                goto free;
            }

            if (!WriteProcessMemory(hProcess, pTargetRtlRestoreContextThreadHijack, &c, sizeof(CONTEXT), nullptr))
            {
                tInjector::logln("WriteProcessMemory failed with code: %d", GetLastError());
                goto free;
            }
        }

        // allocate & write shellcode to hijack the thread
        {
            pTargetShellCodeThreadHijack = VirtualAllocEx(hProcess, nullptr, tInjector::hijack::GetShellcodeSize(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pTargetShellCodeThreadHijack)
            {
                tInjector::logln("VirtualAllocEx failed with code: %d", GetLastError());
                goto free;
            }

            // set up the shellcode
            pShellCodeThreadHijack = VirtualAlloc(nullptr, tInjector::hijack::GetShellcodeSize(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!pShellCodeThreadHijack)
            {
                tInjector::logln("VirtualAlloc failed with code: %d", GetLastError());
                goto free;
            }

            // copy the shellcode into the buffer
            memcpy(pShellCodeThreadHijack, tInjector::hijack::GetShellcode(), tInjector::hijack::GetShellcodeSize());

            // prepare the shellcode
            {
                *reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x18) = reinterpret_cast<tDWORD>(pTargetShellCodeParam);
                *reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x22) = reinterpret_cast<tDWORD>(pTargetShellCode);
                *reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x2E) = reinterpret_cast<tDWORD>(pTargetRtlRestoreContextThreadHijack);
                *reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x38) = reinterpret_cast<tDWORD>(&RtlRestoreContext);
            }

            if (!WriteProcessMemory(hProcess, pTargetShellCodeThreadHijack, pShellCodeThreadHijack, tInjector::hijack::GetShellcodeSize(), nullptr))
            {
                tInjector::logln("WriteProcessMemory failed with code: %d", GetLastError());
                goto free;
            }
        }

#ifdef _WIN64
        auto storedRip = c.Rip;
        c.Rip = reinterpret_cast<tDWORD>(pTargetShellCodeThreadHijack); // write payload to hijack the thread and call our required function and then jump back to previous execution
#else
        auto storedEip = c.Eip;
        c.Eip = reinterpret_cast<tDWORD>(pTargetShellCodeThreadHijack); // write payload to hijack the thread and call our required function and then jump back to previous execution
#endif

        if (!SetThreadContext(hThread, &c))
        {
            tInjector::logln("SetThreadContext failed with code: %d", GetLastError());

            if (ResumeThread(hThread) == -1)
            {
                tInjector::logln("ResumeThread failed with code: %d", GetLastError());
            }

            CloseHandle(hThread);
            goto free;
        }

        if (ResumeThread(hThread) == -1)
        {
#ifdef _WIN64
            c.Rip = storedRip; // restore previous rip
#else
            c.Eip = storedEip; // restore previous eip
#endif

            if (!SetThreadContext(hThread, &c))
            {
                tInjector::logln("SetThreadContext failed with code: %d", GetLastError());
                CloseHandle(hThread);
                goto free;
            }

            tInjector::logln("ResumeThread failed with code: %d", GetLastError());
            CloseHandle(hThread);
            goto free;
        }

        while (sc.ret == EShellCodeRet::SHELLCODE_UNKOWN)
        {
            if (ReadProcessMemory(hProcess, pTargetShellCodeParam, &sc, sizeof(ShellCode_t), nullptr))
            {
                if (sc.ret == EShellCodeRet::SHELLCODE_SUCCESS)
                {
                    if (m_opt & OPT_ERASE_PE_HEADER)
                    {
                        auto m_erase_pe_header = option::erase_pe_header(hProcess, pMappedModule, tInjector::helper::GetPEHeaderSize(ntheader));
                        tInjector::logln(m_erase_pe_header ? "removed pe header" : "failed to remove pe header");
                    }

                    tInjector::logln("Successfully injected module: %s", TargetModulePath);
                    break;
                }
                else if (sc.ret == EShellCodeRet::SHELLCODE_FAILED)
                {
                    tInjector::logln("Injection failed with error: %d", GetLastError());
                    break;
                }
            }

            Sleep(100);
        }

        CloseHandle(hThread);

        break;
    }

    default:
        tInjector::logln("Injection Method is invalid");
        break;
    }

free:
	fclose(f);

	if (pModule)
	{
		free(pModule);
		pModule = 0;
	}

    // free up allocated memory
    if (pShellCodeThreadHijack)
    {
        VirtualFree(pShellCodeThreadHijack, 0, MEM_RELEASE);
        pShellCodeThreadHijack = nullptr;
    }

    if (pTargetRtlRestoreContextThreadHijack)
    {
        VirtualFree(pTargetRtlRestoreContextThreadHijack, 0, MEM_RELEASE);
        pTargetRtlRestoreContextThreadHijack = nullptr;
    }

    if (pTargetShellCodeThreadHijack)
    {
        VirtualFreeEx(hProcess, pTargetShellCodeThreadHijack, 0, MEM_RELEASE);
        pTargetShellCodeThreadHijack = nullptr;
    }

    /*
    * do not unload mapped module on successfully mapped
    */
    if (sc.ret != EShellCodeRet::SHELLCODE_SUCCESS)
    {
        if (pMappedModule)
        {
            VirtualFreeEx(hProcess, pMappedModule, 0, MEM_RELEASE);
            pMappedModule = nullptr;
        }
    }

    if (pTargetShellCodeParam)
    {
        VirtualFreeEx(hProcess, pTargetShellCodeParam, 0, MEM_RELEASE);
        pTargetShellCodeParam = nullptr;
    }

    if (pTargetShellCode)
    {
        VirtualFreeEx(hProcess, pTargetShellCode, 0, MEM_RELEASE);
        pTargetShellCode = nullptr;
    }

	CloseHandle(hProcess);

    return (exitCode == 0) ? true : false;
}