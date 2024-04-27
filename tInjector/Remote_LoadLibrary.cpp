#include "Remote_LoadLibrary.h"

enum class EShellCodeRet
{
	SHELLCODE_UNKOWN = 0,
	SHELLCODE_SUCCESS,
	SHELLCODE_FAILED
};

struct ShellCode_t
{
	LPVOID pLoadLibraryA;
	char path[MAX_PATH];
	EShellCodeRet ret;
};

/*tDWORD ShellCode(LPVOID param)
{
	ShellCode_t* sc = (ShellCode_t*)param;

	typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR lpLibFileName);
	tLoadLibraryA fnc = (tLoadLibraryA)sc->pLoadLibraryA;
	int ret = fnc(sc->path) ? 0 : 1;
	sc->ret = ret ? EShellCodeRet::SHELLCODE_FAILED : EShellCodeRet::SHELLCODE_SUCCESS;

	return ret;
}*/

// it's the above function
#ifdef _WIN64
static BYTE ShellCode[] =
{
		0x48, 0x89, 0x4C, 0x24, 0x08,
		0x55,
		0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,
		0x48, 0x8D, 0x6C, 0x24, 0x20,
		0x48, 0x8B, 0x45, 0x70,
		0x48, 0x89, 0x45, 0x00,
		0x48, 0x8B, 0x45, 0x00,
		0x48, 0x8B, 0x00,
		0x48, 0x89, 0x45, 0x08,
		0x48, 0x8B, 0x45, 0x00,
		0x48, 0x83, 0xC0, 0x08,
		0x48, 0x8B, 0xC8,
		0xFF, 0x55, 0x08,
		0x48, 0x85, 0xC0,
		0x74, 0x09,
		0xC7, 0x45, 0x54, 0x00, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0x54, 0x01, 0x00, 0x00, 0x00,
		0x8B, 0x45, 0x54,
		0x89, 0x45, 0x10,
		0x83, 0x7D, 0x10, 0x00,
		0x74, 0x09,
		0xC7, 0x45, 0x54, 0x02, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0x54, 0x01, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x45, 0x00,
		0x8B, 0x4D, 0x54,
		0x89, 0x88, 0x0C, 0x01, 0x00, 0x00,
		0x48, 0x63, 0x45, 0x10,
		0x48, 0x8D, 0x65, 0x60,
		0x5D,
		0xC3,
};
#else
static BYTE ShellCode[] = {
		0x55,
		0x8B, 0xEC,
		0x83, 0xEC, 0x14,
		0x8B, 0x45, 0x08,
		0x89, 0x45, 0xFC,
		0x8B, 0x4D, 0xFC,
		0x8B, 0x11,
		0x89, 0x55, 0xEC,
		0x8B, 0x45, 0xFC,
		0x83, 0xC0, 0x04,
		0x50,
		0xFF, 0x55, 0xEC,
		0x85, 0xC0,
		0x74, 0x09,
		0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0xF8, 0x01, 0x00, 0x00, 0x00,
		0x8B, 0x4D, 0xF8,
		0x89, 0x4D, 0xF0,
		0x83, 0x7D, 0xF0, 0x00,
		0x74, 0x09,
		0xC7, 0x45, 0xF4, 0x02, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0xF4, 0x01, 0x00, 0x00, 0x00,
		0x8B, 0x55, 0xFC,
		0x8B, 0x45, 0xF4,
		0x89, 0x82, 0x08, 0x01, 0x00, 0x00,
		0x8B, 0x45, 0xF0,
		0x8B, 0xE5,
		0x5D,
		0xC3,
};
#endif

// Calling LoadLibraryA in target process using Shellcode
bool tInjector::method::remoteLoadLibrary(const char* TargetProcessName, const char* TargetModulePath, tInjector::InjectionMethod Method)
{
	LPVOID pShellCodeThreadHijack = nullptr;
	LPVOID pTargetShellCodeThreadHijack = nullptr;

#ifdef _WIN64
	LPVOID pTargetRtlRestoreContextThreadHijack = nullptr;
#endif

	LPVOID pTargetShellCodeParam = nullptr;
	LPVOID pTargetShellCode = nullptr;
	DWORD exitCode = 1;

	char absolutePath[MAX_PATH] = { 0 };
	strcpy_s(absolutePath, MAX_PATH, TargetModulePath);

	if (!tInjector::helper::toAbsolutePath(absolutePath)) {
		tInjector::logln("Failed to get absolute path");
		return false;
	}

	auto pid = tInjector::helper::getProcessIdByName(TargetProcessName);
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

	// Allocate & Write Shellcode Param to Target Process Space
	{
		ShellCode_t param = { 0 };
		param.pLoadLibraryA = LoadLibraryA;
		strcpy_s(param.path, absolutePath);

		pTargetShellCodeParam = VirtualAllocEx(hProcess, nullptr, sizeof(ShellCode_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pTargetShellCodeParam)
		{
			tInjector::logln("VirtualAllocEx failed with code: %d", GetLastError());
			goto free;
		}

		if (!WriteProcessMemory(hProcess, pTargetShellCodeParam, &param, sizeof(ShellCode_t), nullptr))
		{
			tInjector::logln("WriteProcessMemory failed with code: %d", GetLastError());
			goto free;
		}
	}

	// Allocate & Write Shellcode
	{
		pTargetShellCode = VirtualAllocEx(hProcess, NULL, tInjector_ARRLEN(ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetShellCode)
		{
			tInjector::logln("VirtualAllocEx failed with code: %d", GetLastError());
			goto free;
		}

		if (!WriteProcessMemory(hProcess, pTargetShellCode, ShellCode, tInjector_ARRLEN(ShellCode), NULL))
		{
			tInjector::logln("WriteProcessMemory failed with code: %d", GetLastError());
			goto free;
		}
	}

	switch (Method)
	{
	case InjectionMethod::CreateRemoteThread:
	{
		// Execute the Shellcode
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
				ShellCode_t sc = { 0 };
				sc.ret = EShellCodeRet::SHELLCODE_UNKOWN;
				while (sc.ret == EShellCodeRet::SHELLCODE_UNKOWN)
				{
					if (ReadProcessMemory(hProcess, pTargetShellCodeParam, &sc, sizeof(ShellCode_t), nullptr))
					{
						if (sc.ret == EShellCodeRet::SHELLCODE_SUCCESS)
						{
							tInjector::logln("Successfully injected module: %s", absolutePath);
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

	case InjectionMethod::ThreadHijacking:
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

#ifdef _WIN64
		auto storedRip = c.Rip;
#else
		auto storedEip = c.Eip;
#endif

#ifdef _WIN64
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
#endif

		// allocate & write shellcode to hijack the thread
		{
			pTargetShellCodeThreadHijack = VirtualAllocEx(hProcess, nullptr, tInjector::hijack::getShellcodeSize(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!pTargetShellCodeThreadHijack)
			{
				tInjector::logln("VirtualAllocEx failed with code: %d", GetLastError());
				goto free;
			}

			// set up the shellcode
			pShellCodeThreadHijack = VirtualAlloc(nullptr, tInjector::hijack::getShellcodeSize(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!pShellCodeThreadHijack)
			{
				tInjector::logln("VirtualAlloc failed with code: %d", GetLastError());
				goto free;
			}

			// copy the shellcode into the buffer
			memcpy(pShellCodeThreadHijack, tInjector::hijack::getShellcode(), tInjector::hijack::getShellcodeSize());

			// prepare the shellcode
			{
#ifdef _WIN64
				*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x18) = reinterpret_cast<tDWORD>(pTargetShellCode);
				*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x22) = reinterpret_cast<tDWORD>(pTargetShellCodeParam);
				*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x2E) = reinterpret_cast<tDWORD>(pTargetRtlRestoreContextThreadHijack);
				*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x38) = reinterpret_cast<tDWORD>(RtlRestoreContext);
#else
				*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x6) = storedEip;
				*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0xF) = reinterpret_cast<tDWORD>(pTargetShellCode);
				*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x14) = reinterpret_cast<tDWORD>(pTargetShellCodeParam);
#endif
			}

			if (!WriteProcessMemory(hProcess, pTargetShellCodeThreadHijack, pShellCodeThreadHijack, tInjector::hijack::getShellcodeSize(), nullptr))
			{
				tInjector::logln("WriteProcessMemory failed with code: %d", GetLastError());
				goto free;
			}
		}

#ifdef _WIN64
		c.Rip = reinterpret_cast<tDWORD>(pTargetShellCodeThreadHijack);
#else
		c.Eip = reinterpret_cast<DWORD>(pTargetShellCodeThreadHijack);
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
				c.Rip = storedRip;
			#else
				c.Eip = storedEip;
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

		ShellCode_t sc = { 0 };
		sc.ret = EShellCodeRet::SHELLCODE_UNKOWN;
		while (sc.ret == EShellCodeRet::SHELLCODE_UNKOWN)
		{
			if (ReadProcessMemory(hProcess, pTargetShellCodeParam, &sc, sizeof(ShellCode_t), nullptr))
			{
				if (sc.ret == EShellCodeRet::SHELLCODE_SUCCESS)
				{
					tInjector::logln("Successfully injected module: %s", absolutePath);
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
	// free up allocated memory
	if (pShellCodeThreadHijack)
	{
		VirtualFree(pShellCodeThreadHijack, 0, MEM_RELEASE);
		pShellCodeThreadHijack = nullptr;
	}

#ifdef _WIN64
	if (pTargetRtlRestoreContextThreadHijack)
	{
		VirtualFree(pTargetRtlRestoreContextThreadHijack, 0, MEM_RELEASE);
		pTargetRtlRestoreContextThreadHijack = nullptr;
	}
#endif

	if (pTargetShellCodeThreadHijack)
	{
		VirtualFreeEx(hProcess, pTargetShellCodeThreadHijack, 0, MEM_RELEASE);
		pTargetShellCodeThreadHijack = nullptr;
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