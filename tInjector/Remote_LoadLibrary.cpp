#include "Remote_LoadLibrary.h"

struct ShellCode_t
{
	LPVOID pLoadLibraryA;
	char path[MAX_PATH];
};

/*DWORD ShellCode(LPVOID param)
{
	auto sc = (ShellCode_t*)param;

	typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR lpLibFileName);
	auto fnc = (tLoadLibraryA)sc->pLoadLibraryA;
	return fnc(sc->path) ? 0 : 1;
}*/

// it's the above function
static BYTE m_ShellCode[] = {
	0x48, 0x89, 0x4C, 0x24, 0x08,
	0x55,
	0x48, 0x81, 0xEC, 0x80, 0x0, 0x0, 0x0,
	0x48, 0x8D, 0x6C, 0x24, 0x20,
	0x48, 0x8B, 0x45, 0x70,
	0x48, 0x89, 0x45, 0x0,
	0x48, 0x8B, 0x45, 0x0,
	0x48, 0x8B, 0x0,
	0x48, 0x89, 0x45, 0x08,
	0x48, 0x8B, 0x45, 0x0,
	0x48, 0x83, 0xC0, 0x08,
	0x48, 0x8B, 0xC8,
	0x48, 0x8B, 0xC8,
	0xFF, 0x55, 0x08,
	0x48, 0x85, 0xC0,
	0x74, 0x09,
	0xC7, 0x45, 0x50, 0x0, 0x0, 0x0, 0x0,
	0xEB, 0x07,
	0xC7, 0x45, 0x50, 0x01, 0x0, 0x0, 0x0,
	0x8B, 0x45, 0x50,
	0x48, 0x8D, 0x65, 0x60,
	0x5D,
	0xC3
};

// Calling LoadLibraryA in target process using Shellcode
bool tInjector::method::RemoteLoadLibrary(const char* TargetProcessName, const char* TargetModulePath, tInjector::InjectionMethod Method)
{
	LPVOID pShellCodeThreadHijack = nullptr;
	LPVOID pTargetShellCodeThreadHijack = nullptr;
	LPVOID pTargetRtlRestoreContextThreadHijack = nullptr;
	LPVOID pTargetShellCodeParam = nullptr;
	LPVOID pTargetShellcode = nullptr;
	DWORD exitCode = 1;

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

	// Allocate & Write Shellcode Param to Target Process Space
	{
		ShellCode_t param = { 0 };
		param.pLoadLibraryA = &LoadLibraryA; // use LoadLibraryA
		strcpy_s(param.path, TargetModulePath);

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
		pTargetShellcode = VirtualAllocEx(hProcess, NULL, tInjector_ARRLEN(m_ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetShellcode)
		{
			tInjector::logln("VirtualAllocEx failed with code: %d", GetLastError());
			goto free;
		}

		if (!WriteProcessMemory(hProcess, pTargetShellcode, m_ShellCode, tInjector_ARRLEN(m_ShellCode), NULL))
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
			auto hRT = CreateRemoteThread(hProcess, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(pTargetShellcode), pTargetShellCodeParam, NULL, nullptr);
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
				*reinterpret_cast<DWORD64*>(reinterpret_cast<DWORD64>(pShellCodeThreadHijack) + 0x18) = reinterpret_cast<DWORD64>(pTargetShellCodeParam);
				*reinterpret_cast<DWORD64*>(reinterpret_cast<DWORD64>(pShellCodeThreadHijack) + 0x22) = reinterpret_cast<DWORD64>(pTargetShellcode);
				*reinterpret_cast<DWORD64*>(reinterpret_cast<DWORD64>(pShellCodeThreadHijack) + 0x2E) = reinterpret_cast<DWORD64>(pTargetRtlRestoreContextThreadHijack);
				*reinterpret_cast<DWORD64*>(reinterpret_cast<DWORD64>(pShellCodeThreadHijack) + 0x38) = reinterpret_cast<DWORD64>(&RtlRestoreContext);
			}

			if (!WriteProcessMemory(hProcess, pTargetShellCodeThreadHijack, pShellCodeThreadHijack, tInjector::hijack::GetShellcodeSize(), nullptr))
			{
				tInjector::logln("WriteProcessMemory failed with code: %d", GetLastError());
				goto free;
			}
		}

		auto storedRip = c.Rip;
		c.Rip = reinterpret_cast<DWORD64>(pTargetShellCodeThreadHijack); // write payload to hijack the thread and call our required function and then jump back to previous execution

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
			c.Rip = storedRip; // restore previous rip
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

		Sleep(10000); // todo: optimize me
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

	if (pTargetShellCodeParam)
	{
		VirtualFreeEx(hProcess, pTargetShellCodeParam, 0, MEM_RELEASE);
		pTargetShellCodeParam = nullptr;
	}

	if (pTargetShellcode)
	{
		VirtualFreeEx(hProcess, pTargetShellcode, 0, MEM_RELEASE);
		pTargetShellcode = nullptr;
	}

	CloseHandle(hProcess);

	return (exitCode == 0) ? true : false;
}