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
bool tInjector::method::RemoteLoadLibrary(const char* TargetProcessName, const char* TargetModulePath)
{
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

free:
	// free up allocated memory
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