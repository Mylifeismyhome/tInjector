#define tInjector_ARRLEN(x) sizeof(x) / sizeof(x[0])

#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

namespace tInjector
{
	DWORD GetProcessIdByName(const char* pName)
	{
		auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!hSnap) return 0;

		size_t pNameLen = strlen(pName);

		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);

		if (Process32First(hSnap, &entry))
		{
			do
			{
				if (!memcmp(pName, entry.szExeFile, pNameLen))
				{
					return entry.th32ProcessID;
				}

			} while (Process32Next(hSnap, &entry));
		}

		return 0;
	}

	void log(const char c)
	{
		std::cout << c;
	}

	void log(const char* msg, ...)
	{
		va_list vaArgs;
		va_start(vaArgs, msg);
		const size_t size = std::vsnprintf(nullptr, 0, msg, vaArgs);
		std::vector<char> str(size + 1);
		std::vsnprintf(str.data(), str.size(), msg, vaArgs);
		va_end(vaArgs);

		std::cout << str.data();
	}

	void logln(const char* msg, ...)
	{
		va_list vaArgs;
		va_start(vaArgs, msg);
		const size_t size = std::vsnprintf(nullptr, 0, msg, vaArgs);
		std::vector<char> str(size + 1);
		std::vsnprintf(str.data(), str.size(), msg, vaArgs);
		va_end(vaArgs);

		std::cout << str.data() << std::endl;
	}
}

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

int main()
{
	tInjector::logln("Enter Processname:");

	std::string TargetProcessName;
	std::cin >> TargetProcessName;

	tInjector::logln("Enter target module path:");

	std::string TargetModulePath;
	std::cin >> TargetModulePath;

	// injection routine //
	LPVOID pTargetShellCodeParam = nullptr;
	LPVOID pTargetShellcode = nullptr;

	auto pid = tInjector::GetProcessIdByName(TargetProcessName.data());
	if (!pid)
	{
		tInjector::logln("Process not found");
		return 0;
	}

	auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
	{
		tInjector::logln("OpenProcess failed with code: %d", GetLastError());
		return 0;
	}

	// Allocate & Write Shellcode Param to Target Process Space
	{
		ShellCode_t param = { 0 };
		param.pLoadLibraryA = &LoadLibraryA; // use LoadLibraryA
		strcpy_s(param.path, TargetModulePath.data());

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

		DWORD exitCode = 0;
		GetExitCodeThread(hRT, &exitCode);

		if (!exitCode)
		{
			tInjector::logln("Successfully injected module: %s", TargetModulePath.data());
		}
		else
		{
			tInjector::logln("Injection failed with error: %d", GetLastError());
		}
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
	return 0;
}