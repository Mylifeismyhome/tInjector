#include "SetWindowsHookEx.h"
#include <psapi.h>

struct TWindowsProc
{
	char* m_TargetProcessName;
	DWORD dwThreadId, dwProcessId;
	HINSTANCE hInstance;
	HWND hWnd;
	bool valid;
};

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	TWindowsProc* m_WindowsProc = (TWindowsProc*)lParam;

	// function that prints Windows and their handles
	DWORD dwThreadId, dwProcessId;
	HINSTANCE hInstance;
	char title[255];
	char modulefilename[255];
	HANDLE hProcess;

	if (!hWnd)
	{
		return TRUE;		// Not a window
	}

	hInstance = (HINSTANCE)GetWindowLong(hWnd, -6);
	dwThreadId = GetWindowThreadProcessId(hWnd, &dwProcessId);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	// GetModuleFileNameEx uses psapi, which works for NT only!
	if (GetModuleFileNameExA(hProcess, hInstance, modulefilename, sizeof(modulefilename)))
	{
		auto m_modName = std::string(modulefilename);
		auto i = m_modName.find_last_of('\\');
		if (i != std::string::npos)
		{
			m_modName = m_modName.substr(i + 1, m_modName.size() - i - 1);
		}

		//tInjector::logln("Window: %s", m_modName.data());

		if (!strcmp(m_modName.data(), m_WindowsProc->m_TargetProcessName))
		{
			m_WindowsProc->dwProcessId = dwProcessId;
			m_WindowsProc->dwThreadId = dwThreadId;
			m_WindowsProc->hInstance = hInstance;
			m_WindowsProc->hWnd = hWnd;
			m_WindowsProc->valid = true;
		}
	}

	CloseHandle(hProcess);
	return TRUE;
}

static bool m_EntryPointExecuted = false;
VOID CALLBACK CSendMessageCallback(__in  HWND hwnd,
	__in  UINT uMsg,
	__in  ULONG_PTR dwData,  // This is *the* 0
	__in  LRESULT lResult)   // The result from the callee
{
	m_EntryPointExecuted = true;
}

bool tInjector::method::SetWindowsHookEx(const char* TargetProcessName, const char* TargetModulePath, const char* EntryPointName)
{
	TWindowsProc* m_WindowsProc = new TWindowsProc();
	m_WindowsProc->m_TargetProcessName = _strdup(TargetProcessName);
	m_WindowsProc->valid = false;
	EnumWindows(EnumWindowsProc, (LPARAM)m_WindowsProc);
	free(m_WindowsProc->m_TargetProcessName);

	HMODULE m_hModule = nullptr;
	HOOKPROC m_pMainEntry = nullptr;
	HHOOK m_HHooked = nullptr;

	if (!m_WindowsProc->valid)
	{
		tInjector::logln("EnumWindowsProc not found a window");
		goto clean;
	}

	m_hModule = LoadLibraryExA(TargetModulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!m_hModule)
	{
		tInjector::logln("LoadLibraryExA failed with code: %d", GetLastError());
		goto clean;
	}

	m_pMainEntry = (HOOKPROC)GetProcAddress(m_hModule, EntryPointName);
	if (!m_pMainEntry)
	{
		tInjector::logln("'%s' is not exported", EntryPointName);
		goto clean;
	}

	m_HHooked = SetWindowsHookExA(WH_GETMESSAGE, m_pMainEntry, m_hModule, m_WindowsProc->dwThreadId);
	if (!m_HHooked)
	{
		tInjector::logln("SetWindowsHookExA failed with code: %d", GetLastError());
		goto clean;
	}

	SendMessageCallback(m_WindowsProc->hWnd, WH_GETMESSAGE, 0, 0, CSendMessageCallback, 0);
	SendMessage(m_WindowsProc->hWnd, WH_GETMESSAGE, NULL, NULL);

	if (!PostMessage(m_WindowsProc->hWnd, WM_NULL, NULL, NULL))
	{
		tInjector::logln("PostMessage failed with code: %d", GetLastError());
		goto clean;
	}

	while (!m_EntryPointExecuted)
	{
		Sleep(1);
	}

	if (!UnhookWindowsHookEx(m_HHooked))
	{
		tInjector::logln("UnhookWindowsHookEx failed with code: %d", GetLastError());
	}

clean:
	if (m_hModule
		&& !FreeLibrary(m_hModule))
	{
		tInjector::logln("FreeLibrary failed with code: %d", GetLastError());
	}

	delete m_WindowsProc;
	return false;
}