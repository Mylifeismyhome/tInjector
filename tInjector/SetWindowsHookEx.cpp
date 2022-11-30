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
	__in  ULONG_PTR dwData,
	__in  LRESULT lResult)
{
	m_EntryPointExecuted = true;
}

bool tInjector::method::SetWindowsHookEx(const char* TargetProcessName, const char* TargetModulePath, const char* EntryPointName)
{
	/*
	* to perform injection over SetWindowsHookEx
	* we do require a valid HWND
	* EnumWindows all windows
	* get the executeable name by using GetModuleFileNameExA
	* check if it matches TargetProcessName
	* and if does then store the HWND for further use
	*/
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

	/*
	* first we do need to load the target module by using LoadLibraryExA
	* with the dwflag of DONT_RESOLVE_DLL_REFERENCES
	* DONT_RESOLVE_DLL_REFERENCES will load up the module but will not call the dllmain entry (or whatever the entrypoint is set to)
	*/
	m_hModule = LoadLibraryExA(TargetModulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!m_hModule)
	{
		tInjector::logln("LoadLibraryExA failed with code: %d", GetLastError());
		goto clean;
	}

	/*
	* since we do not call the entry point automatically
	* we will need to obtain an exported function from the module
	* that we want to call and in our case we will use it as an entry point
	*/
	m_pMainEntry = (HOOKPROC)GetProcAddress(m_hModule, EntryPointName);
	if (!m_pMainEntry)
	{
		tInjector::logln("'%s' is not exported", EntryPointName);
		goto clean;
	}

	/*
	* now we simply call SetWindowsHookExA with any idHook, in our case WH_GETMESSAGE
	* the function we do want to be called is our resolved entry point from our loaded module
	*/
	m_HHooked = SetWindowsHookExA(WH_GETMESSAGE, m_pMainEntry, m_hModule, m_WindowsProc->dwThreadId);
	if (!m_HHooked)
	{
		tInjector::logln("SetWindowsHookExA failed with code: %d", GetLastError());
		goto clean;
	}

	/*
	* SendMessageCallback to retrieve a callback when the event with idHook of WH_GETMESSAGE have been called
	*/
	SendMessageCallback(m_WindowsProc->hWnd, WH_GETMESSAGE, 0, 0, CSendMessageCallback, 0);

	/*
	* https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessage
	* Sends the specified message to a window or windows. The SendMessage function calls the window procedure for the specified window and does not return until the window procedure has processed the message.
	*/
	SendMessage(m_WindowsProc->hWnd, WH_GETMESSAGE, NULL, NULL);

	/*
	* https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea
	* Places (posts) a message in the message queue associated with the thread that created the specified window and returns without waiting for the thread to process the message.
	*/
	if (!PostMessage(m_WindowsProc->hWnd, WM_NULL, NULL, NULL))
	{
		tInjector::logln("PostMessage failed with code: %d", GetLastError());
		goto clean;
	}

	/*
	* wait until the event have been called so on our callback was called
	* in our callback we set 'm_EntryPointExecuted' to 'true'
	*/
	while (!m_EntryPointExecuted)
	{
		Sleep(1);
	}

	/*
	* function was called so now do unhook it before it does get called again
	*/
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