#include "SetWindowsHookEx.h"
#include <psapi.h>

/*
* as an example
* in your module (dll)
* just create a function and export it
* like this
* 
*	static bool isEntryPointExecuted = false;
*	extern "C" __declspec(dllexport) void DllEntryPoint()
*	{
*		if (isEntryPointExecuted)
*			return;
*
*		isEntryPointExecuted = true;
*		MessageBoxA(nullptr, "HELLOW", "HELLE", MB_OK);
*	}
* 
* now passing the parameter 'EntryPointName' in 'SetWindowsHookEx' as 'DllEntryPoint'
* will get resolved by GetProcAddress function
*/

struct TWindowsProc
{
	char* targetProcessName;
	DWORD dwThreadId, dwProcessId;
	HINSTANCE hInstance;
	HWND hWnd;
	bool valid;
};

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	TWindowsProc* windowsProc = (TWindowsProc*)lParam;

	// function that prints Windows and their handles
	DWORD dwThreadId, dwProcessId;
	HINSTANCE hInstance;
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
		auto modName = std::string(modulefilename);
		auto i = modName.find_last_of('\\');
		if (i != std::string::npos)
		{
			modName = modName.substr(i + 1, modName.size() - i - 1);
		}

		if (!strcmp(modName.data(), windowsProc->targetProcessName))
		{
			windowsProc->dwProcessId = dwProcessId;
			windowsProc->dwThreadId = dwThreadId;
			windowsProc->hInstance = hInstance;
			windowsProc->hWnd = hWnd;
			windowsProc->valid = true;
		}
	}

	CloseHandle(hProcess);
	return TRUE;
}

static bool isEntryPointExecuted = false;
VOID CALLBACK CSendMessageCallback(__in  HWND hwnd,
	__in  UINT uMsg,
	__in  ULONG_PTR dwData,
	__in  LRESULT lResult)
{
	isEntryPointExecuted = true;
}

bool tInjector::method::setWindowsHookEx(const char* TargetProcessName, const char* TargetModulePath, const char* EntryPointName)
{
	char absolutePath[MAX_PATH] = { 0 };
	strcpy_s(absolutePath, MAX_PATH, TargetModulePath);

	if (!tInjector::helper::toAbsolutePath(absolutePath)) {
		tInjector::logln("Failed to get absolute path");
		return false;
	}

	/*
	* to perform injection over SetWindowsHookEx
	* we do require a valid HWND
	* EnumWindows all windows
	* get the executeable name by using GetModuleFileNameExA
	* check if it matches TargetProcessName
	* and if does then store the HWND for further use
	*/
	TWindowsProc* windowsProc = new TWindowsProc();
	windowsProc->targetProcessName = _strdup(TargetProcessName);
	windowsProc->valid = false;
	EnumWindows(EnumWindowsProc, (LPARAM)windowsProc);
	free(windowsProc->targetProcessName);

	HMODULE hModule = nullptr;
	HOOKPROC pMainEntry = nullptr;
	HHOOK hHooked = nullptr;

	if (!windowsProc->valid)
	{
		tInjector::logln("EnumWindowsProc not found a window");
		goto clean;
	}

	/*
	* first we do need to load the target module by using LoadLibraryExA
	* with the dwflag of DONT_RESOLVE_DLL_REFERENCES
	* DONT_RESOLVE_DLL_REFERENCES will load up the module but will not call the dllmain entry (or whatever the entrypoint is set to)
	*/
	hModule = LoadLibraryExA(absolutePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!hModule)
	{
		tInjector::logln("LoadLibraryExA failed with code: %d", GetLastError());
		goto clean;
	}

	/*
	* since we do not call the entry point automatically
	* we will need to obtain an exported function from the module
	* that we want to call and in our case we will use it as an entry point
	*/
	pMainEntry = (HOOKPROC)GetProcAddress(hModule, EntryPointName);
	if (!pMainEntry)
	{
		tInjector::logln("'%s' is not exported", EntryPointName);
		goto clean;
	}

	/*
	* now we simply call SetWindowsHookExA with any idHook, in our case WH_GETMESSAGE
	* the function we do want to be called is our resolved entry point from our loaded module
	*/
	hHooked = SetWindowsHookExA(WH_GETMESSAGE, pMainEntry, hModule, windowsProc->dwThreadId);
	if (!hHooked)
	{
		tInjector::logln("SetWindowsHookExA failed with code: %d", GetLastError());
		goto clean;
	}

	/*
	* SendMessageCallback to retrieve a callback when the event with idHook of WH_GETMESSAGE have been called
	*/
	SendMessageCallback(windowsProc->hWnd, WH_GETMESSAGE, 0, 0, CSendMessageCallback, 0);

	/*
	* https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessage
	* Sends the specified message to a window or windows. The SendMessage function calls the window procedure for the specified window and does not return until the window procedure has processed the message.
	*/
	SendMessage(windowsProc->hWnd, WH_GETMESSAGE, NULL, NULL);

	/*
	* https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea
	* Places (posts) a message in the message queue associated with the thread that created the specified window and returns without waiting for the thread to process the message.
	*/
	if (!PostMessage(windowsProc->hWnd, WM_NULL, NULL, NULL))
	{
		tInjector::logln("PostMessage failed with code: %d", GetLastError());
		goto clean;
	}

	/*
	* wait until the event have been called so on our callback was called
	* in our callback we set 'isEntryPointExecuted' to 'true'
	*/
	while (!isEntryPointExecuted)
	{
		Sleep(1);
	}

	/*
	* function was called so now do unhook it before it does get called again
	*/
	if (!UnhookWindowsHookEx(hHooked))
	{
		tInjector::logln("UnhookWindowsHookEx failed with code: %d", GetLastError());
	}

clean:
	if (hModule && !FreeLibrary(hModule))
	{
		tInjector::logln("FreeLibrary failed with code: %d", GetLastError());
	}

	delete windowsProc;
	return false;
}