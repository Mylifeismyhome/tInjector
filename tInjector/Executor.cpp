#include "Executor.h"

bool Injector::Executor::autoDetect(CMemory* pMemory, EMethod method, LPVOID ptrFunc, LPVOID ptrParam, tFncReadShellCodeStatus fncReadShellCodeStatus)
{
	switch (method) {
	case EMethod::CreateRemoteThread:
		return createRemoteThread(pMemory, ptrFunc, ptrParam, fncReadShellCodeStatus);

	case EMethod::ThreadHijacking:
		return threadHijacking(pMemory, ptrFunc, ptrParam, fncReadShellCodeStatus);

	default:
		break;
	}

	return false;
}

bool Injector::Executor::createRemoteThread(CMemory* pMemory, LPVOID ptrFunc, LPVOID ptrParam, tFncReadShellCodeStatus fncReadShellCodeStatus)
{
	bool ret = false;

	DWORD exitCode = 0;

	auto hRT = pMemory->createRemoteThread(ptrFunc, ptrParam, NULL, NULL);
	if (!hRT)
	{
		Injector::logln("CreateRemoteThread failed with code: %d", GetLastError());
		goto free;
	}

	WaitForSingleObject(hRT, INFINITE);
	GetExitCodeThread(hRT, &exitCode);

	if (exitCode != 0) {
		goto free;
	}

	if (fncReadShellCodeStatus) {
		EShellCodeRet shellcodeRet = (*fncReadShellCodeStatus)(pMemory, ptrParam);
		if (shellcodeRet != EShellCodeRet::SHELLCODE_SUCCESS) {
			goto free;
		}
	}

	// success
	ret = true;

free:
	if (hRT) {
		CloseHandle(hRT);
		hRT = nullptr;
	}

	return ret;
}

bool Injector::Executor::threadHijacking(CMemory* pMemory, LPVOID ptrFunc, LPVOID ptrParam, tFncReadShellCodeStatus fncReadShellCodeStatus)
{
	bool ret = false;

	LPVOID pShellCodeThreadHijack = nullptr;
	LPVOID pTargetShellCodeThreadHijack = nullptr;

#ifdef _WIN64
	LPVOID pTargetRtlRestoreContextThreadHijack = nullptr;
#endif

	CONTEXT c = { 0 };
	c.ContextFlags = CONTEXT_FULL;

#ifdef _WIN64
	DWORD64 storedRip = 0;
#else
	DWORD storedEip = 0;
#endif

	THREADENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);

	HANDLE hThread = nullptr;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnap)
	{
		Injector::logln("CreateToolhelp32Snapshot failed");
		goto free;
	}

	if (Thread32First(hSnap, &entry))
	{
		do
		{
			if (entry.th32OwnerProcessID == pMemory->getProcessId())
			{
				hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
				if (hThread) break;
			}
		} while (Thread32Next(hSnap, &entry));
	}

	CloseHandle(hSnap);

	if (!hThread)
	{
		Injector::logln("No Thread found to hijack");
		goto free;
	}

	if (SuspendThread(hThread) == -1)
	{
		Injector::logln("SuspendThread failed with code: %d", GetLastError());
		goto free;
	}

	if (!GetThreadContext(hThread, &c))
	{
		Injector::logln("GetThreadContext failed with code: %d", GetLastError());
		goto free;
	}

#ifdef _WIN64
	storedRip = c.Rip;
#else
	storedEip = c.Eip;
#endif

	// allocate & write shellcode to hijack the thread
	{
		pTargetShellCodeThreadHijack = pMemory->alloc(Injector::hijack::getShellcodeSize(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetShellCodeThreadHijack)
		{
			Injector::logln("VirtualAllocEx failed with code: %d", GetLastError());
			goto free;
		}

		// set up the shellcode
		pShellCodeThreadHijack = VirtualAlloc(nullptr, Injector::hijack::getShellcodeSize(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pShellCodeThreadHijack)
		{
			Injector::logln("VirtualAlloc failed with code: %d", GetLastError());
			goto free;
		}

		// copy the shellcode into the buffer
		memcpy(pShellCodeThreadHijack, Injector::hijack::getShellcode(), Injector::hijack::getShellcodeSize());

		// prepare the shellcode
		{
#ifdef _WIN64
			*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x18) = reinterpret_cast<tDWORD>(pTargetShellCode);
			*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x22) = reinterpret_cast<tDWORD>(pTargetShellCodeParam);
			*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x2E) = reinterpret_cast<tDWORD>(pTargetRtlRestoreContextThreadHijack);
			*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x38) = reinterpret_cast<tDWORD>(RtlRestoreContext);
#else
			*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x6) = storedEip;
			*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0xF) = reinterpret_cast<tDWORD>(ptrFunc);
			*reinterpret_cast<tDWORD*>(reinterpret_cast<tDWORD>(pShellCodeThreadHijack) + 0x14) = reinterpret_cast<tDWORD>(ptrParam);
#endif
		}

		if(!pMemory->write(pTargetShellCodeThreadHijack, pShellCodeThreadHijack, Injector::hijack::getShellcodeSize()))
		{
			Injector::logln("WriteProcessMemory failed with code: %d", GetLastError());
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
		Injector::logln("SetThreadContext failed with code: %d", GetLastError());

		if (ResumeThread(hThread) == -1)
		{
			Injector::logln("ResumeThread failed with code: %d", GetLastError());
		}

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
			Injector::logln("SetThreadContext failed with code: %d", GetLastError());
			goto free;
		}

		Injector::logln("ResumeThread failed with code: %d", GetLastError());
		goto free;
	}

	if (fncReadShellCodeStatus) {
		EShellCodeRet shellcodeRet = (*fncReadShellCodeStatus)(pMemory, ptrParam);
		if (shellcodeRet != EShellCodeRet::SHELLCODE_SUCCESS) {
			goto free;
		}
	}

	// success
	ret = true;

free:
	if (hThread) {
		CloseHandle(hThread);
		hThread = nullptr;
	}

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

	pMemory->free(pTargetShellCodeThreadHijack);

	return ret;
}