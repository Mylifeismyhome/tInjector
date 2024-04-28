#include "Memory.h"

Injector::CMemory::CMemory()
{
	processId = 0;
	hProcess = NULL;
}

Injector::CMemory::~CMemory()
{
}

DWORD Injector::CMemory::getProcessId() const
{
	return processId;
}

HANDLE Injector::CMemory::getProcessHandle() const
{
	return hProcess;
}

BOOL Injector::CMemory::write(LPVOID pAddress, LPCVOID pBuffer, size_t bufferSize)
{
	return FALSE;
}

BOOL Injector::CMemory::read(LPCVOID pAddress, LPVOID pBuffer, size_t bufferSize)
{
	return FALSE;
}

LPVOID Injector::CMemory::alloc(size_t bufferSize, DWORD type, DWORD protect)
{
	return NULL;
}

BOOL Injector::CMemory::free(LPVOID pAddress)
{
	return FALSE;
}

HANDLE Injector::CMemory::createRemoteThread(LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	return FALSE;
}

Injector::CWinApiMemory::CWinApiMemory() : CMemory()
{
}

Injector::CWinApiMemory::~CWinApiMemory()
{
	detatch();
}

BOOL Injector::CWinApiMemory::write(LPVOID pAddress, LPCVOID pBuffer, size_t bufferSize)
{
	return WriteProcessMemory(hProcess, pAddress, pBuffer, bufferSize, nullptr);
}

BOOL Injector::CWinApiMemory::read(LPCVOID pAddress, LPVOID pBuffer, size_t bufferSize)
{
	return ReadProcessMemory(hProcess, pAddress, pBuffer, bufferSize, nullptr);
}

LPVOID Injector::CWinApiMemory::alloc(size_t bufferSize, DWORD type, DWORD protect)
{
	return VirtualAllocEx(hProcess, NULL, bufferSize, type, protect);
}

BOOL Injector::CWinApiMemory::free(LPVOID pAddress)
{
	return VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
}

HANDLE Injector::CWinApiMemory::createRemoteThread(LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	return CreateRemoteThread(hProcess, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, dwCreationFlags, lpThreadId);
}

BOOL Injector::CWinApiMemory::attach(DWORD processId)
{
	if (!processId) {
		return FALSE;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess)
	{
		return FALSE;
	}

	this->processId = processId;
	this->hProcess = hProcess;

	return TRUE;
}

BOOL Injector::CWinApiMemory::attach(const char* processName)
{
	DWORD processId = Injector::helper::getProcessIdByName(processName);
	if (!processId)
	{
		return FALSE;
	}

	return attach(processId);
}

BOOL Injector::CWinApiMemory::detatch()
{
	if (!hProcess) {
		return FALSE;
	}

	if (!CloseHandle(hProcess)) {
		return FALSE;

	}

	hProcess = NULL;
	return TRUE;
}