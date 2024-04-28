#pragma once
#include "main.h"

namespace Injector 
{
	class CMemory 
	{
	protected:
		DWORD processId;
		HANDLE hProcess;

	public:
		CMemory();
		~CMemory();

		DWORD getProcessId() const;
		HANDLE getProcessHandle() const;

		virtual BOOL write(LPVOID pAddress, LPCVOID pBuffer, size_t bufferSize);
		virtual BOOL read(LPCVOID pAddress, LPVOID pBuffer, size_t bufferSize);
		virtual LPVOID alloc(size_t bufferSize, DWORD type, DWORD protect);
		virtual BOOL free(LPVOID pAddress);

		virtual HANDLE createRemoteThread(LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
	};

	class CWinApiMemory : public CMemory {
	public:
		CWinApiMemory();
		~CWinApiMemory();

		BOOL write(LPVOID pAddress, LPCVOID pBuffer, size_t bufferSize) override;
		BOOL read(LPCVOID pAddress, LPVOID pBuffer, size_t bufferSize) override;
		LPVOID alloc(size_t bufferSize, DWORD type, DWORD protect) override;
		BOOL free(LPVOID pAddress) override;

		HANDLE createRemoteThread(LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) override;

		BOOL attach(DWORD processId);
		BOOL attach(const char* processName);
		BOOL detatch();
	};
}