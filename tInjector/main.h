#pragma once
#define tInjector_ARRLEN(x) sizeof(x) / sizeof(x[0])

#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

#ifdef _WIN64
typedef DWORD64 tDWORD;
#else
typedef DWORD32 tDWORD;
#endif

#define OPT_ERASE_PE_HEADER 1 << 1

namespace tInjector
{
	namespace helper
	{
		DWORD GetProcessIdByName(const char* pName);
		DWORD GetPEHeaderSize(const IMAGE_NT_HEADERS* pNTH);
	}

	enum class InjectionMethod
	{
		CreateRemoteThread = 0,
		ThreadHijacking
	};

	namespace hijack
	{
		BYTE* GetShellcode();
		size_t GetShellcodeSize();
	}

	namespace option
	{
		bool erase_pe_header(HANDLE m_hProcess, PVOID m_base, size_t m_pe_size);
	}

	void log(const char c);
	void log(const char* msg, ...);
	void logln(const char* msg, ...);
}