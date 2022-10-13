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

	void log(const char c);
	void log(const char* msg, ...);
	void logln(const char* msg, ...);
}