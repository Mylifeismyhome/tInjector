#pragma once
#define tInjector_ARRLEN(x) sizeof(x) / sizeof(x[0])

#include <Windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <vector>
#include <string>

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
		DWORD getProcessIdByName(const char* pName);
		DWORD getPEHeaderSize(const IMAGE_NT_HEADERS* pNTH);
		bool toAbsolutePath(char* path);
	}

	enum class InjectionMethod
	{
		CreateRemoteThread = 0,
		ThreadHijacking
	};

	namespace hijack
	{
		BYTE* getShellcode();
		size_t getShellcodeSize();
	}

	namespace option
	{
		bool erasePEHeader(HANDLE hProcess, PVOID base, size_t peSize);
	}

	void log(const char c);
	void log(const char* msg, ...);
	void logln(const char* msg, ...);
}