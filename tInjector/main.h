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

enum class EShellCodeRet
{
	SHELLCODE_UNKOWN = 0,
	SHELLCODE_SUCCESS,
	SHELLCODE_FAILED
};

namespace Injector
{
	namespace helper
	{
		DWORD getProcessIdByName(const char* pName);
		DWORD getPEHeaderSize(const IMAGE_NT_HEADERS* pNTH);
		bool toAbsolutePath(char* path);
	}

	namespace hijack
	{
		BYTE* getShellcode();
		size_t getShellcodeSize();
	}

	void log(const char c);
	void log(const char* msg, ...);
	void logln(const char* msg, ...);
}