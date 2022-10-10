#pragma once
#define tInjector_ARRLEN(x) sizeof(x) / sizeof(x[0])

#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

namespace tInjector
{
	namespace helper
	{
		DWORD GetProcessIdByName(const char* pName);
		DWORD GetPEHeaderSize(const IMAGE_NT_HEADERS* pNTH);
	}

	void log(const char c);
	void log(const char* msg, ...);
	void logln(const char* msg, ...);
}