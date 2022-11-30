#pragma once
#include "main.h"
#undef SetWindowsHookEx

namespace tInjector
{
	namespace method
	{
		bool SetWindowsHookEx(const char* TargetProcessName, const char* TargetModulePath, const char* EntryPointName);
	}
}