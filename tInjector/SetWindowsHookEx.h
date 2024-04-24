#pragma once
#include "main.h"
#undef SetWindowsHookEx

namespace tInjector
{
	namespace method
	{
		bool setWindowsHookEx(const char* TargetProcessName, const char* TargetModulePath, const char* EntryPointName);
	}
}