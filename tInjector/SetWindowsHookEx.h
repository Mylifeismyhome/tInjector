#pragma once
#include "main.h"
#undef SetWindowsHookEx

namespace Injector
{
	namespace Method
	{
		bool setWindowsHookEx(const char* TargetProcessName, const char* TargetModulePath, const char* EntryPointName);
	}
}