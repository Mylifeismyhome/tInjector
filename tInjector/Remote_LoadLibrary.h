#pragma once
#include "main.h"

namespace tInjector
{
	namespace method
	{
		bool RemoteLoadLibrary(const char* TargetProcessName, const char* TargetModulePath);
	}
}