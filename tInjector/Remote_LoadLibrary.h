#pragma once
#include "main.h"

namespace tInjector
{
	namespace method
	{
		bool remoteLoadLibrary(const char* TargetProcessName, const char* TargetModulePath, tInjector::InjectionMethod Method);
	}
}