#pragma once
#include "main.h"
#include "Executor.h"
#include "Memory.h"

namespace Injector
{
	namespace Method
	{
		bool remoteLoadLibrary(CMemory* pMemory, const char* targetModulePath, Executor::EMethod method);
	}
}