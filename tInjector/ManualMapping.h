#pragma once

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#include "main.h"
#include "Executor.h"
#include "Memory.h"

namespace Injector
{
	namespace Method
	{
		bool manualMapping(CMemory* pMemory, const char* targetModulePath, Executor::EMethod method, unsigned opt = 0);
	}
}