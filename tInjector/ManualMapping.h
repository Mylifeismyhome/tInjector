#pragma once

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#include "main.h"

namespace tInjector
{
	namespace method
	{
		bool ManualMapping(const char* TargetProcessName, const char* TargetModulePath, tInjector::InjectionMethod Method, unsigned m_opt = 0);
	}
}