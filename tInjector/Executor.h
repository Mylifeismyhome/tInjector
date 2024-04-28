#pragma once
#include "main.h"
#include "Memory.h"

namespace Injector
{
	namespace Executor 
	{
		enum class EMethod
		{
			CreateRemoteThread = 0,
			ThreadHijacking
		};

		typedef EShellCodeRet(*tFncReadShellCodeStatus)(CMemory* pMemory, LPVOID pParam);
		bool autoDetect(CMemory* pMemory, EMethod method, LPVOID ptrFunc, LPVOID ptrParam, tFncReadShellCodeStatus fncReadShellCodeStatus);
		bool createRemoteThread(CMemory* pMemory, LPVOID ptrFunc, LPVOID ptrParam, tFncReadShellCodeStatus fncReadShellCodeStatus);
		bool threadHijacking(CMemory* pMemory, LPVOID ptrFunc, LPVOID ptrParam, tFncReadShellCodeStatus fncReadShellCodeStatus);
	}
}