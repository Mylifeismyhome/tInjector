#include "Remote_LoadLibrary.h"
#include "Executor.h"

struct TShellCodeParam
{
	LPVOID pLoadLibraryA;
	char path[MAX_PATH];
	EShellCodeRet ret;
};

/*tDWORD ShellCode(LPVOID param)
{
	ShellCode_t* sc = (ShellCode_t*)param;

	typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR lpLibFileName);
	tLoadLibraryA fnc = (tLoadLibraryA)sc->pLoadLibraryA;
	int ret = fnc(sc->path) ? 0 : 1;
	sc->ret = ret ? EShellCodeRet::SHELLCODE_FAILED : EShellCodeRet::SHELLCODE_SUCCESS;

	return ret;
}*/

// ByteCode Array of the 'ShellCode' function
#ifdef _WIN64
static BYTE ShellCode[] =
{
		0x48, 0x89, 0x4C, 0x24, 0x08,
		0x55,
		0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,
		0x48, 0x8D, 0x6C, 0x24, 0x20,
		0x48, 0x8B, 0x45, 0x70,
		0x48, 0x89, 0x45, 0x00,
		0x48, 0x8B, 0x45, 0x00,
		0x48, 0x8B, 0x00,
		0x48, 0x89, 0x45, 0x08,
		0x48, 0x8B, 0x45, 0x00,
		0x48, 0x83, 0xC0, 0x08,
		0x48, 0x8B, 0xC8,
		0xFF, 0x55, 0x08,
		0x48, 0x85, 0xC0,
		0x74, 0x09,
		0xC7, 0x45, 0x54, 0x00, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0x54, 0x01, 0x00, 0x00, 0x00,
		0x8B, 0x45, 0x54,
		0x89, 0x45, 0x10,
		0x83, 0x7D, 0x10, 0x00,
		0x74, 0x09,
		0xC7, 0x45, 0x54, 0x02, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0x54, 0x01, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x45, 0x00,
		0x8B, 0x4D, 0x54,
		0x89, 0x88, 0x0C, 0x01, 0x00, 0x00,
		0x48, 0x63, 0x45, 0x10,
		0x48, 0x8D, 0x65, 0x60,
		0x5D,
		0xC3,
};
#else
static BYTE ShellCode[] = {
		0x55,
		0x8B, 0xEC,
		0x83, 0xEC, 0x14,
		0x8B, 0x45, 0x08,
		0x89, 0x45, 0xFC,
		0x8B, 0x4D, 0xFC,
		0x8B, 0x11,
		0x89, 0x55, 0xEC,
		0x8B, 0x45, 0xFC,
		0x83, 0xC0, 0x04,
		0x50,
		0xFF, 0x55, 0xEC,
		0x85, 0xC0,
		0x74, 0x09,
		0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0xF8, 0x01, 0x00, 0x00, 0x00,
		0x8B, 0x4D, 0xF8,
		0x89, 0x4D, 0xF0,
		0x83, 0x7D, 0xF0, 0x00,
		0x74, 0x09,
		0xC7, 0x45, 0xF4, 0x02, 0x00, 0x00, 0x00,
		0xEB, 0x07,
		0xC7, 0x45, 0xF4, 0x01, 0x00, 0x00, 0x00,
		0x8B, 0x55, 0xFC,
		0x8B, 0x45, 0xF4,
		0x89, 0x82, 0x08, 0x01, 0x00, 0x00,
		0x8B, 0x45, 0xF0,
		0x8B, 0xE5,
		0x5D,
		0xC3,
};
#endif

static EShellCodeRet fncReadShellCodeStatus(Injector::CMemory* pMemory, LPVOID pParam) {
	TShellCodeParam scp = { 0 };
	scp.ret = EShellCodeRet::SHELLCODE_UNKOWN;

	while (scp.ret == EShellCodeRet::SHELLCODE_UNKOWN)
	{
		if(!pMemory->read(pParam, &scp, sizeof(TShellCodeParam)))
		{
			break;
		}

		Sleep(100);
	}

	return scp.ret;
}

bool Injector::Method::remoteLoadLibrary(CMemory* pMemory, const char* targetModulePath, Executor::EMethod method)
{
	bool ret = false;

	LPVOID pTargetShellCodeParam = nullptr;
	LPVOID pTargetShellCode = nullptr;

	char absolutePath[MAX_PATH] = { 0 };
	strcpy_s(absolutePath, MAX_PATH, targetModulePath);

	TShellCodeParam scp = { 0 };
	scp.ret = EShellCodeRet::SHELLCODE_UNKOWN;

	if (!Injector::helper::toAbsolutePath(absolutePath)) {
		Injector::logln("failed to get absolute path");
		goto free;
	}

	// Allocate & Write Shellcode Param to Target Process Space
	{
		scp.pLoadLibraryA = LoadLibraryA;
		strcpy_s(scp.path, absolutePath);

		pTargetShellCodeParam = pMemory->alloc(sizeof(TShellCodeParam), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!pTargetShellCodeParam)
		{
			Injector::logln("alloc failed (%d)", pMemory->getLastError());
			goto free;
		}

		if(!pMemory->write(pTargetShellCodeParam, &scp, sizeof(TShellCodeParam)))
		{
			Injector::logln("write failed (%d)", pMemory->getLastError());
			goto free;
		}
	}

	// Allocate & Write Shellcode
	{
		pTargetShellCode = pMemory->alloc(tInjector_ARRLEN(ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pTargetShellCode)
		{
			Injector::logln("alloc failed (%d)", pMemory->getLastError());
			goto free;
		}

		if (!pMemory->write(pTargetShellCode, ShellCode, tInjector_ARRLEN(ShellCode)))
		{
			Injector::logln("write failed (%d)", pMemory->getLastError());
			goto free;
		}
	}

	// execute shellcode
	if (!Injector::Executor::autoDetect(pMemory, method, pTargetShellCode, pTargetShellCodeParam, fncReadShellCodeStatus)) {
		goto free;
	}

	// success
	ret = true;

free:
	// free up allocated memory
	pMemory->free(pTargetShellCodeParam);
	pMemory->free(pTargetShellCode);

	return ret;
}