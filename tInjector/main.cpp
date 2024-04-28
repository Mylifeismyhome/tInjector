#include "main.h"

#include "Memory.h"
#include "Executor.h"

#include "Remote_LoadLibrary.h"
#include "ManualMapping.h"
#include "SetWindowsHookEx.h"

static unsigned getOptionsFromCMD()
{
	Injector::logln("choose additional option:\n\t1 - no option\n\t2 - erase pe header");

	std::string option;
	std::cin >> option;

	auto iOption = std::atoi(option.data()) - 1;

	unsigned ret = 0;
	switch (iOption)
	{
	case 1:
		ret |= OPT_ERASE_PE_HEADER;
		break;

	default:
		break;
	}

	return ret;
}

static int getInjectionMethodFromCMD()
{
	Injector::logln("choose executor:\n\t1 - CreateRemoteThread\n\t2 - ThreadHijacking");

	std::string injectionMethod;
	std::cin >> injectionMethod;

	return std::atoi(injectionMethod.data()) - 1;
}

static std::string getCustomEntryPointFromCMD()
{
	Injector::logln("enter custom entry point:");

	std::string customEntryPoint;
	std::cin >> customEntryPoint;

	return customEntryPoint;
}

int main()
{
	Injector::logln("enter processName:");

	std::string targetProcessName;
	std::cin >> targetProcessName;

	Injector::logln("enter module path:");

	std::string targetModulePath;
	std::cin >> targetModulePath;

	Injector::logln("choose method:\n\t1 - Remote LoadLibraryA\n\t2 - Manual Mapping\n\t3 - SetWindowsHookEx");

	std::string method;
	std::cin >> method;

	INT32 iMethod = std::atoi(method.data());

	if (iMethod == 3) {
		Injector::Method::setWindowsHookEx(targetProcessName.data(), targetModulePath.data(), getCustomEntryPointFromCMD().data());
	}
	else {
		Injector::CWinApiMemory memory;
		if (!memory.attach(targetProcessName.data())) {
			Injector::logln("failed to attach to process (%d)", GetLastError());
			return 0;
		}

		switch (iMethod)
		{
		case 1:
			Injector::Method::remoteLoadLibrary(&memory, targetModulePath.data(), static_cast<Injector::Executor::EMethod>(getInjectionMethodFromCMD()));
			break;

		case 2:
			Injector::Method::manualMapping(&memory, targetModulePath.data(), static_cast<Injector::Executor::EMethod>(getInjectionMethodFromCMD()), getOptionsFromCMD());
			break;

		default:
			break;
		}

		if (!memory.detatch()) {
			Injector::logln("failed to detatch from process (%d)", GetLastError());
		}
	}

	system("pause");
	return 0;
}

void Injector::log(const char c)
{
	std::cout << c;
}

void Injector::log(const char* msg, ...)
{
	va_list vaArgs;
	va_start(vaArgs, msg);
	const size_t size = std::vsnprintf(nullptr, 0, msg, vaArgs);
	std::vector<char> str(size + 1);
	std::vsnprintf(str.data(), str.size(), msg, vaArgs);
	va_end(vaArgs);

	std::cout << str.data();
}

void Injector::logln(const char* msg, ...)
{
	va_list vaArgs;
	va_start(vaArgs, msg);
	const size_t size = std::vsnprintf(nullptr, 0, msg, vaArgs);
	std::vector<char> str(size + 1);
	std::vsnprintf(str.data(), str.size(), msg, vaArgs);
	va_end(vaArgs);

	std::cout << "[+] " << str.data() << std::endl;
}

static const char* getParentProcessName(DWORD th32ParentProcessID)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnap) return "";

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);

	if (Process32First(hSnap, &entry))
	{
		do
		{
			if (entry.th32ProcessID == th32ParentProcessID) {
				CloseHandle(hSnap);
				return entry.szExeFile;
			}
		} while (Process32Next(hSnap, &entry));
	}

	CloseHandle(hSnap);
	return "";
}

DWORD Injector::helper::getProcessIdByName(const char* processName)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnap) return 0;

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);

	if (Process32First(hSnap, &entry))
	{
		do
		{
			if (!_stricmp(processName, entry.szExeFile))
			{
				if (entry.th32ParentProcessID == 0) 
				{
					CloseHandle(hSnap);
					return entry.th32ProcessID;
				}

				const char* parentProcessName = getParentProcessName(entry.th32ParentProcessID);
				if (!_stricmp(parentProcessName, processName))
				{
					// keep iterating until we find the main process
					continue;
				}

				// this is the main process
				CloseHandle(hSnap);
				return entry.th32ProcessID;
			}

		} while (Process32Next(hSnap, &entry));
	}

	CloseHandle(hSnap);
	return 0;
}

DWORD Injector::helper::getPEHeaderSize(const IMAGE_NT_HEADERS* pNTH)
{
	return (offsetof(IMAGE_NT_HEADERS, OptionalHeader) + pNTH->FileHeader.SizeOfOptionalHeader + (pNTH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
}

bool Injector::helper::toAbsolutePath(char* path)
{
	char absolutePath[MAX_PATH] = { 0 };
	if (!GetFullPathNameA(path, MAX_PATH, absolutePath, nullptr)) {
		return false;
	}

	strcpy_s(path, MAX_PATH, absolutePath);
	return true;
}

#ifdef _WIN64
static BYTE Shellcode_ThreadHijack[] =
{
	// store stack
	0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,		// mov -16 to rax
	0x48, 0x21, 0xC4,												// and rsp, rax
	0x48, 0x83, 0xEC, 0x20,											// subtract 32 from rsp
	0x48, 0x8b, 0xEC,												// mov rbp, rsp

	// execute shellcode
	0x90, 0x90,														// nop nop
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rax, pointer of shellcode function
	0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rcx, pointer of shellcode params
	0xFF, 0xD0,														// call rax

	// restore stack
	0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rcx, pointer of thread context
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rax, address of RtlRestoreContext to restore it's previous state
	0x48, 0x31, 0xd2,												// xor rdx, rdx
	0xFF, 0xD0,														// call rax
	0xC																// ret
};
#else
static BYTE Shellcode_ThreadHijack[] =
{
	// create space for return value
	0x83, 0xEC, 0x4,												// sub esp, 0x4
	0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,						// push eip on stack

	// store stack
	0x60,															// pushad
	0x9C,															// pushfd
	0x89, 0xE5,														// mov ebp, esp

	// execute shellcode
	0xBB, 0x00, 0x00, 0x00, 0x00,									// mov ebx, pointer of shellcode function
	0x68, 0x00, 0x00, 0x00, 0x00,									// push pointer of shellcode params
	0xFF, 0xD3,														// call ebx

	// restore stack
	0x89, 0xEC,														// mov esp, ebp
	0x9D,															// popfd
	0x61,															// popad
	0xC3															// ret
};
#endif

BYTE* Injector::hijack::getShellcode()
{
	return Shellcode_ThreadHijack;
}

size_t Injector::hijack::getShellcodeSize()
{
	return tInjector_ARRLEN(Shellcode_ThreadHijack);
}