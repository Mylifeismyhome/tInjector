#include "main.h"

#include "Remote_LoadLibrary.h"
#include "ManualMapping.h"
#include "SetWindowsHookEx.h"

unsigned GetOptionsFromCMD()
{
	tInjector::logln("Enter Option { 1 - no option ; 2 - erase pe header }");

	std::string option;
	std::cin >> option;

	auto m_option = std::atoi(option.data()) - 1;

	unsigned m_ret = 0;
	switch (m_option)
	{
	case 1:
		m_ret |= OPT_ERASE_PE_HEADER;
		break;

	default:
		break;
	}

	return m_ret;
}

int GetInjectionMethodFromCMD()
{
	tInjector::logln("Enter Injection-Method { 1 - CreateRemoteThread ; 2 - ThreadHijacking }");

	std::string InjectionMethod;
	std::cin >> InjectionMethod;

	auto m_InjectionMethod = std::atoi(InjectionMethod.data()) - 1;
	return m_InjectionMethod;
}

std::string GetCustomEntryPointFromCMD()
{
	tInjector::logln("Enter name of custom entry point");

	std::string CustomEntryPoint;
	std::cin >> CustomEntryPoint;

	return CustomEntryPoint;
}

int main()
{
	tInjector::logln("Enter Processname:");

	std::string TargetProcessName;
	std::cin >> TargetProcessName;

	tInjector::logln("Enter target module path:");

	std::string TargetModulePath;
	std::cin >> TargetModulePath;

	tInjector::logln("Enter Method { 1 - Remote LoadLibraryA ; 2 - Manual Mapping ; 3 - SetWindowsHookEx }");

	std::string Method;
	std::cin >> Method;

	switch (std::atoi(Method.data()))
	{
	case 1:
		tInjector::method::RemoteLoadLibrary(TargetProcessName.c_str(), TargetModulePath.c_str(), static_cast<tInjector::InjectionMethod>(GetInjectionMethodFromCMD()));
		break;

	case 2:
		tInjector::method::ManualMapping(TargetProcessName.c_str(), TargetModulePath.c_str(), static_cast<tInjector::InjectionMethod>(GetInjectionMethodFromCMD()), GetOptionsFromCMD());
		break;

	case 3:
		tInjector::method::SetWindowsHookEx(TargetProcessName.c_str(), TargetModulePath.c_str(), GetCustomEntryPointFromCMD().c_str());
		break;

	default:
		break;
	}
	
	system("pause");
	return 0;
}

void tInjector::log(const char c)
{
	std::cout << c;
}

void tInjector::log(const char* msg, ...)
{
	va_list vaArgs;
	va_start(vaArgs, msg);
	const size_t size = std::vsnprintf(nullptr, 0, msg, vaArgs);
	std::vector<char> str(size + 1);
	std::vsnprintf(str.data(), str.size(), msg, vaArgs);
	va_end(vaArgs);

	std::cout << str.data();
}

void tInjector::logln(const char* msg, ...)
{
	va_list vaArgs;
	va_start(vaArgs, msg);
	const size_t size = std::vsnprintf(nullptr, 0, msg, vaArgs);
	std::vector<char> str(size + 1);
	std::vsnprintf(str.data(), str.size(), msg, vaArgs);
	va_end(vaArgs);

	std::cout << str.data() << std::endl;
}

DWORD tInjector::helper::GetProcessIdByName(const char* pName)
{
	auto hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnap) return 0;

	size_t pNameLen = strlen(pName);

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(entry);

	if (Process32First(hSnap, &entry))
	{
		do
		{
			if (!memcmp(pName, entry.szExeFile, pNameLen))
			{
				CloseHandle(hSnap);
				return entry.th32ProcessID;
			}

		} while (Process32Next(hSnap, &entry));
	}

	CloseHandle(hSnap);
	return 0;
}

DWORD tInjector::helper::GetPEHeaderSize(const IMAGE_NT_HEADERS* pNTH)
{
	return (offsetof(IMAGE_NT_HEADERS, OptionalHeader) + pNTH->FileHeader.SizeOfOptionalHeader + (pNTH->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
}


static BYTE m_Shellcode_ThreadHijack[] =
{
	0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,		// mov -16 to rax
	0x48, 0x21, 0xC4,												// and rsp, rax
	0x48, 0x83, 0xEC, 0x20,											// subtract 32 from rsp
	0x48, 0x8b, 0xEC,												// mov rbp, rsp
	0x90, 0x90,														// nop nop
	0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rcx, pointer of shellcode params
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// mov rax, pointer of shellcode function
	0xFF, 0xD0,														// call rax
	0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rcx, pointer of thread context
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rax, address of RtlRestoreContext to restore it's previous state
	0x48, 0x31, 0xd2,												// xor rdx, rdx
	0xFF, 0xD0,														// call rax
	0xC																// ret
};

BYTE* tInjector::hijack::GetShellcode()
{
	return m_Shellcode_ThreadHijack;
}

size_t tInjector::hijack::GetShellcodeSize()
{
	return tInjector_ARRLEN(m_Shellcode_ThreadHijack);
}

bool tInjector::option::erase_pe_header(HANDLE m_hProcess, PVOID m_base, size_t m_pe_size)
{
	unsigned char m_zero = 0;
	if (!WriteProcessMemory(m_hProcess, m_base, &m_zero, m_pe_size, nullptr))
	{
		return false;
	}

	return true;
}
