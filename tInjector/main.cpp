#include "main.h"

#include "Remote_LoadLibrary.h"

int main()
{
	tInjector::logln("Enter Processname:");

	std::string TargetProcessName;
	std::cin >> TargetProcessName;

	tInjector::logln("Enter target module path:");

	std::string TargetModulePath;
	std::cin >> TargetModulePath;

	tInjector::method::Method_RemoteLoadLibrary(TargetProcessName.c_str(), TargetModulePath.c_str());
	
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
				return entry.th32ProcessID;
			}

		} while (Process32Next(hSnap, &entry));
	}

	return 0;
}