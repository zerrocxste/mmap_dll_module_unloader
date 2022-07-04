#ifdef _WIN64
#error Only for x32 applications
#endif

#include "includes.h"

HMODULE g_ThisModule;
void* g_pThisModuleTLS;

struct LibraryUnlinkerData_s;

PTLS_ENTRY GetTlsEntry();
DWORD LibraryUnlinker(LibraryUnlinkerData_s* libraryUnlinkerData);

struct LibraryUnlinkerNode_s
{
	LibraryUnlinkerNode_s() : m_NextNode(nullptr) {}
	MEMORY_BASIC_INFORMATION mbi{};
	LibraryUnlinkerNode_s* m_NextNode;
};

struct LibraryUnlinkerData_s
{
	static LibraryUnlinkerData_s* Create(void* pfUnlinkerFunc, PTLS_ENTRY pTLSListAddress, PTLS_ENTRY pTLSNodeAddress)
	{
		static auto ucrtbase = GetModuleHandleA("ucrtbase.dll");
		static auto f_malloc = (decltype(malloc)*)GetProcAddress(ucrtbase, "malloc");
		static auto f_free = (decltype(free)*)GetProcAddress(ucrtbase, "free");

		auto ret = (LibraryUnlinkerData_s*)f_malloc(sizeof(LibraryUnlinkerData_s));

		ret->m_pFirstNode = nullptr;
		ret->m_pVirtualFreeFA = VirtualFree;
		ret->m_pMallocFA = f_malloc;
		ret->m_pFreeFA = f_free;
		ret->m_pUnlinkerFunc = (decltype(LibraryUnlinker)*)pfUnlinkerFunc;
		ret->m_pTLSListAddress = pTLSListAddress;
		ret->m_pTLSNodeAddress = pTLSNodeAddress;

		return ret;
	}

	LibraryUnlinkerNode_s* m_pFirstNode;

	decltype(VirtualFree)* m_pVirtualFreeFA;
	decltype(malloc)* m_pMallocFA;
	decltype(free)* m_pFreeFA;
	decltype(LibraryUnlinker)* m_pUnlinkerFunc;

	PTLS_ENTRY m_pTLSListAddress;
	PTLS_ENTRY m_pTLSNodeAddress;
};

DWORD LibraryUnlinker(LibraryUnlinkerData_s* libraryUnlinkerData)
{
	auto TlsListEntry = libraryUnlinkerData->m_pTLSListAddress;
	auto Tls = (PTLS_ENTRY)TlsListEntry->TlsEntryLinks.Flink;

	while (true)
	{
		if (Tls->TlsEntryLinks.Flink == (LIST_ENTRY*)libraryUnlinkerData->m_pTLSNodeAddress)
		{
			((PTLS_ENTRY)libraryUnlinkerData->m_pTLSNodeAddress->TlsEntryLinks.Flink)->TlsEntryLinks.Blink = (_LIST_ENTRY*)Tls;
			Tls->TlsEntryLinks.Flink = Tls->TlsEntryLinks.Flink->Flink;
			break;
		}

		Tls = (PTLS_ENTRY)Tls->TlsEntryLinks.Flink;
	}

	auto Node = libraryUnlinkerData->m_pFirstNode;
	while (Node != nullptr)
	{
		libraryUnlinkerData->m_pVirtualFreeFA(Node->mbi.BaseAddress, 0, MEM_RELEASE);
		auto NextNode = Node->m_NextNode;
		libraryUnlinkerData->m_pFreeFA(Node);
		Node = NextNode;
	}

	libraryUnlinkerData->m_pFreeFA(libraryUnlinkerData);

	return 1337;
}

void MMapModuleUnloader::ExFreeLib()
{
	int FuncSize = 0;

	for (auto FuncAddress = (std::uint32_t)LibraryUnlinker;
		*(std::uint32_t*)FuncAddress != 0xCCCCCCCC;
		FuncAddress++, FuncSize++);

	auto CodeAllocatedPage = VirtualAlloc(nullptr, FuncSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	memcpy(CodeAllocatedPage, LibraryUnlinker, FuncSize);

	printf("[+] Reallocated LibraryUnlinker function address: %p\n", __FUNCTION__, CodeAllocatedPage);

	auto pLibUnlinkerData = LibraryUnlinkerData_s::Create(CodeAllocatedPage, GetTlsEntry(), (PTLS_ENTRY)g_pThisModuleTLS);

	auto Node = &pLibUnlinkerData->m_pFirstNode;

	MEMORY_BASIC_INFORMATION mbi{};
	for (auto BaseAddress = (std::uintptr_t)g_ThisModule; VirtualQuery((void*)BaseAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != 0; BaseAddress = (std::uintptr_t)mbi.BaseAddress + mbi.RegionSize)
	{
		if (mbi.Type != MEM_PRIVATE)
			break;

		*Node = new LibraryUnlinkerNode_s();
		(*Node)->mbi = mbi;
		Node = &(*Node)->m_NextNode;
	}

	CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)CodeAllocatedPage, pLibUnlinkerData, 0, nullptr));
}

bool MMapModuleUnloader::MMapModuleUnloaderInitialize(HMODULE hDllModule)
{
	g_ThisModule = hDllModule;

	auto TlsEntry = GetTlsEntry();

	if (!TlsEntry)
		return false;

	g_pThisModuleTLS = TlsEntry->TlsEntryLinks.Blink;

	return true;
}

std::uintptr_t get_module_size(std::uintptr_t address)
{
	return PIMAGE_NT_HEADERS(address + (std::uintptr_t)PIMAGE_DOS_HEADER(address)->e_lfanew)->OptionalHeader.SizeOfImage;
}

std::uintptr_t compare_mem(const char* pattern, const char* mask, std::uintptr_t base, std::uintptr_t size, const int patternLength, DWORD speed, bool safe)
{
	std::uintptr_t PageRegionSizeCount = 0;

	for (std::uintptr_t i = 0; i < size - patternLength; i += speed)
	{
		if (safe)
		{
			if (PageRegionSizeCount == 0)
			{
				MEMORY_BASIC_INFORMATION mbi{};
				VirtualQuery((void*)(base + i), &mbi, sizeof(MEMORY_BASIC_INFORMATION));

				if (mbi.Protect == 0 || mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_WRITECOPY)
				{
					i += mbi.RegionSize - 1;
					PageRegionSizeCount = 0;
					continue;
				}
				else
				{
					if (base + i > (std::uintptr_t)mbi.BaseAddress)
						PageRegionSizeCount -= (base + i) - (std::uintptr_t)mbi.BaseAddress;

					PageRegionSizeCount += mbi.RegionSize - 1;
				}
			}
			else
				PageRegionSizeCount--;
		}

		bool found = true;
		for (std::uintptr_t j = 0; j < patternLength; j++)
		{
			if (mask[j] == '?')
				continue;

			if (pattern[j] != *(char*)(base + i + j))
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			return base + i;
		}
	}

	return NULL;
}

std::uintptr_t find_pattern(HMODULE module, const char* pattern, const char* mask, DWORD scan_speed, bool safe)
{
	std::uintptr_t base = (std::uintptr_t)module;
	std::uintptr_t size = get_module_size(base);

	std::uintptr_t patternLength = (std::uintptr_t)strlen(mask);

	return compare_mem(pattern, mask, base, size, patternLength, scan_speed, safe);
}

PTLS_ENTRY GetTlsEntry()
{
	static PTLS_ENTRY pTlsEntry = nullptr;

	if (pTlsEntry != nullptr)
		return pTlsEntry;

	auto ntdll = GetModuleHandle("ntdll.dll");

	auto Instruction = find_pattern(ntdll, "\xC7\x45\xD0\x00\x00\x00\x00\xA1", "xxx????x", 1, true); //win10 / win11 ~2021-2022 | "C7 45 D0 ? ? ? ? A1"

	if (!Instruction)
	{
		Instruction = find_pattern(ntdll, "\xC7\x45\xD4\x00\x00\x00\x00\x8B\x1D", "xxx????xx", 1, true); //win7 | "C7 45 D4 ? ? ? ? 8B 1D"

		if (!Instruction)
		{
			Instruction = find_pattern(ntdll, "\xC7\x45\xCC\xFF\xFF\xFF\xFF\xA1", "xxx????x", 1, true); //old win10 ~2018-2019 | "C7 45 CC ? ? ? ? A1" 

			if (!Instruction)
				return nullptr;
		}
	}

	pTlsEntry = *(PTLS_ENTRY*)(Instruction + 0x3);

	return pTlsEntry;
}