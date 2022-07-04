#pragma once

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID           DllBase;
	PVOID           Entrypoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _TLS_ENTRY
{
	LIST_ENTRY            TlsEntryLinks;
	IMAGE_TLS_DIRECTORY   TlsDirectory;
	PLDR_DATA_TABLE_ENTRY ModuleEntry;
	SIZE_T Index;
} TLS_ENTRY, * PTLS_ENTRY;

namespace MMapModuleUnloader
{
	bool MMapModuleUnloaderInitialize(HMODULE hDllModule);
	void ExFreeLib();
}