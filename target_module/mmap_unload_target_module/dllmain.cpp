#include "includes.h"

/*
	Module have static base address for correct test this sample.
	My choise is 0x10000000
*/

void thMain()
{
	printf("[+] " __FUNCTION__ " > Injected dll\n");

	while (!GetAsyncKeyState(VK_DELETE)) { Sleep(1); }

	printf("[-] " __FUNCTION__ " > Unloading dll...\n");

	MMapModuleUnloader::ExFreeLib();
}

BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD  ul_reason_for_call,
					   LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		printf("[+] " __FUNCTION__ " > Module base address: %p\n", (void*)hModule);

		if (!MMapModuleUnloader::MMapModuleUnloaderInitialize(hModule))
		{
			MessageBoxA(0, "Not found static Tls entry", "Critical", MB_OK | MB_ICONERROR);
			TerminateProcess(GetCurrentProcess(), 0);
		}

		CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)thMain, nullptr, 0, nullptr));
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

