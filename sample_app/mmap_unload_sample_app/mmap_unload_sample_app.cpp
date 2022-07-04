#include <Windows.h>
#include <iostream>

int g_iCreatedThreadCount = 0;

void thLoop()
{
	Sleep(1000);

	printf("[+] New cycle: %d\n", g_iCreatedThreadCount++);
	   
	CloseHandle( CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)thLoop, nullptr, 0, nullptr) ); 
}

int main()
{		
	thLoop();
	
	while (true) { Sleep(1); }
}