#include <netlink/socket.h>
#include <netlink/socket_group.h>

#include "DetourAssemblyList.h"



DWORD WINAPI KzLocalNetworkTransactionThread(LPVOID lpParam) {
	try {
	
	}
	catch (NL::Exception e) {

	}

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved ) {
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		OutputDebugString(L"Process Attach!");

		CreateThread(NULL, 0, KzLocalNetworkTransactionThread, 0, 0, NULL);

		/*Detours mHookEngine;
			....
		*/
		break;
	}
    case DLL_THREAD_ATTACH:
		OutputDebugString(L"Thread Attach!");
		break;
    case DLL_THREAD_DETACH:
		OutputDebugString(L"Thread DETACH!");
		break;
    case DLL_PROCESS_DETACH:

		OutputDebugString(L"Process DETACH!");
        break;
    }
    return TRUE;
}

