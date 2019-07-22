#include <netlink/socket.h>
#include <netlink/socket_group.h>

#include "DetourAssemblyList.h"

#include <fileapi.h>
#include <tchar.h>

#include "..\\CommonData.h"

#pragma comment(lib, "ntdll.lib")



// GLOBAL VARIABLES
BOOL mDisconnect = false;
BOOL mProcessThreadAlive = true;
BOOL mMustHide = true;

std::vector< std::wstring > mProtectedPaths;
LPCTSTR mSharedMemoryPtr = nullptr;

HANDLE hMapFile = nullptr;
HANDLE MtxMutexProcessThreadAlive = nullptr;
HANDLE MtxMutexDisconnect = nullptr;
HANDLE MtxMutexMustHide = nullptr;
HANDLE MtxMutexProtectedPaths = nullptr;



// Method decides if the file is to be hidden.
BOOL PkHideFileName(WCHAR *FilePath, DWORD FilePathLength, WCHAR* FileName, ULONG FileNameLength) {
	ENTER_MUTEX_SCOPE(MtxMutexMustHide);

	if (!mMustHide) { 
		
		EXIT_MUTEX_SCOPE(MtxMutexMustHide);

		return false;
	}

	ENTER_MUTEX_SCOPE(MtxMutexProtectedPaths);

	WCHAR tFilePath[2 * MAX_PATH];

	wcscpy_s(tFilePath, MAX_PATH, FilePath);
	
	FilePathLength--;
	FileNameLength /= 2;

	if (tFilePath[FilePathLength] != '\\') {
		FilePathLength++;
		tFilePath[FilePathLength] = '\\';  
	}
	 
	wcsncpy_s(tFilePath + FilePathLength + 1, MAX_PATH, FileName, FileNameLength);
	tFilePath[FilePathLength + FileNameLength + 1] = 0;

	std::wstring mFullPath = tFilePath;

	for (std::wstring mInnerStr : mProtectedPaths) {
		if (mFullPath.find(mInnerStr) != std::string::npos && mMustHide) {
			
			EXIT_MUTEX_SCOPE(MtxMutexProtectedPaths);

			EXIT_MUTEX_SCOPE(MtxMutexMustHide);

			return true;
		}
	}
	
	EXIT_MUTEX_SCOPE(MtxMutexProtectedPaths);

	EXIT_MUTEX_SCOPE(MtxMutexMustHide);

	return false;
}

// Detour function of NtQueryDirectoryFile
NTSTATUS WINAPI DetourNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event OPTIONAL, PVOID ApcRoutine OPTIONAL, PVOID ApcContext OPTIONAL, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName OPTIONAL, BOOLEAN RestartScan) {
	
	// Here use the code from the latest version of HorizonDova rootkit...someone would surely know :)

	return mNtStatus;
}

NTSTATUS NTAPI DetourNtResumeThread(HANDLE hThread, PULONG SuspendCount) {
	THREAD_BASIC_INFORMATION tbi;

	OutputDebugString(L"CALLLLELDD");


	// Here use the code from the latest version of HorizonDova rootkit...someone would surely know :)
	
	if (NT_SUCCESS(NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL))) {
	
		// tbi.ClientId.UniqueProcess)

	}

	return NewNtResumeThread(hThread, SuspendCount);
}




NTSTATUS WINAPI DetourNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ulProcessFlags, ULONG ulThreadFlags, PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParameters, PPS_CREATE_INFO PsCreateInfo, PPS_ATTRIBUTE_LIST PsAttributeList) {
//  Prevents opening of restricted exes.

//  Detour ntdll.dll + 0x74AA00....... 

//  Get _code of module loaded at ntdll.dll + 0x74AA00....... + offset (2 | 5 bt)

//  Rellocate table

//  Use ReflectedLoadLibrary on ntdll - remove symbs - replace _code 

//  Swap new vtable with the original

//  Itterate through loaded modules - get original ntdll  addr

//  ............. use old code from HorizonDova

//	return status;

}


// Socket callback declarations
class OnRead : public NL::SocketGroupCmd {
	void exec(NL::Socket* socket, NL::SocketGroup* group, void* reference) {

		// Read the command from the server -- validate 

	}
};

class OnDisconnect : public NL::SocketGroupCmd {
	void exec(NL::Socket* socket, NL::SocketGroup* group, void* reference) {
		ENTER_MUTEX_SCOPE(MtxMutexDisconnect);

		// ....

		EXIT_MUTEX_SCOPE(MtxMutexDisconnect);
	}
};

DWORD WINAPI KzLocalNetworkTransactionThread(LPVOID lpParam) {
	// Initiate the NL socket
	NL::init();

	while (true) {

		ENTER_MUTEX_SCOPE(MtxMutexProcessThreadAlive);

		if (!mProcessThreadAlive) break;

		EXIT_MUTEX_SCOPE(MtxMutexProcessThreadAlive);



		ENTER_MUTEX_SCOPE(MtxMutexDisconnect);

		mDisconnect = false;

		EXIT_MUTEX_SCOPE(MtxMutexDisconnect);


		ENTER_MUTEX_SCOPE(MtxMutexDisconnect);

		try {
			// Create instance of read callback
			OnRead onRead;
			// Create instance of disconnect callback
			OnDisconnect onDisconnect;

			// Create server socket
			NL::Socket socket("localhost", mServerPort);
			// Create socket container
			NL::SocketGroup group;

			// Setup handlers
			group.add(&socket);
			group.setCmdOnRead(&onRead);
			group.setCmdOnDisconnect(&onDisconnect);
			socket.setPid(GetCurrentProcessId());
			
			// Send first command for identifying
			socket.sendCommand(mCommand_pid, socket.getPid());

			while (true) {
				if (mDisconnect) break;

				group.listen(500);
			}
		}
		catch (NL::Exception e) {

		}

		EXIT_MUTEX_SCOPE(MtxMutexDisconnect);
	}

	return 0;
}

BOOL MpInitializeSharedMemoryMap() {
	hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, L"mSharedDataModel");

	if (hMapFile == NULL)
	{
		OutputDebugString(TEXT("Could not open file mapping object.\n"));
		return false;
	}

	mSharedMemoryPtr = (LPTSTR)MapViewOfFile(hMapFile,FILE_MAP_ALL_ACCESS, 0,0,mMaxMapFileSize);

	if (mSharedMemoryPtr == NULL)
	{
		OutputDebugString(TEXT("Could not map view of file!\n"));

		CloseHandle(hMapFile);

		return false;
	}

	return true;
}



BOOL APIENTRY DllMain ( HMODULE hModule,DWORD ul_reason_for_call,LPVOID lpReserved ) {
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		MpInitializeSharedMemoryMap();

		MtxMutexProcessThreadAlive = CreateMutex(NULL, FALSE, NULL);
		MtxMutexDisconnect		   = CreateMutex(NULL, FALSE, NULL);
		MtxMutexMustHide		   = CreateMutex(NULL, FALSE, NULL);
		MtxMutexProtectedPaths	   = CreateMutex(NULL, FALSE, NULL);

		MessageBox(0, L"Attach debugger", L"Attach debugger", 0);

		// Start the local server - client comunication
		CreateThread(NULL, 0, KzLocalNetworkTransactionThread, 0, 0, NULL);

		Detours mHookEngine;
		 
		LPVOID mb;


		HMODULE mNtdll = GetModuleHandle(_T("ntdll.dll"));
		HMODULE mKernel32 = GetModuleHandle(_T("kernel32.dll"));


		mHookEngine.Hookfunction(GetProcAddress(mNtdll, "NtQueryDirectoryFile"), DetourNtQueryDirectoryFile, mb);

		NewNtQueryDirectoryFile = (PrototypeDetourNtQueryDirectoryFile)mb;



		mHookEngine.Hookfunction(GetProcAddress(mNtdll, "NtResumeThread"), DetourNtResumeThread, mb);

		NewNtResumeThread = (PrototypeDetourNtResumeThread)mb;

		break;
	}
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:

		ENTER_MUTEX_SCOPE(MtxMutexDisconnect)
		mDisconnect = true;
		EXIT_MUTEX_SCOPE(MtxMutexDisconnect);


		ENTER_MUTEX_SCOPE(MtxMutexProcessThreadAlive)
		mProcessThreadAlive = false;
		EXIT_MUTEX_SCOPE(MtxMutexProcessThreadAlive);

		if(mSharedMemoryPtr)
		UnmapViewOfFile(mSharedMemoryPtr);

		if(hMapFile)
		CloseHandle(hMapFile);


		CloseHandle(MtxMutexProcessThreadAlive);
		CloseHandle(MtxMutexDisconnect);
		CloseHandle(MtxMutexMustHide);
		CloseHandle(MtxMutexProtectedPaths);


        break;
    }
    return TRUE;
}

