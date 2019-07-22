#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <string>
#include <stdio.h>

BOOL ModuleAlreadyLoaded(CONST PCHAR MOD_NAME, DWORD PID) {
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);

	if (NULL == hProcess) return false;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.

				if (strcmp(szModName, MOD_NAME) == 0) {

					CloseHandle(hProcess);

					return true;
				}
			}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return false;
}

DWORD GetProcessPid(CONST PCHAR ProcessName, CONST PCHAR LibraryPath) {
	PROCESSENTRY32 ProcessEntryStruct;
	ProcessEntryStruct.dwSize = sizeof(PROCESSENTRY32);

	HANDLE HelperSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (HelperSnapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	if (Process32First(HelperSnapshot, &ProcessEntryStruct))
	{
		while (Process32Next(HelperSnapshot, &ProcessEntryStruct))
			if (strcmp(ProcessName, ProcessEntryStruct.szExeFile) == 0) {

				// Check for already loaded modules.
				if (ModuleAlreadyLoaded(LibraryPath, ProcessEntryStruct.th32ProcessID)) continue;

				// Why to continue execution though ?
				// Because there could be multiple process with the same name opened.

				// close the handle for the snapshot
				CloseHandle(HelperSnapshot);

				// return the pid
				return ProcessEntryStruct.th32ProcessID;
			}
	}

	// close the handle for the snapshot
	CloseHandle(HelperSnapshot);

	// return an empty pid - ussually specific to system
	return 0;
}


BOOL InjectLbraryPid(DWORD ProcessPid, CONST PCHAR LibraryPath) {

	// Get a handle to the process
	HANDLE ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, ProcessPid);

	// Is a valid handle ?
	if (!ProcessHandle) {
		OutputDebugStringA("OpenProcess failed!");

		return false;
	}

	// Get the handle for the library
	HMODULE Kernel32Lib = GetModuleHandle("kernel32.dll");

	// check for validity
	if (!Kernel32Lib) {
		OutputDebugStringA("Kernel32 not found!");

		CloseHandle(ProcessHandle);
		return false;
	}

	// Get the address of the LoadLibrary Function inside the library.
	LPVOID LoadLibraryAddress = (LPVOID)GetProcAddress(Kernel32Lib, "LoadLibraryA");

	if (!LoadLibraryAddress) {
		OutputDebugStringA("LoadLibraryA not found!");

		CloseHandle(ProcessHandle);
		return false;
	}

	// Allocate enough memory in a remote process to hold
	// the path of the library to be injected.
	LPVOID RemoteProcessLibPathAddress = VirtualAllocEx(ProcessHandle, NULL, strlen(LibraryPath) + 1, MEM_COMMIT, PAGE_READWRITE);

	if (!RemoteProcessLibPathAddress) {
		OutputDebugStringA("VirtualAllocEx failed!");

		CloseHandle(ProcessHandle);
		return false;
	}


	// Holds how many bytes of the path was written.
	SIZE_T BytesWritten;

	if (!WriteProcessMemory(ProcessHandle, RemoteProcessLibPathAddress, LibraryPath, strlen(LibraryPath) + 1, &BytesWritten)) {
		OutputDebugStringA("WriteProcessMemory failed!");

		CloseHandle(ProcessHandle);
		return false;
	}

	// Execute the LoadLibrary Function in the context
	// of the specified process.
	// As the kernel32 and some other libraries are always mapped
	// to the same address in each process, then this call will be succesfull.
	HANDLE RemoteThreadContext = CreateRemoteThreadEx(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, RemoteProcessLibPathAddress, 0, NULL, NULL);

	if (!RemoteThreadContext) {
		OutputDebugStringA("CreateRemoteThreadEx failed!");

		CloseHandle(ProcessHandle);
		return false;
	}

	WaitForSingleObject(RemoteThreadContext, INFINITE);

	VirtualFreeEx(ProcessHandle, RemoteProcessLibPathAddress, strlen(LibraryPath) + 1, MEM_RELEASE);

	CloseHandle(RemoteThreadContext);

	CloseHandle(ProcessHandle);

	OutputDebugStringA("Succeded!");
}


BOOL InjectLibrary(CONST PCHAR ProcessName, CONST PCHAR LibraryPath) {

	// Get the pid of the proces
	DWORD ProcessPid = GetProcessPid(ProcessName, LibraryPath);

	// Is the process active ?
	if (ProcessPid == 0) {
		OutputDebugStringA("Invalid PID!");
		return false;
	}

	return InjectLbraryPid(ProcessPid, LibraryPath);
}

