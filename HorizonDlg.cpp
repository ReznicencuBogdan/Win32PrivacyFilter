
// HorizonDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "HorizonSecureFolder.h"
#include "HorizonDlg.h"
#include "afxdialogex.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// HorizonDlg dialog
BEGIN_MESSAGE_MAP(HorizonDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_SIG_KILL, &HorizonDlg::OnBnClickedButtonSigKill)
	ON_NOTIFY(NM_CLICK, IDC_LIST2, &HorizonDlg::OnNMClickListProcessList)
	ON_BN_CLICKED(IDC_CHECK1, &HorizonDlg::OnBnClickedCheckcbxsetclearsecuritytoken)
	ON_BN_CLICKED(IDC_BUTTON3, &HorizonDlg::OnBnClickBrowseFolder)
	ON_BN_CLICKED(IDC_BUTTON4, &HorizonDlg::OnBnClickedRemoveFolder)
END_MESSAGE_MAP()


// Stable formatted local logger.
void HorizonDlg::DbgPrint(PTCHAR mFormatedMessage, ...) {
	TCHAR mStreamOutBuffer[1024];

	va_list argptr;
	va_start(argptr, mFormatedMessage);

	wvsprintf(mStreamOutBuffer, mFormatedMessage, argptr);
	OutputDebugString(mStreamOutBuffer);

	va_end(argptr);
}


// Declare a thread - alive flag.
// TODO: Make it thread safe!
BOOL HorizonDlg::KzThreadFlag = true;


#pragma region __horizon_message_handlers

HorizonDlg::HorizonDlg(CWnd* pParent): CDialogEx(IDD_HORIZONSECUREFOLDER_DIALOG, pParent), 
									   onDisconnect(this), 
	                                   onAccept(this),
	                                   onRead(this) {
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

BOOL HorizonDlg::OnInitDialog() {

	// Initiate the Dialog component
	CDialogEx::OnInitDialog();

	// Tap into the NetLink's sockets - world
	using namespace NL;

	// Set the icon for this dialog.
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// Setup the mProcessList
	mProcessList.InsertColumn(0, _T("Process Name"), LVCFMT_LEFT, 140);
	mProcessList.InsertColumn(1, _T("Security Token"), LVCFMT_LEFT, 130);
	mProcessList.InsertColumn(2, _T("Pid"), LVCFMT_LEFT, 90);
	mProcessList.InsertColumn(3, _T("Image Path"), LVCFMT_LEFT, 300);

	// Set full row selet and gridlines
	mProcessList.SetExtendedStyle(mProcessList.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// Create the Shared Memory which holds the security paths.
	MpInitializeSharedMemoryMap();

	// Initialize the syncronizing mutexes
	MtxMutexGroupOfSockets		 = CreateMutex(NULL, FALSE, NULL);
	MtxMutexPathList		 	 = CreateMutex(NULL, FALSE, NULL);
	MtxMutexSecurityGroupPolicy  = CreateMutex(NULL, FALSE, NULL);
	MtxMutexKzThreadFlag		 = CreateMutex(NULL, FALSE, NULL);

	// Initiate the NL socket
	init();
	// Setup server socket
	socketServer = new Socket(5000);
	// Create socket container
	group = new SocketGroup();

	group->setCmdOnAccept(&onAccept);
	group->setCmdOnRead(&onRead);
	group->setCmdOnDisconnect(&onDisconnect);
	group->add(socketServer);

	// Setup thread arguments.
	kzArg.mCtx = this;
	kzArg.sSrv = socketServer;
	kzArg.sGrp = group;

	// Start the local server - client comunication
	KzThreadHandle = ::CreateThread(NULL, 0, KzLocalNetworkTransactionThread, &kzArg, 0, NULL);

	if (!KzThreadHandle) {

		// Show some debugging info
		DbgPrint(_T("OnInitDialog: Failed creating background service!\n"));

		MessageBox(_T("There was an error while creating the background thread!"), _T("Error"), MB_OK);

		CDialogEx::OnCancel();

		return FALSE; 
	}

	// Be positive when returning unkwown values.
	return TRUE;
}

VOID HorizonDlg::DoDataExchange(CDataExchange* pDX){
	CDialogEx::DoDataExchange(pDX);

	DDX_Control(pDX, IDC_LIST2, mProcessList);
	DDX_Control(pDX, IDC_CHECK1, cbxSetClearSecurityToken);
	DDX_Control(pDX, IDC_LIST3, mPathList);
}

VOID HorizonDlg::OnPaint() {
	if (IsIconic()) {
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);

		CRect rect;
		GetClientRect(&rect);

		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else CDialogEx::OnPaint();
	
}

VOID HorizonDlg::OnOK() {
	// Just override this method so that the dialog
	// won't catch the ENTER event.
}

VOID HorizonDlg::OnCancel() {
	// Doing some safe operations for a safe closedown.

	// Disable the thread - alive flag!
	ENTER_MUTEX_SCOPE(MtxMutexKzThreadFlag);
	KzThreadFlag = false;
	EXIT_MUTEX_SCOPE(MtxMutexKzThreadFlag);


	// Wait for the thread to finish it's activity
	WaitForSingleObject(KzThreadHandle, INFINITE);

	// Send shutdown message down the socket.
	socketServer->disconnect();

	// Itterate through the client list and delete | disconect each one
	MtIterateThroughClients([&](NL::Socket* mCapturedSocket) -> BOOL {
		mCapturedSocket->disconnect();
		delete mCapturedSocket;

		return true;
	});

	// Throw the heap allocated ptr's to the destructor.
	delete group;
	delete socketServer;

	// Remove view of file map
	if(mViewPtr) UnmapViewOfFile(mViewPtr);

	// Remove the file map
	if(mHandleMapFile) CloseHandle(mHandleMapFile);

	// Closing mutex handles
	CloseHandle(MtxMutexGroupOfSockets);
	CloseHandle(MtxMutexPathList);
	CloseHandle(MtxMutexSecurityGroupPolicy);
	CloseHandle(MtxMutexKzThreadFlag);


	// Continue the usual closedown operations.
	CDialogEx::OnCancel();
	
}

HCURSOR HorizonDlg::OnQueryDragIcon(){
	return static_cast<HCURSOR>(m_hIcon);
}

#pragma endregion __horizon_message_handlers


#pragma region __common_event_handlers
void HorizonDlg::OnBnClickedButtonSigKill() {

	// Get the index of the selected item
	int nItem = mProcessList.GetSelectionMark();

	// Check if there is indeed an item selected
	if (nItem == -1) return;

	// Get the String version of the PID
	CString mProcListItemPid = mProcessList.GetItemText(nItem, 2);

	// Store the process pid here
	DWORD PID;
	
	// Convert the string into a valid PID DWORD Value
	swscanf_s(mProcListItemPid, _T("%u"), &PID);

	// Itterate through the client list and selected only the one with a matching PID Value.
	MtIterateThroughClients([&](NL::Socket* mCapturedSocket) -> BOOL {
		if (mCapturedSocket->getPid() == PID) {
			// Send the command to this socket
			// mCapturedSocket->sendCommand(mCommand_sig_kill, mCommand_empty_data);

			// stop the loop because the is for sure just one process with the provided PID.
			return false;	
		}

		return true;
	});


}

void HorizonDlg::OnNMClickListProcessList(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);

	if (pNMItemActivate->iItem == -1) return;

	if (mProcessList.GetItemText(pNMItemActivate->iItem, 1).Compare(_T("true")) == 0) {
		cbxSetClearSecurityToken.SetCheck(1);
	}
	else {
		cbxSetClearSecurityToken.SetCheck(0);
	}

	*pResult = 0;
}

void HorizonDlg::OnBnClickedCheckcbxsetclearsecuritytoken() {
	// Show some debugging info
	DbgPrint(_T("OnBnClickedCheckcbxsetclearsecuritytoken: Clicked on security check box!\n"));

	// Get the index of the selected item
	int nItem = mProcessList.GetSelectionMark();

	// Check if there is indeed an item selected
	if (nItem == -1) return;

	BOOL mCbxGetCheck = cbxSetClearSecurityToken.GetCheck();

	DbgPrint(_T("OnBnClickedCheckcbxsetclearsecuritytoken: Updated ListCtrl item according to new security status!\n"));

	/*
	*   Notice that I don't modify the status flag for each item entry in the Control List.
	*	I am doing something rather peculiar; I send a notification to each desired client - and expect
	*   (in a threaded - context of course) a response with the new security flag. At that point
	*   in time will I adjust the UI settings.
	*
	*	As a result there is no // mProcessList.SetItemText(nItem, 1, mCbxGetCheck ? _T("true") : _T("false"))  //
	*/

	CString mSelectedItemName = mProcessList.GetItemText(nItem, 3);

	DWORD mParameter = 0;

	ENTER_MUTEX_SCOPE(MtxMutexSecurityGroupPolicy);

	if (mCbxGetCheck) {
		// Add the mSelectedItemName to the security policy group
		// And update every client which has the same path with the 
		// newly aquired rights.

		DbgPrint(_T("OnBnClickedCheckcbxsetclearsecuritytoken: Adding new path '%s' to security group policy!\n"), mSelectedItemName);

		mSecurityGroupPolicy.insert(mSelectedItemName);

		mParameter = 1;
	}
	else {
		// Remove the mSelectedItemName from the security policy group
		// And update every client which has the same path with the 
		// newly aquired rights.

		DbgPrint(_T("OnBnClickedCheckcbxsetclearsecuritytoken: Removing path '%s' from security group policy!\n"), mSelectedItemName);

		mSecurityGroupPolicy.remove(mSelectedItemName);

		mParameter = 0;
	}

	EXIT_MUTEX_SCOPE(MtxMutexSecurityGroupPolicy);

	DbgPrint(_T("OnBnClickedCheckcbxsetclearsecuritytoken: Sending clients the new security status!\n\n"));

	// Itterate through the client list
	MtIterateThroughClients([&](NL::Socket* mCapturedSocket) -> BOOL {
		if (mSelectedItemName.Compare(mCapturedSocket->getPathPtr()) == 0)
			mCapturedSocket->sendCommand(mCommand_security_status, mParameter);

		return true;
	});
}

void HorizonDlg::OnBnClickBrowseFolder() {
	CFolderPickerDialog mFolderBrowser;

	mFolderBrowser.m_ofn.lpstrTitle = L"Select folder you want to hide";
	mFolderBrowser.m_ofn.lpstrInitialDir = _T("C:\\");

	if (mFolderBrowser.DoModal() == IDOK) {
		if (mPathList.GetCount() >= mMapMaxCount) {
			DbgPrint(_T("OnBnClickBrowseFolder: Reached maximum number of entries!\n"));
			
			return;
		}

		ENTER_MUTEX_SCOPE(MtxMutexPathList);
		
		// Insert the string into the list
		mPathList.InsertString(0, mFolderBrowser.GetPathName());
		
		DbgPrint(_T("OnBnClickBrowseFolder: Inserted new path!\n"));
		DbgPrint(_T("OnBnClickBrowseFolder: Rebuilding mapped file content!\n"));

		// Rebuild the shared memory context
		for (int k = 0; k < mPathList.GetCount(); k++) 	mPathList.GetText(k, mViewPtr + k * mMapEntrySize);
		
		// Send the update to the clients
		MpNotifyClientsOnSharedMemUpdate( MpSharedMemAction::full_update );

		EXIT_MUTEX_SCOPE(MtxMutexPathList);

		mFolderBrowser.DestroyWindow();
	}
}

void HorizonDlg::OnBnClickedRemoveFolder() {
	ENTER_MUTEX_SCOPE(MtxMutexPathList, INFINITE);

	INT nItem = mPathList.GetCurSel();

	if (nItem != -1) {
		// Remove string from the list
		mPathList.DeleteString(nItem);

		// Rebuild the shared memory context
		for (int k = 0; k < mPathList.GetCount(); k++) 	mPathList.GetText(k, mViewPtr + k * mMapEntrySize);

		// Send the update to the clients
		MpNotifyClientsOnSharedMemUpdate(MpSharedMemAction::full_update);
	}

	EXIT_MUTEX_SCOPE(MtxMutexPathList);
}


VOID HorizonDlg::MpNotifyClientsOnSharedMemUpdate( MpSharedMemAction mAction ) {

	/*
	*	DON'T USE THE MUTEX FOR THE MtxMutexPathList HERE
	*/

	// Decide the command data
	DWORD mData = ( (DWORD) mAction | ( (DWORD) mPathList.GetCount() << 8 ) );

	// Itterate through the client list
	MtIterateThroughClients([&](NL::Socket* mCapturedSocket) -> BOOL { 

		// mCapturedSocket->sendCommand( .... mData);

		return true; 
	});

	// Show some debugging info
	DbgPrint(_T("MpNotifyClientsOnSharedMemUpdate: Notified clients of mapped file changes!\n"));
}

BOOL HorizonDlg::MpInitializeSharedMemoryMap() {
	// Show some debugging info
	DbgPrint(_T("MpInitializeSharedMemoryMap: Creating File Mapping!\n"));

	// Create the shared memeory space
	mHandleMapFile = ::CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, mMaxMapFileSize, _T("mSharedDataModel"));

	// Check if creating shared memoy was succesfull
	if (!mHandleMapFile) {

		// Show some debugging info
		DbgPrint(_T("MpInitializeSharedMemoryMap: Failed to CreateFileMapping!\n"));

		return false;
	}

	DbgPrint(_T("MpInitializeSharedMemoryMap: Mapping file!\n"));

	// Map the entire comitted area
	mViewPtr = (LPTSTR)::MapViewOfFile(mHandleMapFile, FILE_MAP_ALL_ACCESS, 0,0, mMaxMapFileSize);

	if (mViewPtr == NULL) {

		// Show some debuggin info
		DbgPrint(_T("MpInitializeSharedMemoryMap: Failed commiting view of mapped file!\n"));

		CloseHandle(mHandleMapFile);

		return false;
	}

	DbgPrint(_T("MpInitializeSharedMemoryMap: Maped file succesfully!\n"));

	return true;
}

#pragma endregion __common_event_handlers





VOID HorizonDlg::LbCreateProcessEntry(PTCHAR FULL_PATH, BOOL SECURITY, DWORD PID ) {
	// Populate the list control with details about the process.
	// Tranform the PID int to a LPCWSTR string ptr.
	TCHAR mPidBuffer[10];

	// Fill the buffer 
	wsprintfW(mPidBuffer, L"%u", PID);

	DbgPrint(_T("LbCreateProcessEntry: Creating new entry for process '%s' in the ListCtrl!\n"), FULL_PATH);

	int nIndex = mProcessList.InsertItem(0, PathFindFileName(FULL_PATH));
	mProcessList.SetItemText(nIndex, 1, SECURITY ? _T("true") : _T("false"));
	mProcessList.SetItemText(nIndex, 2, mPidBuffer);
	mProcessList.SetItemText(nIndex, 3, FULL_PATH);
}

INT HorizonDlg::LbFindProcessItemByPid(DWORD PID) {
	TCHAR mPidBuffer[10];

	// Fill the buffer
	wsprintfW(mPidBuffer, _T("%u"), PID);
	
	CString mCstrPid(mPidBuffer);

	for (int i = 0; i < mProcessList.GetItemCount(); i++) 
		if (mCstrPid.Compare(mProcessList.GetItemText(i, 2)) == 0) return i;
	
	return -1;
}

VOID HorizonDlg::LbRemoveProcessItemByPid(DWORD PID) {

	INT mProcListItemPid = LbFindProcessItemByPid(PID);

	if (mProcListItemPid != -1)	mProcessList.DeleteItem(mProcListItemPid);

}

template < typename LambdaFunctor >
VOID HorizonDlg::MtIterateThroughClients(LambdaFunctor mDelegate) {
	ENTER_MUTEX_SCOPE(MtxMutexGroupOfSockets);

	// Itterate through the client list
	for (UINT k = 1; k < (unsigned)group->size(); ++k)
		if (!mDelegate(group->get(k))) break;
	

	EXIT_MUTEX_SCOPE(MtxMutexGroupOfSockets);
}

