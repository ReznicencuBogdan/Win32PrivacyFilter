
// HorizonDlg.h : header file
//

#pragma once

#include <netlink/socket.h>
#include <netlink/socket_group.h>

#include <Psapi.h>
#include <vector>

#include "..\\CommonData.h"

#define inherits_nl_sockets  public NL::SocketGroupCmd
#define inherits_instantiate_class public InstantiateBaseClass





// HorizonDlg dialog
class HorizonDlg : public CDialogEx {
// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_HORIZONSECUREFOLDER_DIALOG };
#endif

protected: virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg void OnOK();
	afx_msg void OnCancel();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	// Stable formatted local logger.
	void DbgPrint(PTCHAR lpOutputString, ...);

	// Setup server socket
	NL::Socket *socketServer = nullptr;
	// Create socket container
	NL::SocketGroup *group = nullptr;
	// Setup a thread - alive flag.
	static BOOL KzThreadFlag;
	// Obtain a resource handle for the thread.
	HANDLE KzThreadHandle = nullptr;
	
	// Create specific thread argument type.
	struct KzLocalNewtworkThreadArg {
		// Dlg context
		HorizonDlg* mCtx;
		// Setup server socket
		NL::Socket* sSrv;
		// Create socket container
		NL::SocketGroup* sGrp;
	};
	// Declare a thread argument
	KzLocalNewtworkThreadArg kzArg;


	HANDLE MtxMutexGroupOfSockets = nullptr;
	HANDLE MtxMutexPathList = nullptr;
	HANDLE MtxMutexSecurityGroupPolicy = nullptr;
	HANDLE MtxMutexKzThreadFlag = nullptr;


	enum MpSharedMemAction {
		full_update    = 0x00000000U,
		insert_element = 0x00000001U, /* TODO : in future releases */
		remove_element = 0x00000002U  /* TODO : in future releases */

		/*	This data can be saved on one byte
		*   Therefore, in case of DWORD conversion
		*   There are 3 bytes left intact which aproximate 
		*   in unsigned context abt. 0 - 2^24 - 1
		*/
	};

	HANDLE mHandleMapFile;
	LPTSTR mViewPtr;


	/*	The following class specializez in holding details about processes
	*	which have been granted access to hidden data on the filesystem.
	*	The data is not temporary. Each time this interface is closed, the
	*	data is backed up in a local, hidden config file.s 
	*/
	class SecurityGroupPolicy {
	private: std::vector < CString > mProcFullPathList;
	public:
		void insert(CString mProcPath) {
			if (!exists(mProcPath)) mProcFullPathList.push_back(mProcPath);
		}

		std::vector < CString>::iterator find(CString mProcPath) {
			return std::find(mProcFullPathList.begin(), mProcFullPathList.end(), mProcPath);
		}

		void remove(CString mProcPath) {
			std::vector < CString>::iterator mFoundIt = find(mProcPath);

			if (find(mProcPath) != mProcFullPathList.end()) mProcFullPathList.erase(mFoundIt);		
		}

		bool exists(CString mProcPath) {
			if (find(mProcPath) != mProcFullPathList.end()) return true;
			return false;
		}
	} ;

	// Create an instance of the security class.
	SecurityGroupPolicy mSecurityGroupPolicy;


	// Socket callback declarations
	class InstantiateBaseClass {
	protected: HorizonDlg* mContext = nullptr;
	public: InstantiateBaseClass(HorizonDlg* mContext) {
				this->mContext = mContext;
			}
	};

	class OnAccept : inherits_nl_sockets , inherits_instantiate_class {
	public: void exec(NL::Socket* socket, NL::SocketGroup* group, void* reference) {
			// Create instance for the new connection
			NL::Socket* newConnection = socket->accept();

			// Add the instance to the collection
			ENTER_MUTEX_SCOPE(mContext->MtxMutexGroupOfSockets);
			group->add(newConnection);		
			EXIT_MUTEX_SCOPE(mContext->MtxMutexGroupOfSockets);

			// Show debug message
			mContext->DbgPrint(_T("OnAccept: Accepted new client!\n"));
			}

			OnAccept(HorizonDlg* mContext) : InstantiateBaseClass(mContext) {}
	};


	class OnRead : inherits_nl_sockets, inherits_instantiate_class {
	public: void exec(NL::Socket* socket, NL::SocketGroup* group, void* reference) {
			DWORD mRecvCommand;
			DWORD mData;

			// Read and parse receved data.
			ENTER_MUTEX_SCOPE(mContext->MtxMutexGroupOfSockets);
			socket->readCommand(mRecvCommand, mData);

			switch (mRecvCommand) {
			case mCommand_pid: {
				// This array holds the full path of a process.
				TCHAR mFullProcessPath[MAX_PATH];

				// Save the PID and asociate it with this socket.
				socket->setPid(mData);
				
				// Write some safe data in the array.
				wcscpy_s(mFullProcessPath, _T("EMPTY"));

				// Transform the PID into a valid process image name.
				HANDLE mProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, mData);

				if (mProcHandle) {
					// Get the full process path and write it into the buffer.
					::GetModuleFileNameEx(mProcHandle, 0, mFullProcessPath, MAX_PATH);

					// Make sure there is no chance of overwritting the \0
					mFullProcessPath[MAX_PATH - 1] = 0;

					// Release the handle.
					CloseHandle(mProcHandle);
				}

				// Copy the full process path into the client asociated to this socket.
				wcscpy_s(socket->getPathPtr(), MAX_PATH, mFullProcessPath);

				// Show debug message
				mContext->DbgPrint(_T("OnRead: Received PID %u from process %s!\n"), mData, mFullProcessPath);

				// Is this process in the security group?
				ENTER_MUTEX_SCOPE(mContext->MtxMutexSecurityGroupPolicy);
				BOOL mSecurityStatus = mContext->mSecurityGroupPolicy.exists(mFullProcessPath);
				EXIT_MUTEX_SCOPE(mContext->MtxMutexSecurityGroupPolicy);

				// Create a new entry in the list for the new pocess.
				mContext->LbCreateProcessEntry(mFullProcessPath, mSecurityStatus, mData);

				// If it is in the security group then notify the process.
				if (mSecurityStatus) {
					mContext->DbgPrint(_T("OnRead: The process '%s' is in the security policy group! Sending client the new security status!\n"), mFullProcessPath);

					socket->sendCommand(mCommand_security_status, 1);
				}

				break;
			}
			case mCommand_security_status: {
				// Receive security status. This is a confirmation of aproval
				// after having received the command from the server.
				INT nItem = mContext->LbFindProcessItemByPid(socket->getPid());

				// Check existance of a row containing the process pid.
				if (nItem == -1) break;

				// Update the process status in the UI.
				mContext->mProcessList.SetItemText(nItem, 1, mData == 1 ? _T("true") : _T("false"));

				// Show debug message
				mContext->DbgPrint(_T("OnRead: Updated UI after security status changed to %s!\n"), mData == 1 ? _T("true") : _T("false"));
				break;
			}
			}
			
			EXIT_MUTEX_SCOPE(mContext->MtxMutexGroupOfSockets);

			}

			OnRead(HorizonDlg* mContext) : InstantiateBaseClass(mContext) {}
	};

	class OnDisconnect : inherits_nl_sockets, inherits_instantiate_class {
	public:	void exec(NL::Socket* socket, NL::SocketGroup* group, void* reference) {
			
		    ENTER_MUTEX_SCOPE(mContext->MtxMutexGroupOfSockets);

			// Show debug message
			mContext->DbgPrint(_T("OnDisconnect: Process %s disconnected!\n"), socket->getPathPtr());

			// Remove socket from group container
			group->remove(socket);

			// Remove entry from process lsit
			mContext->LbRemoveProcessItemByPid(socket->getPid());

			// Delete socket instance
			delete socket;

			EXIT_MUTEX_SCOPE(mContext->MtxMutexGroupOfSockets);

			}

			OnDisconnect(HorizonDlg* mContext) : InstantiateBaseClass(mContext) {}
	};



	// Instantiate socket handlers
	OnDisconnect onDisconnect;
	OnAccept onAccept;
	OnRead onRead;



	// Socket communication thread.
	static DWORD WINAPI KzLocalNetworkTransactionThread(LPVOID lpParam) {
		KzLocalNewtworkThreadArg* kzArg = (KzLocalNewtworkThreadArg*)lpParam;

		// Show debug message
		kzArg->mCtx->DbgPrint(_T("KzLocalNetworkTransactionThread: Entered Thread!\n"));

		// Show debug message
		kzArg->mCtx->DbgPrint(_T("KzLocalNetworkTransactionThread: Starting listening session!\n"));

		while (true) {
			
			ENTER_MUTEX_SCOPE(kzArg->mCtx->MtxMutexKzThreadFlag);

			if (!kzArg->mCtx->KzThreadFlag) break;

			kzArg->sGrp->listen(1000);
		
			EXIT_MUTEX_SCOPE(kzArg->mCtx->MtxMutexKzThreadFlag);
		}

		// Show debug message
		kzArg->mCtx->DbgPrint(_T("KzLocalNetworkTransactionThread: Service thread received kill signal!\n"));

		return 0;
	}


public:
	HorizonDlg(CWnd* pParent = nullptr);	// standard constructor

public:
	// Creates new entry in the process list.
	VOID LbCreateProcessEntry(PTCHAR FULL_PATH, BOOL SECURITY, DWORD PID);
	INT  LbFindProcessItemByPid(DWORD PID);
	VOID LbRemoveProcessItemByPid(DWORD PID);
	BOOL MpInitializeSharedMemoryMap();
	VOID MpNotifyClientsOnSharedMemUpdate(MpSharedMemAction mAction);

	template < typename LambdaFunctor >
	VOID MtIterateThroughClients( LambdaFunctor );


	// Holds the list of process along with details
	CListCtrl mProcessList;
	CButton   cbxSetClearSecurityToken;
	CListBox  mPathList;
	CEdit     mLogCtrl;

	afx_msg void OnBnClickedButtonSigKill();
	afx_msg void OnNMClickListProcessList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBnClickedCheckcbxsetclearsecuritytoken();
	afx_msg void OnBnClickBrowseFolder();
	afx_msg void OnBnClickedRemoveFolder();
};


