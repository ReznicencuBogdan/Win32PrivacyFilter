CONST UINT  mServerPort = 5000;

CONST DWORD mCommand_pid = 0x0111;
CONST DWORD mCommand_security_status = 0x1011;
CONST DWORD mCommand_sig_kill = 0x2022;
CONST DWORD mCommand_empty_data = 0x00000000;
CONST DWORD mCommand_shared_data_action = 0x3303;


CONST DWORD mMapEntrySize = MAX_PATH * sizeof(TCHAR);
CONST DWORD mMapMaxCount = 30;
CONST DWORD mMaxMapFileSize = mMapEntrySize * mMapMaxCount; // 30 entries of THCAR

#define ENTER_MUTEX_SCOPE(MtxResource) WaitForSingleObject(MtxResource, INFINITE);
#define EXIT_MUTEX_SCOPE(MtxResource) ReleaseMutex(MtxResource);