#pragma once

#include <Windows.h>
#include <vector>


/* *************************************************************
*  **** This library is maintained by Reznicencu Bogdan ********
*  ***************** for testing purposes.  ********************
*  ************************************************************/


#define HK_FAIL					0x0001
#define HK_FAIL_ALREADY_HOOKED	0x0002
#define HK_FAIL_MEM_PROTECTION	0x0004
#define HK_FAIL_MEM_ALLOC		0x0008

#define HK_SUCCEDED				0x0000

struct HookInfoClass {
	LPVOID mWantedFunctionAddress;  // -
	LPVOID mNewOriginalFunction;	// - 

	BYTE mWantedFunctionBckpInstructions[16];
	SIZE_T mWantedFunctionInstructionSize; // -

	BOOL operator==(CONST LPVOID& mComparableAddress) CONST
	{
		return mWantedFunctionAddress == mComparableAddress;
	}
};


class Detours {
private:
	// Removes the hooks at class destruction.
	BOOL mLocalScopeClass;
	// Stores all the hooks details.
	std::vector<HookInfoClass> mHookInfoClassVector;
public:
	Detours(BOOL mLocalScopeClass = false) {
		this->mLocalScopeClass = mLocalScopeClass;
	}

	// Finds a hook inside the vector
	std::vector<HookInfoClass>::iterator FindHookClassInfoByAddres(LPVOID WantedFunction);
	// Tells if the function has already been modified
	BOOL IsFunctionAlreadyHooked(LPVOID WantedFunction);
	// Create a detour for the function.
	INT Hookfunction(LPVOID WantedFunction, LPVOID DetourFunction, LPVOID &NewOriginalFunction);
	// Unhooks function and restores initial values.
	VOID UnhookFunction(LPVOID WantedFunction);
	// On class destruction.
	~Detours();
};