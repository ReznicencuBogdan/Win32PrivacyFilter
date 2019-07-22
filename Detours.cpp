#include "Detours.h"
#include "OpInsight.h"

/* *************************************************************
*  **** This library is maintained by Reznicencu Bogdan ********
*  ***************** for testing purposes.  ********************
*  ************************************************************/


std::vector<HookInfoClass>::iterator Detours::FindHookClassInfoByAddres(LPVOID WantedFunction) {
	return std::find(mHookInfoClassVector.begin(), mHookInfoClassVector.end(), WantedFunction);
}

BOOL Detours::IsFunctionAlreadyHooked(LPVOID WantedFunction) {
	return (FindHookClassInfoByAddres(WantedFunction) != mHookInfoClassVector.end());
}

INT Detours::Hookfunction(LPVOID WantedFunction, LPVOID DetourFunction, LPVOID& NewOriginalFunction) {
	HookInfoClass mHookInfo;
	memset(&mHookInfo, 0x00, sizeof(HookInfoClass));
	mHookInfo.mWantedFunctionAddress = WantedFunction;

	// Verify if the function has already been hooked
	if (IsFunctionAlreadyHooked(WantedFunction)) return HK_FAIL | HK_FAIL_ALREADY_HOOKED;

	OPCODE_INF mInstructionInfo;
	SIZE_T mInstructionOffset = 0;
	SIZE_T mNewOriginalFunctionSize = 0;
	DWORD mOriginalProtectionFlags;

	// Construct an array which will hold the new JMP instruction
	BYTE mJumpInstruction[5] = { 0xE9 , 0x00, 0x00, 0x00, 0x00 };

	// Search for full-set instruction in the jmp near-bounds
	while (mInstructionOffset < 5) {
		LPBYTE mByteAddress = (LPBYTE)WantedFunction + mInstructionOffset;
		BYTE   mByteValue = (*mByteAddress);

		// Get current instruction info.
		PkRegisterInstruction(mByteAddress, &mInstructionInfo);

		// Check if reached out-of-bounds. Not every compiler respects the rule though...
		if (mByteValue == 0x90 || mByteValue == 0xCC) return HK_FAIL;

		// Check if the instruction operates on relative offsets
		// Validate and modify in future release.




		// Increase the instruction offset.
		mInstructionOffset += mInstructionInfo.len;
	}

	// Save the size of the intructions to be replaced.
	mHookInfo.mWantedFunctionInstructionSize = mInstructionOffset;

#if defined _M_IX86
	// Decide how big the new original function is.
	mNewOriginalFunctionSize = mInstructionOffset + 5;

#elif defined _M_X64

	// Decide how big the new original function is.
	mNewOriginalFunctionSize = mInstructionOffset + 16;
#endif


	// Allow write protection
	if (!VirtualProtect(WantedFunction, mInstructionOffset, PAGE_EXECUTE_READWRITE, &mOriginalProtectionFlags)) return HK_FAIL_MEM_PROTECTION;
	// Allocate a new address to store the original function code.
	NewOriginalFunction = VirtualAlloc(NULL, mNewOriginalFunctionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// If it failed to allocate a new space then restore protections.
	if (!NewOriginalFunction) {
		VirtualProtect(WantedFunction, mInstructionOffset, mOriginalProtectionFlags, &mOriginalProtectionFlags);

		return HK_FAIL | HK_FAIL_MEM_ALLOC;
	}

	// Create a trampoline.
	/* BYTE mTrampoline[12] = { 0x48 , 0xB8, 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0xFF , 0xE0 };
	* (PSIZE_T)&mTrampoline[2] = (SIZE_T)WantedFunction + mInstructionOffset;*/

#if defined _M_IX86
	// I'm on 32bit so a relative 32bit jump is possible here.
	BYTE mTrampoline[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };		/* JMP 0x00000000 */

	INT mTrmpOffset = (INT)((INT)WantedFunction + (INT)mInstructionOffset - (INT)(NewOriginalFunction) - (INT)mInstructionOffset - 5);

	// Write the relative trampoline 32bit
	*(PINT)& mTrampoline[1] = mTrmpOffset;

#elif defined _M_X64
	BYTE mTrampoline[16] = {
					 0x50 ,															        /* PUSH RAX					   */
					 0x48, 0xB8 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0x00 , 0xFF ,	/* MOV RAX,0x0000000000000000  */
					 0x48, 0x87, 0x04, 0x24,												/* XCHG QWORD PTR SS:[RSP],RAX */
					 0xC3 };																/* RET						   */

	*(PSIZE_T)& mTrampoline[3] = (SIZE_T)WantedFunction + mInstructionOffset;
#endif

	// Nope the memory space for safety reasons.
	memset(NewOriginalFunction, 0x90, mNewOriginalFunctionSize);
	// For a trampoline to work, I will have to execute the instrution replaced with a jmp.
	memcpy_s(NewOriginalFunction, mInstructionOffset, WantedFunction, mInstructionOffset);
	// Append the trampoline to OriginalFunction.
	memcpy_s((LPVOID)((SIZE_T)NewOriginalFunction + mInstructionOffset), sizeof(mTrampoline), mTrampoline, sizeof(mTrampoline));


	// Create a backup of the original instructions.
	memcpy_s(mHookInfo.mWantedFunctionBckpInstructions, mInstructionOffset, WantedFunction, mInstructionOffset);
	// Reset the instructions with nop'es
	memset(WantedFunction, 0x90, mInstructionOffset);
	// Calculate the jmp offset
	*(PINT)& mJumpInstruction[1] = (INT)((SIZE_T)DetourFunction - (SIZE_T)WantedFunction - 5);
	// Write the jump.
	memcpy_s(WantedFunction, 5, mJumpInstruction, 5);


	// Store the address of the new OriginalFunctionS
	mHookInfo.mNewOriginalFunction = NewOriginalFunction;
	// Store the hook info
	mHookInfoClassVector.push_back(mHookInfo);
	// Restore old protection
	VirtualProtect(WantedFunction, mInstructionOffset, mOriginalProtectionFlags, &mOriginalProtectionFlags);

	return HK_SUCCEDED;
}

VOID Detours::UnhookFunction(LPVOID WantedFunction) {
	// Check existance of instance in vector
	std::vector < HookInfoClass >::iterator mItterator = FindHookClassInfoByAddres(WantedFunction);
	// If none then return
	if (mItterator == mHookInfoClassVector.end()) return;
	// Cast the instance to the object.
	HookInfoClass mHookInfo = *mItterator;
	// Hold the original memory protection flags.
	DWORD mOriginalProtectionFlags;
	// Change memory protection.
	VirtualProtect(mHookInfo.mWantedFunctionAddress, mHookInfo.mWantedFunctionInstructionSize, PAGE_EXECUTE_READWRITE, &mOriginalProtectionFlags);
	// Restore the original instruction to WantedFunction.
	memcpy_s(WantedFunction, mHookInfo.mWantedFunctionInstructionSize, mHookInfo.mWantedFunctionBckpInstructions, mHookInfo.mWantedFunctionInstructionSize);
	// Restore protection 
	VirtualProtect(mHookInfo.mWantedFunctionAddress, mHookInfo.mWantedFunctionInstructionSize, mOriginalProtectionFlags, &mOriginalProtectionFlags);
	// Free the memory allocated for the trampoline.
	VirtualFree(mHookInfo.mNewOriginalFunction, 0, MEM_RELEASE);
	// Remove the entry from the vector,
	mHookInfoClassVector.erase(mItterator);
}

Detours::~Detours() {
	if (mLocalScopeClass)
		for (auto& mHookInfo : mHookInfoClassVector)
			UnhookFunction(mHookInfo.mWantedFunctionAddress);
}

