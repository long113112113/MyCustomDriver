/*
 * @file Memory.hpp
 * @brief Memory Utilities, like hooking or something.
 */

#pragma once

#include "../Include.hpp"

/*
 * @brief Write on Read-Only Memory.
 * @returns `TRUE` if operation was successful, `FALSE` otherwise.
 */
BOOLEAN WriteOnReadOnlyMemory(PVOID src, PVOID dst, size_t size);

/*
 * @brief Determine if address is canonical.
 * @returns `TRUE` if the address is canonical, `FALSE` otherwise.
 */
BOOLEAN IsCanonicalAddress(PVOID address);

/*
 * @brief Make Non-canonical address to canonical address.
 * @returns `address` made to be canonical.
 */
PVOID MakeCanonicalAddress(PVOID address);

/*
 * @brief Get Pml4E's VA Type.
 * @returns `0xFF` if index was invalid, else the Pml4e's VA Type, based on _MI_SYSTEM_VA_TYPE.
 */
UCHAR GetPml4eVaType(size_t index);

/*
 * @brief Get PML4/PDPT/PD/PT Entry Pointer for virtual address. You can set it by level.
 * @param v: The address that you want to get.
 * @param level: 4 for PML4, 3 for PDPT, 2 for PD, 1 for PT.
 * @returns Page Table entry for virtual address. `NULL` if failed to get it
 */
UINT64* GetPageTableEntryPointer(PVOID v, size_t level);
UINT64* GetLastPageTableEntryPointer(PVOID v);

#define FlushTlb __writecr3(__readcr3())

/*
 * @brief Get Pml4 index of address.
 */

size_t GetPml4Index(PVOID address);

/*
 * @brief Determine if the address is valid.
 * @return `TRUE` if valid, `FALSE` otherwise.
 */
BOOLEAN IsValidAddress(PVOID address);

namespace Hook {

	/*
	 * @brief Trampoline hook `hookFunction`.
	 * @details `gateway` SHOULD be a function with over than 32 opcodes.
	 * @return `TRUE` if operation was successful.
	 */
	BOOLEAN HookTrampoline(PVOID origFunction, PVOID hookFunction, PVOID gateway, size_t len);

}

/*
 * @brief Get Module Information
 * @param szModuleName: module name
 * @param outTargetModule: pointer for module entry
 */
NTSTATUS GetModuleInformation(const char* szModuleName, PSYSTEM_MODULE_ENTRY outTargetModule);

/*
 * @brief Get Kernel Base and Size.
 * @param outBase: pointer for kernel base.
 * @param outSize: pointer for kernel size.
 */
BOOLEAN GetKernelBaseNSize(uintptr_t* outBase, size_t* outSize);

/*
 * @brief Find PE Section By Name
 * @param base: PE Image Base
 * @param sectionName: Section Name
 * @param outSectionBase: pointer for section base.
 * @param outSectionSize: pointer for section size.
 * @return `TRUE` if operation was successful.
 */
BOOLEAN FindPeSectionByName(size_t base, const char sectionName[8], uintptr_t* outSectionBase, size_t* outSectionSize);

/*
* @brief Search Pattern Range.
* @param start: start.
* @param end: end.
* @param pattern: pattern for searching.
* @param mask: mask for pattern. 'x' for valid pattern, '?' for wildcard.
* @param result: the result is storing here.
* @return `TRUE` if pattern is found.
*/
BOOLEAN PatternSearchRange(unsigned char* start, unsigned char* end, const UCHAR* pattern, const char* mask, uintptr_t* result);

/*
 * @brief Search Pattern in specific NT Kernel Section.
 * @param sectionName: Section Name
 * @param pattern: pattern for searching.
 * @param mask: mask for pattern. 'x' for valid pattern, '?' for wildcard.
 * @param result: pointer to the result.
 */
BOOLEAN PatternSearchNtKernelSection(const char sectionName[8], const UCHAR* pattern, const char* mask, uintptr_t* result);

/*
 * @brief Get Absolute Address from QWORD PTR [rip+Rel4BAddr] instruction.
 */
uintptr_t GetAbsAddrFromRel4B(unsigned int* Rel4BAddr);