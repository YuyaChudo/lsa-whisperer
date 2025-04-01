// Copyright (C) 2024 Evan McBroom
//
// Kernel security device driver (ksecdd)
//
// I originally audited ksecdd in July 2023 with Jonny Johnson (@jsecurity101).
// Our goal was to document for the LSA Whisperer wiki ksecdd's use as a NTOS
// extension host. As an extension host, ksecdd provides equivalents to the Win32
// LSA APIs for device drivers.
//
// @floesen showed in April 2024 that an IOCTL for ksecdd may be used when
// executing within LSA to execute an arbitrary address in kernel space with
// a user controllable argument (e.g., FSCTL_HANDLE_FUNCTION_RETURN).
// Reference: https://github.com/floesen/KExecDD
//
// Jonny and I knew from our previous work that ksecdd provided other abusable
// IOCTLs when executing within LSA but we had not fully audited these IOCTLs
// at that time. Here is my attempt at a full audit of the current IOCTLs
// structures for ksecdd, completed in October 2024.
//
// The only type name that is currently unknown is the type name for the input
// to IOCTL_KSEC_IPC_SET_FUNCTION_RETURN, but its definition and description
// is believed to be following:
//
// /// <summary>
// /// Used to communicate the return value or status of a previous
// /// LSAP_KERNEL_CLIENT_CALLBACK IOCTL call via a call to
// /// IOCTL_KSEC_IPC_SET_FUNCTION_RETURN. KsecDD will execute the
// /// address of Pointer as a function with the value of Status as
// /// its only argument.
// /// </summary>
// struct {
//     PVOID Pointer;
//     LONG Status;
// };
//
#pragma once
#include <phnt_windows.h>

#include <sspi.h>

// A minimal set of macros are defined for interacting with
// ksecdd when the phnt headers are not being used.
#ifndef _NTIOAPI_H
    #define _NTIOAPI_H

    #define KSEC_DEVICE_NAME   "\\Device\\KSecDD"

    #define IOCTL_KSEC_CONNECT_LSA                      CTL_CODE(FILE_DEVICE_KSEC, 0, METHOD_BUFFERED, FILE_WRITE_ACCESS)
    #define IOCTL_KSEC_RNG                              CTL_CODE(FILE_DEVICE_KSEC, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_RNG_REKEY                        CTL_CODE(FILE_DEVICE_KSEC, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_ENCRYPT_MEMORY                   CTL_CODE(FILE_DEVICE_KSEC, 3, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_DECRYPT_MEMORY                   CTL_CODE(FILE_DEVICE_KSEC, 4, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_ENCRYPT_MEMORY_CROSS_PROC        CTL_CODE(FILE_DEVICE_KSEC, 5, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_DECRYPT_MEMORY_CROSS_PROC        CTL_CODE(FILE_DEVICE_KSEC, 6, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_ENCRYPT_MEMORY_SAME_LOGON        CTL_CODE(FILE_DEVICE_KSEC, 7, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_DECRYPT_MEMORY_SAME_LOGON        CTL_CODE(FILE_DEVICE_KSEC, 8, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_FIPS_GET_FUNCTION_TABLE          CTL_CODE(FILE_DEVICE_KSEC, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_ALLOC_POOL                       CTL_CODE(FILE_DEVICE_KSEC, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_FREE_POOL                        CTL_CODE(FILE_DEVICE_KSEC, 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_COPY_POOL                        CTL_CODE(FILE_DEVICE_KSEC, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_DUPLICATE_HANDLE                 CTL_CODE(FILE_DEVICE_KSEC, 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_REGISTER_EXTENSION               CTL_CODE(FILE_DEVICE_KSEC, 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_CLIENT_CALLBACK                  CTL_CODE(FILE_DEVICE_KSEC, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_GET_BCRYPT_EXTENSION             CTL_CODE(FILE_DEVICE_KSEC, 16, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_GET_SSL_EXTENSION                CTL_CODE(FILE_DEVICE_KSEC, 17, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_GET_DEVICECONTROL_EXTENSION      CTL_CODE(FILE_DEVICE_KSEC, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_ALLOC_VM                         CTL_CODE(FILE_DEVICE_KSEC, 19, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_FREE_VM                          CTL_CODE(FILE_DEVICE_KSEC, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_COPY_VM                          CTL_CODE(FILE_DEVICE_KSEC, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_CLIENT_FREE_VM                   CTL_CODE(FILE_DEVICE_KSEC, 22, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_INSERT_PROTECTED_PROCESS_ADDRESS CTL_CODE(FILE_DEVICE_KSEC, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_REMOVE_PROTECTED_PROCESS_ADDRESS CTL_CODE(FILE_DEVICE_KSEC, 24, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_GET_BCRYPT_EXTENSION2            CTL_CODE(FILE_DEVICE_KSEC, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_IPC_GET_QUEUED_FUNCTION_CALLS    CTL_CODE(FILE_DEVICE_KSEC, 26, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
    #define IOCTL_KSEC_IPC_SET_FUNCTION_RETURN          CTL_CODE(FILE_DEVICE_KSEC, 27, METHOD_NEITHER, FILE_ANY_ACCESS)
#endif

#define KSEC_DEVICE_NAME_U L"\\Device\\KsecDD"

#ifdef __cplusplus
extern "C" {
#endif

struct _LSAP_DUPLICATE_HANDLE;
struct _LSAP_KERNEL_CLIENT_CALLBACK;
struct _LSAP_MEM_COPY;
struct _LSAP_MEM_FREE;
struct _LSAP_POOL_ALLOC;
struct _LSAP_PROTECTED_PROCESS_ADDRESS;
struct _LSAP_VM_ALLOC;
struct _LSAP_VM_COPY;
struct _LSAP_VM_FREE;

/// <summary>
/// Duplicate an lsa handle to a target process specified by ClientHandle.
/// If ClientHandle is 0, then the handle is duplicated to the SYSTEM process.
/// Duplication is done with DUPLICATE_SAME_ACCESS.
/// </summary>
/// <returns>The value of the handle within the specified client process.</returns>
typedef struct _LSAP_DUPLICATE_HANDLE {
    HANDLE HandleToDuplicate; /// Handle within lsa to duplicate
    HANDLE ClientHandle; /// Handle of a client process that the lsa handle should be duplicated to
    ULONG PackageIndex; /// Used for lsa debug logging
} LSAP_DUPLICATE_HANDLE, *PLSAP_DUPLICATE_HANDLE;

/// <summary>
/// Used to execute a callback function within a user mode process.
/// The original intention of the method was <see href="https://github.com/EvanMcBroom/lsa-whisperer/blob/f8322899275c25a3b9bcfa4f362c16ab8d307403/include/spm.hpp#L457">to execute callbacks inside client processes of LSA's SPM APIs.</see>
/// </summary>
/// <returns>A SecBuffer of the output data.</returns>
typedef struct _LSAP_KERNEL_CLIENT_CALLBACK {
    ULONG CallbackType; // Should be set to 3 for <see href="https://github.com/EvanMcBroom/lsa-whisperer/blob/f8322899275c25a3b9bcfa4f362c16ab8d307403/include/spm.hpp#L469">CallbackType::PACKAGE</see>
    PVOID CallbackFunction;
    PVOID CallbackArg1;
    PVOID CallbackArg2;
    SecBuffer CallbackInput;
} LSAP_KERNEL_CLIENT_CALLBACK, *PLSAP_KERNEL_CLIENT_CALLBACK;

/// <summary>
/// Copy date between lsa memory and a paged pool.
/// The paged pool memory region specified by SystemAddress and CopySize
/// must be in the list of valid memory ranges for copying data.
/// If LsaAddress is detected as being in kernel memory, then
/// a simply memcpy is used. Otherwise a MmCopyVirtualMemory is used.
/// </summary>
typedef struct _LSAP_MEM_COPY {
    PVOID LsaAddress;
    PVOID SystemAddress;
    ULONG CopySize;
    LONG CopyToSystem; /// If memory should be copied to the paged pool or the reverse
    ULONG PackageIndex;
} LSAP_MEM_COPY, *PLSAP_MEM_COPY;

/// <summary>
/// Free a SYSTEM address specifying a paged pool or a virtual memory region.
/// The memory is assumed to be the result of a LSAP_POOL_ALLOC or LSAP_VM_ALLOC
/// call and it must be in the list of valid memory ranges. If the address is
/// for a virtual memory, the process must additional be a protected process
/// Otherwise, the memory is only removed from the list of valid memory ranges,
/// if present in the list. If all checks pass, the memory is freed via either
/// ZwFreeVirtualMemory with MEM_RELEASE or with ExFreePoolWithTag.
/// </summary>
typedef struct _LSAP_MEM_FREE {
    HANDLE SystemAddress;
    ULONG PackageIndex; /// Used for lsa debug logging
} LSAP_MEM_FREE, *PLSAP_MEM_FREE;

/// <summary>
/// Allocate a paged pool of kernel memory with tag 0x5a65734b (e.g., 'KseZ').
/// The allocated memory will be added in a list of valid memory ranges for
/// other IOCTL calls.
/// </summary>
/// <returns>The base address of the allocated paged pool.</returns>
typedef struct _LSAP_POOL_ALLOC {
    ULONG AllocSize;
    ULONG PackageIndex; // Used for lsa debug logging
} LSAP_POOL_ALLOC, *PLSAP_POOL_ALLOC;

/// <summary>
/// Used to insert or remove a virtual memory region in the list of valid
/// memory regions for performing other IOCTL calls, such as LSAP_MEM_COPY,
/// LSAP_MEM_FREE, LSAP_VM_COPY, and LSAP_VM_FREE. Paged pools and virtual
/// memory allocated by LSAP_POOL_ALLOC or LSAP_VM_ALLOC are automatically
/// added to this list.
/// </summary>
typedef struct _LSAP_PROTECTED_PROCESS_ADDRESS {
    PVOID StartAddress;
    ULONG Size;
} LSAP_PROTECTED_PROCESS_ADDRESS, *PLSAP_PROTECTED_PROCESS_ADDRESS;

/// <summary>
/// Allocates memory inside a protected process.
/// The process must be protected, otherwise the IOCTL call will fail.
/// The allocated memory will be committed with a protection or read/write.
/// The allocated memory will be added in a list of valid memory ranges for
/// other IOCTL calls.
/// </summary>
/// <returns>The base address of the allocated memory.</returns>
typedef struct _LSAP_VM_ALLOC {
    HANDLE ClientHandle; /// Handle of a client process that the memory should be allocated in
    SIZE_T AllocSize;
} LSAP_VM_ALLOC, *PLSAP_VM_ALLOC;

/// <summary>
/// Copies memory between lsa and a user mode process.
/// The memory region specified by ClientAddress and CopySize
/// must be valid memory within the user mode process.
/// The memory region specified by LsaAddress and CopySize is
/// not validated. The memory is copied using MmCopyVirtualMemory.
/// </summary>
typedef struct _LSAP_VM_COPY {
    HANDLE ClientHandle; /// Handle to a user mode process
    PVOID ClientAddress; /// Address in the user mode process
    PVOID LsaAddress;
    BOOL CopySize;
    ULONG CopyToClient; /// If memory should be copied to the user mode process or the reverse
} LSAP_VM_COPY, *PLSAP_VM_COPY;

/// <summary>
/// Free memory inside a user mode process. The memory region does need to
/// be in the valid list of memory regions, but unlike the LSAP_VM_ALLOC
/// IOCTL call, the user mode process does not have to be a protected
/// process for the call to succeed. The memory is freed via
/// ZwFreeVirtualMemory with MEM_RELEASE.
/// </summary>
typedef struct _LSAP_VM_FREE {
    HANDLE ClientHandle; /// Handle to the user mode process
    PVOID ClientAddress;
} LSAP_VM_FREE, *PLSAP_VM_FREE;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Lsa {
    using CLIENT_CALL_RETURN = CLIENT_CALL_RETURN;
    using DUPLICATE_HANDLE = LSAP_DUPLICATE_HANDLE;
    using KERNEL_CLIENT_CALLBACK = LSAP_KERNEL_CLIENT_CALLBACK;
    using MEMORY_COPY = LSAP_MEM_COPY;
    using MEMORY_FREE = LSAP_MEM_FREE;
    using POOL_ALLOC = LSAP_POOL_ALLOC;
    using PROTECTED_PROCESS_ADDRESS = LSAP_PROTECTED_PROCESS_ADDRESS;
    using VM_ALLOC = LSAP_VM_ALLOC;
    using VM_COPY = LSAP_VM_COPY;
    using VM_FREE = LSAP_VM_FREE;
}
#endif