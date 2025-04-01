// Copyright (C) 2024 Evan McBroom
//
// Network logon (netlogon) cache. Types for the netlogon
// protocol (e.g., [MS-NRPC]) are not included.
//
#pragma once
#include <phnt_windows.h>

#include <ntsam.h>

#define NLP_CACHE_ENCRYPTION_KEY_LEN (64)
#define NLP_CACHE_NAME               L"\\Registry\\Machine\\Security\\Cache"
#define NLP_CACHE_TITLE_INDEX        100 // Provided at the TitleIndex parameter to NtCreateKey when creating the cache

#define NLP_DEFAULT_LOGON_CACHE_COUNT (10)
#define NLP_MAX_LOGON_CACHE_COUNT     (50)

// Netlogon revision numbers. At least one additional revision
// was added after NT 5.2 which added the IterationCount member
// to the _LOGON_CACHE_ENTRY structure. That revision number
// still needs to be added to these macro defines.
#define NLP_CACHE_REVISION_NT_1_0   (0x00010000) // NT 3.0
#define NLP_CACHE_REVISION_NT_1_0B  (0x00010002) // NT 3.5
#define NLP_CACHE_REVISION_NT_4_SP4 (0x00010003) // NT 4.0 SP 4 - adds support for salted passwords
#define NLP_CACHE_REVISION_NT_5_0   (0x00010004) // NT 5.0 - adds support opaque cache data and storing data in a single location

#ifdef __cplusplus
extern "C" {
#endif

struct _CACHE_PASSWORDS;
struct _LOGON_CACHE_ENTRY;
struct _LOGON_CACHE_ENTRY_NT_4_SP4;

/// <summary>
/// Cached password are stored as two encrypted one way
/// function (OWF) passwords concatenated together.
/// </summary>
typedef struct _CACHE_PASSWORDS {
    USER_INTERNAL1_INFORMATION SecretPasswords;
} CACHE_PASSWORDS, *PCACHE_PASSWORDS;

/// <summary>
/// The storage format for the netlogon cache. The stored information
/// is a subset of whats included in NETLOGON_VALIDATION_SAM_INFO.
/// 
/// Immediately following this structure in the cache is a series of
/// GROUP_MEMBERSHIP structures. Immediately following the GROUP_MEMBERSHIP
/// structures will be a SID which represents the LogonDomainId. The
/// remaining data is the content of the UNICODE_STRING typed members
/// for the LOGON_CACHE_ENTRY structure.
/// 
/// Prior to NT 5.0, the CACHE_PASSWORDS and SupplementalCacheData content
/// was stored in a seperate location. On NT 5.0 and higher this content
/// is encrypted with a key derived from a 128 bit random value and a
/// per-machine lsa secret then stored in the cache after the original cache
/// data content. The random value that is used is stored as the RandomKey
/// member of this structure.
/// 
/// The msv1_0!NlpBuildCacheEntry method should be consulted for any
/// deviations that are found with this description and the layout of the
/// cache data on disk.
/// </summary>
typedef struct _LOGON_CACHE_ENTRY {
    USHORT UserNameLength;
    USHORT DomainNameLength;
    USHORT EffectiveNameLength;
    USHORT FullNameLength;
    USHORT LogonScriptLength;
    USHORT ProfilePathLength;
    USHORT HomeDirectoryLength;
    USHORT HomeDirectoryDriveLength;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG GroupCount; // The number of GROUP_MEMBERSHIP structures following this structure in the cache
    USHORT LogonDomainNameLength;
    // Remaining members are present on NT 1.0A and higher
    USHORT LogonDomainIdLength; // Originally unused and named Unused1
    TimeStamp Time; // Defined by Microsoft as LARGE_INTEGER, but TimeStamp is more appropriate
    ULONG Revision;
    ULONG SidCount; // Originally unused and named Unused2
    BOOLEAN Valid;
    // Remaining members are present on 3.51 build 622 and higher
    CHAR Unused; // Was originally typed as CHAR[2] before IterationCount was added
    USHORT IterationCount; // Data was retyped as USHORT after NT 5.2 and Unused's length was shortened to account for the change
    ULONG SidLength;
    // Following members are present on 3.51 but went unused until NT 5.0
    ULONG LogonPackage; // The RPC ID of the package doing the logon.
    USHORT DnsDomainNameLength;
    USHORT UpnLength;
    // Remaining members are present on NT5.0 build 2053 and higher
    CHAR RandomKey[16]; // The 128 bit random value that is used with an lsa secret to derive the encryption key for CachePasswords and SupplementalCacheData
    CHAR MAC[16]; // encrypted data integrity check.
    // All remaining data including the marshalled data beyong this structure
    // is encrypted at rest and protected from tampering via an HMAC.
    CACHE_PASSWORDS CachePasswords;
    ULONG SupplementalCacheDataLength; // Length of opaque supplemental cache data.
    ULONG SupplementalCacheDataOffset; // Offset from the start of LOGON_CACHE_ENTRY to the SupplementalCacheData
    ULONG CacheFlags; // Populated with the RequestFlags member from the original MSV1_0_CACHE_LOGON_REQUEST call
    ULONG LogonServerLength; // Was previously named Spare2. Refers to LogonServer data that is stored after structure in the cache
    // Remaining members are reserved for future use
    ULONG Spare3;
    ULONG Spare4;
    ULONG Spare5;
    ULONG Spare6;
} LOGON_CACHE_ENTRY, *PLOGON_CACHE_ENTRY;

/// <summary>
/// Please refer to _LOGON_CACHE_ENTRY for detailed
/// information about this structure.
/// </summary>
typedef struct _LOGON_CACHE_ENTRY_NT_4_SP4 {
    USHORT UserNameLength;
    USHORT DomainNameLength;
    USHORT EffectiveNameLength;
    USHORT FullNameLength;
    USHORT LogonScriptLength;
    USHORT ProfilePathLength;
    USHORT HomeDirectoryLength;
    USHORT HomeDirectoryDriveLength;
    ULONG UserId;
    ULONG PrimaryGroupId;
    ULONG GroupCount;
    USHORT LogonDomainNameLength;
    USHORT LogonDomainIdLength;
    LARGE_INTEGER Time;
    ULONG Revision;
    ULONG SidCount;
    BOOLEAN Valid;
    CHAR Unused[3];
    ULONG SidLength;
    ULONG LogonPackage;
    USHORT DnsDomainNameLength;
    USHORT UpnLength;
} LOGON_CACHE_ENTRY_NT_4_SP4, *PLOGON_CACHE_ENTRY_NT_4_SP4;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Netlogon {
    using CACHE_PASSWORDS = _CACHE_PASSWORDS;
    using LOGON_CACHE_ENTRY = _LOGON_CACHE_ENTRY;
    using LOGON_CACHE_ENTRY_NT_4_SP = _LOGON_CACHE_ENTRY_NT_4_SP4;
}
#endif