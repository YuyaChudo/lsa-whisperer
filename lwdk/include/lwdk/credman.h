// Copyright (C) 2024 Evan McBroom
//
// Credential manager (credman)
//
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

#include "um/ntsecapi.h"
#include <wincred.h>

#define CRED_TARGET_INFO_HASH_TABLE_SIZE 16
#define CREDSETS_FLAGS_LOCAL_ACCOUNT     0x01 // User is logged onto a local account
#define MARSHALED_CREDENTIAL_SET_VERSION 1

// How to match a cred to target info
// Ordered from most to least specific
#define CRED_DFS_SHARE_NAME         0
#define CRED_DNS_SERVER_NAME        1
#define CRED_NETBIOS_SERVER_NAME    2
#define CRED_TARGET_NAME            3
#define CRED_WILDCARD_SERVER_NAME   4
#define CRED_DNS_DOMAIN_NAME        5
#define CRED_NETBIOS_DOMAIN_NAME    6
#define CRED_UNIVERSAL_SESSION_NAME 7
#define CRED_UNIVERSAL_NAME         8
#define CRED_MAX_ALIASES            9

#ifdef __cplusplus
extern "C" {
#endif

enum _CredParsedUserNameType;
enum _ENCODE_BLOB_ENUM;
enum _TARGET_ATTRIBUTE_TYPE;
enum _TARGET_NAME_TYPE;
enum _WILDCARD_TYPE;
enum _WTOA_ENUM;

struct _CANONICAL_CREDENTIAL;
struct _CANONICAL_TARGET_INFO;
struct _CRED_WRITE_UNDO;
struct _CREDENTIAL_SET;
struct _CREDENTIAL_SETS;
struct _CREDENTIAL_TARGET_INFORMATIONW;
struct _ENCRYPTED_CREDENTIALW;
struct _MARSHALED_CREDENTIAL;
struct _MARSHALED_CREDENTIAL_SET;
struct _PROMPT_DATA;
struct _SESSION_CREDENTIAL_SETS;
struct _USER_CREDENTIAL_SETS;

// Unknown
enum ProtectionMethodType;
struct CREDENTIAL_FILE_HEADER;

typedef enum _CredParsedUserNameType {
    parsedUsernameInvalid = 0,
    parsedUsernameUpn = 1,
    parsedUsernameNt4Style = 2,
    parsedUsernameCertificate = 3,
    parsedUsernameNonQualified = 4,
} CredParsedUserNameType,
    *PCredParsedUserNameType;

// Describe if encoding or decoding should be done
typedef enum _ENCODE_BLOB_ENUM {
    DoBlobEncode = 0, // Encode CredentialBlob
    DoBlobDecode = 1, // Decode CredentialBlob
    DoBlobNeither = 2 // Leave Credential blob intact
} ENCODE_BLOB_ENUM,
    *PENCODE_BLOB_ENUM;

typedef enum _TARGET_ATTRIBUTE_TYPE {
    TaTarget = 0,
    TaName = 1,
    TaBatch = 2,
    TaInteractive = 3,
    TaService = 4,
    TaNetwork = 5,
    TaNetworkCleartext = 6,
    TaRemoteInteractive = 7,
    TaCachedInteractive = 8,
    TaUnknown = 9,
} TARGET_ATTRIBUTE_TYPE,
    *PTARGET_ATTRIBUTE_TYPE;

typedef enum _TARGET_NAME_TYPE {
    IsUsernameTarget = 0,
    IsNotUsernameTarget = 1,
    MightBeUsernameTarget = 2
} TARGET_NAME_TYPE,
    *PTARGET_NAME_TYPE;

// Wildcard formats for the TargetName field of a cred
typedef enum _WILDCARD_TYPE {
    WcDfsShareName = 0, // Target name of the form <DfsRoot>\<DfsShare>
    WcServerName = 1, // Target name of the form <ServerName>
    WcServerWildcard = 2, // Wildcard of the form *.<DnsName>
    WcDomainWildcard = 3, // Wildcard of the form <Domain>\*
    WcUniversalSessionWildcard = 4, // Wildcard of the form "*Session"
    WcUniversalWildcard = 5, // Wildcard of the form *
    WcUserName = 6 // Target Name equals UserName
} WILDCARD_TYPE,
    *PWILDCARD_TYPE;

// Character conversion direction
typedef enum _WTOA_ENUM {
    DoWtoA = 1, // Convert unicode to ansi
    DoAtoW = 2, // Convert ansi to unicode
    DoWtoW = 3 // Convert unicode to unicode
} WTOA_ENUM,
    *PWTOA_ENUM;

typedef struct _CANONICAL_CREDENTIAL {
    CREDENTIALW Cred;
    ULONG ClearCredentialBlobSize;
    LIST_ENTRY Next;
    UNICODE_STRING TargetName;
    UNICODE_STRING TargetAlias;
    UNICODE_STRING UserName;
    WILDCARD_TYPE WildcardType;
    UNICODE_STRING NonWildcardedTargetName; // TargetName without the WildcardType portion
    ULONG AllocatedSize;
    BOOLEAN ReturnMe; // Should the cred be returned to the caller
    BOOLEAN UseLogonPassword;
} CANONICAL_CREDENTIAL, *PCANONICAL_CREDENTIAL;

typedef struct _CANONICAL_TARGET_INFO {
    UNICODE_STRING TargetName;
    UNICODE_STRING NetbiosServerName;
    UNICODE_STRING DnsServerName;
    UNICODE_STRING NetbiosDomainName;
    UNICODE_STRING DnsDomainName;
    UNICODE_STRING DnsTreeName;
    UNICODE_STRING PackageName;
    DWORD Flags;
    DWORD CredTypeCount;
    LPDWORD CredTypes;
    LIST_ENTRY HashNext; // Link into SessionCredSets->TargetInfoHashTable
    LIST_ENTRY LruNext; // Link into SessionCredSets->TargetInfoLruList
} CANONICAL_TARGET_INFO, *PCANONICAL_TARGET_INFO;

// Describes when a credential should be prompted for
typedef struct _PROMPT_DATA {
    LIST_ENTRY Next;
    UNICODE_STRING TargetName;
    DWORD Type; // Credential type
    DWORD Persist;
    BOOLEAN Written; // Has the credential been written yet
} PROMPT_DATA, *PPROMPT_DATA;

// Describes ability to undo a write to a cred
typedef struct _CRED_WRITE_UNDO {
    PCANONICAL_CREDENTIAL OldCredential; // May be nullptr if there is no old cred
    PCANONICAL_CREDENTIAL NewCredential;
    PPROMPT_DATA OldPromptData; // May be nullptr if there is no old prompt data
    PPROMPT_DATA NewPromptData; // May be nullptr if there is no new prompt data
} CRED_WRITE_UNDO, *PCRED_WRITE_UNDO;

// Describes a set of credentials
typedef struct _CREDENTIAL_SET {
    LONG ReferenceCount; // Reference tracking for the credential set
    LIST_ENTRY Credentials; // List of credentials in this credential set
    BOOLEAN FileRead; // Was the credential read from disk?
    BOOLEAN Dirty; // Is the credential set dirty?
    BOOLEAN BeingWritten; // Is a thread currently writing the credential?
    ULONG WriteCount; // How many times has the credential set been marked dirty?
} CREDENTIAL_SET, *PCREDENTIAL_SET;

// Data structure to manage credential sets by the users they are specific to
typedef struct _USER_CREDENTIAL_SETS {
    LIST_ENTRY Next;
    LONG ReferenceCount; // Reference tracking for the user credential set
    PCREDENTIAL_SET EnterpriseCredSet; // The set that is replicated across the enterprise
    PCREDENTIAL_SET LocalMachineCredSet; // The set that is specific to this machine
    PSID UserSid; // This field should be a constant of the user the set is for
    RTL_CRITICAL_SECTION CritSect; // USed to serialize access to credentials
} USER_CREDENTIAL_SETS, *PUSER_CREDENTIAL_SETS;

// Describes a cred set that is specific to a session
typedef struct _SESSION_CREDENTIAL_SETS {
    LONG ReferenceCount;
    PCREDENTIAL_SET SessionCredSet;
    LIST_ENTRY PromptData;
    LIST_ENTRY TargetInfoHashTable[CRED_TARGET_INFO_HASH_TABLE_SIZE];
    LIST_ENTRY TargetInfoLruList;
    ULONG TargetInfoCount; // Number of entries in TargetInfoHashTable and TargetInfoLruList
    BOOLEAN ProfileLoaded; // Has the profile for the cred set been loaded
} SESSION_CREDENTIAL_SETS, *PSESSION_CREDENTIAL_SETS;

// Describes all of the cred sets for a logon session
typedef struct _CREDENTIAL_SETS {
    PUSER_CREDENTIAL_SETS UserCredentialSets; // Cred sets shared by all logon sessions for the user
    PSESSION_CREDENTIAL_SETS SessionCredSets; // Cred sets specific to this logon session
    ULONG Flags;
} CREDENTIAL_SETS, *PCREDENTIAL_SETS;

typedef struct _MARSHALED_CREDENTIAL {
    ULONG EntrySize;
    // Fields from a CREDENTIALW structure
    DWORD Flags;
    DWORD Type;
    FILETIME LastWritten;
    DWORD CredentialBlobSize;
    DWORD Persist;
    DWORD AttributeCount;
    DWORD Expansion1; // Reserved
    DWORD Expansion2; // Reserved
} MARSHALED_CREDENTIAL, *PMARSHALED_CREDENTIAL;

// Describes an encryptable credential set which is
typedef struct _MARSHALED_CREDENTIAL_SET {
    ULONG Version;
    ULONG Size; // Size in bytes of the entire cred set
    // MARSHALED_CREDENTIAL credSets[0]
} MARSHALED_CREDENTIAL_SET, *PMARSHALED_CREDENTIAL_SET;

#ifdef __cplusplus
} // Closes extern "C" above
namespace CredMan {
    // Enumerations
    using CredParsedUserNameType = _CredParsedUserNameType;
    using ENCODE_BLOB_ENUM = _ENCODE_BLOB_ENUM;
    using TARGET_ATTRIBUTE_TYPE = _TARGET_ATTRIBUTE_TYPE;
    using TARGET_NAME_TYPE = _TARGET_NAME_TYPE;
    using WILDCARD_TYPE = _WILDCARD_TYPE;
    using WTOA_ENUM = _WTOA_ENUM;

    using CANONICAL_CREDENTIAL = _CANONICAL_CREDENTIAL;
    using CANONICAL_TARGET_INFO = _CANONICAL_TARGET_INFO;
    using CRED_WRITE_UNDO = _CRED_WRITE_UNDO;
    using CREDENTIAL_SET = _CREDENTIAL_SET;
    using CREDENTIAL_SETS = _CREDENTIAL_SETS;
    using CREDENTIAL_TARGET_INFORMATIONW = _CREDENTIAL_TARGET_INFORMATIONW;
    using ENCRYPTED_CREDENTIALW = _ENCRYPTED_CREDENTIALW;
    using MARSHALED_CREDENTIAL = _MARSHALED_CREDENTIAL;
    using MARSHALED_CREDENTIAL_SET = _MARSHALED_CREDENTIAL_SET;
    using PROMPT_DATA = _PROMPT_DATA;
    using SESSION_CREDENTIAL_SETS = _SESSION_CREDENTIAL_SETS;
    using USER_CREDENTIAL_SETS = _USER_CREDENTIAL_SETS;
}
#endif