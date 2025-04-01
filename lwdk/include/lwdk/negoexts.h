// Copyright (C) 2024 Evan McBroom
//
// Negotiate extender (negoexts) which includes
// - Negoexts definitions
// - The Windows security type (wst) library
//
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

#include "um/ntsecpkg.h"
#include <sspi.h>

#define NEGOEX_NAME_A "NegoExtender"

#ifdef __cplusplus
extern "C" {
#endif

enum _NEGOEXTS_MESSAGE_TYPE;
enum _WST_CONTEXT_STATE;
enum _WST_MESSAGE_TYPE;
enum _WST_RESUME_STATE;
enum _WST_STATE;

struct _NEGOEXTS_PACKED_CONTEXT;
struct _NEGOEXTS_REG_PARAMETER;
struct _NEGOEXTS_UMODE_CONTEXT;
struct _NEGOTIATE_FLUSH_CONTEXT_REQUEST;
struct _NEGOTIATE_GET_CREDUI_CONTEXT_REQUEST;
struct _NEGOTIATE_GET_CREDUI_CONTEXT_RESPONSE;
struct _NEGOTIATE_LOOKUP_CONTEXT_REQUEST;
struct _NEGOTIATE_LOOKUP_CONTEXT_RESPONSE;
struct _NEGOTIATE_UPDATE_CREDENTIALS_REQUEST;
struct _WST_ACTIVE_ENGINE_CONTEXT;
struct _WST_ALERT;
struct _WST_ALERT_HEARTBEAT;
struct _WST_ALERT_MESSAGE;
struct _WST_ALERT_VECTOR;
struct _WST_AUTH_SCHEME_VECTOR;
struct _WST_BYTE_VECTOR;
struct _WST_CHECKSUM;
struct _WST_CONTEXT_BY_TARGET_TABLE_ENTRY;
struct _WST_CONTEXT_CREDENTIAL;
struct _WST_CONTEXT_SUPPLIED_CREDS;
struct _WST_CONTEXT_TABLE_ENTRY;
struct _WST_CONTEXT;
struct _WST_CRED_TABLE_ENTRY;
struct _WST_CREDENTIAL;
struct _WST_CREDUI_CONTEXT_ITEM;
struct _WST_CSPDATA_DETAIL;
struct _WST_ENCRYPTION_KEY;
struct _WST_EXCHANGE_MESSAGE;
struct _WST_EXTENSION_VECTOR;
struct _WST_EXTENSION;
struct _WST_HELLO_MESSAGE;
struct _WST_LIST_ENTRY;
struct _WST_LIST;
struct _WST_MESSAGE_HEADER;
struct _WST_MESSAGE;
struct _WST_PASSWORD_UNICODE_STRING;
struct _WST_SSP_PACKAGE;
struct _WST_VERIFY_MESSAGE;

typedef enum _NEGOEXTS_MESSAGE_TYPE {
    NegGetCredUIContext = 2,
    NegUpdateCredentials = 3,
    NegLookupContext = 4,
    NegFlushContext = 5,
} NEGOEXTS_MESSAGE_TYPE,
    *PNEGOEXTS_MESSAGE_TYPE;

/// <summary>
/// Members were given a prefix to prevent conflicting type names.
/// </summary>
typedef enum _WST_CONTEXT_STATE {
    WstIdleState = 0,
    WstHelloReceived = 1,
    WstHelloSentState = 2,
    WstExchangeSentState = 3,
    WstVerifySentState = 4,
    WstAuthenticatedState = 5,
    WstErrorMessageSentState = 6,
    WstInvalidState = 7,
} WST_CONTEXT_STATE,
    *PWST_CONTEXT_STATE;

typedef enum _WST_MESSAGE_TYPE {
    WST_MESSAGE_TYPE_CLIENT_HELLO = 0,
    WST_MESSAGE_TYPE_SERVER_HELLO = 1,
    WST_MESSAGE_TYPE_CLIENT_META_DATA = 2,
    WST_MESSAGE_TYPE_SERVER_META_DATA = 3,
    WST_MESSAGE_TYPE_CHALLENGE = 4,
    WST_MESSAGE_TYPE_AP_REQUEST = 5,
    WST_MESSAGE_TYPE_VERIFY = 6,
    WST_MESSAGE_TYPE_ALERT = 7,
} WST_MESSAGE_TYPE,
    *PWST_MESSAGE_TYPE;

typedef enum _WST_RESUME_STATE {
    ResumeIdleState = 0,
    ResumeProcessingInitialHello = 1,
    ResumeProcessingResponse = 2,
} WST_RESUME_STATE,
    *PWST_RESUME_STATE;

typedef enum _WST_STATE {
    WSTStateLsaMode = 1,
    WSTStateUserMode = 2,
} WST_STATE,
    *PWST_STATE;

// WST types which must be defined first due to their
// use in other type definitions.

typedef struct _WST_ALERT_VECTOR {
    ULONG AlertArrayOffset;
    USHORT AlertCount;
} WST_ALERT_VECTOR, *PWST_ALERT_VECTOR;

typedef struct _WST_BYTE_VECTOR {
    ULONG ByteArrayOffset;
    ULONG ByteArrayLength;
} WST_BYTE_VECTOR, *PWST_BYTE_VECTOR;

typedef struct _WST_CREDENTIAL {
    ULONGLONG Signature;
    LONG References;
    BOOL Linked;
    SECPKG_CREDENTIAL SecPkgCredential;
    SECPKG_SUPPLIED_CREDENTIAL SuppliedCreds;
} WST_CREDENTIAL, *PWST_CREDENTIAL;

typedef struct _WST_ENCRYPTION_KEY {
    LONG keytype;
    struct
    {
        ULONG length;
        PBYTE value;
    } keyvalue;
} WST_ENCRYPTION_KEY, *PWST_ENCRYPTION_KEY;

typedef struct _WST_LIST_ENTRY {
    LIST_ENTRY Next;
    ULONG ReferenceCount;
} WST_LIST_ENTRY, *PWST_LIST_ENTRY;

typedef struct _WST_MESSAGE_HEADER {
    ULONGLONG Signature;
    WST_MESSAGE_TYPE MessageType;
    ULONG SequenceNum;
    ULONG cbHeaderLength;
    ULONG cbMessageLength;
    GUID ConversationId;
} WST_MESSAGE_HEADER, *PWST_MESSAGE_HEADER;

// All remaining type definitions

typedef struct _NEGOEXTS_PACKED_CONTEXT {
    ULONG ContextType;
    ULONG Pad;
    ULONG PackageId;
    ULONG PackedPackageContextOffset;
    ULONG PackedPackageContextLength;
} NEGOEXTS_PACKED_CONTEXT, *PNEGOEXTS_PACKED_CONTEXT;

typedef struct _NEGOEXTS_REG_PARAMETER {
    LPWSTR Name;
    PULONG Address;
    ULONG DefaultValue;
    LONG ReverseSense;
    LONG GPEnabled;
} NEGOEXTS_REG_PARAMETER, *PNEGOEXTS_REG_PARAMETER;

typedef struct _NEGOEXTS_UMODE_CONTEXT {
    WST_LIST_ENTRY ListEntry;
    ULONGLONG Signature;
    HANDLE LsaContextHandle;
    ULONG PackageId;
    PSECPKG_USER_FUNCTION_TABLE PackageFunctionTable;
} NEGOEXTS_UMODE_CONTEXT, *PNEGOEXTS_UMODE_CONTEXT;

typedef struct _NEGOTIATE_FLUSH_CONTEXT_REQUEST {
    ULONG MessageType;
    USHORT cbHeaderLength;
    ULONGLONG ContextHandle;
} NEGOTIATE_FLUSH_CONTEXT_REQUEST, *PNEGOTIATE_FLUSH_CONTEXT_REQUEST;

typedef struct _NEGOTIATE_GET_CREDUI_CONTEXT_REQUEST {
    ULONG MessageType;
    USHORT cbHeaderLength; // sizeof(_NEGOTIATE_GET_CREDUI_CONTEXT_REQUEST)
    ULONGLONG ContextHandle;
    GUID CredType; // As specified by the SEC_WINNT_AUTH_DATA_TYPE_* macros
    LUID LogonId;
} NEGOTIATE_GET_CREDUI_CONTEXT_REQUEST, *PNEGOTIATE_GET_CREDUI_CONTEXT_REQUEST;

typedef struct _NEGOTIATE_GET_CREDUI_CONTEXT_RESPONSE {
    ULONG MessageType;
    USHORT cbHeaderLength;
    ULONG FlatCredUIContextLength;
    ULONG FlatCredUIContextOffset;
    HANDLE TokenHandle;
} NEGOTIATE_GET_CREDUI_CONTEXT_RESPONSE, *PNEGOTIATE_GET_CREDUI_CONTEXT_RESPONSE;

typedef struct _NEGOTIATE_LOOKUP_CONTEXT_REQUEST {
    ULONG MessageType;
    USHORT cbHeaderLength; // sizeof(_LOOKUP_CONTEXT_REQUEST)
    ULONG TargetNameOffset;
    USHORT TargetNameLengthInCharacters;
} NEGOTIATE_LOOKUP_CONTEXT_REQUEST, *PNEGOTIATE_LOOKUP_CONTEXT_REQUEST;

typedef struct _NEGOTIATE_LOOKUP_CONTEXT_RESPONSE {
    ULONG MessageType;
    USHORT cbHeaderLength;
    ULONGLONG ContextHandle;
} NEGOTIATE_LOOKUP_CONTEXT_RESPONSE, *PNEGOTIATE_LOOKUP_CONTEXT_RESPONSE;

typedef struct _NEGOTIATE_UPDATE_CREDENTIALS_REQUEST {
    ULONG MessageType;
    USHORT cbHeaderLength; // sizeof(_UPDATE_CREDENTIALS_REQUEST)
    ULONGLONG ContextHandle;
    GUID CredType; // As specified by the SEC_WINNT_AUTH_DATA_TYPE_* macros
    ULONG FlatCredUIContextLength;
    ULONG FlatCredUIContextOffset;
} NEGOTIATE_UPDATE_CREDENTIALS_REQUEST, *PNEGOTIATE_UPDATE_CREDENTIALS_REQUEST;

typedef struct _WST_ACTIVE_ENGINE_CONTEXT {
    LIST_ENTRY ListEntry;
    ULONGLONG Signature;
    GUID AuthScheme;
    HANDLE ContextHandle;
    HANDLE CredHandle;
    SecBuffer ContextData;
    BOOL VerifySent;
    BOOL VerifyReceived;
    ULONG PackageFlags;
    BOOL IsAuthenticated;
    WST_ENCRYPTION_KEY SessionKey;
    WST_ENCRYPTION_KEY OldSessionKey;
    BOOL IsPromptingNeeded;
    SECPKG_CRED_CLASS CredClass;
} WST_ACTIVE_ENGINE_CONTEXT, *PWST_ACTIVE_ENGINE_CONTEXT;

typedef struct _WST_BYTE_VECTOR WST_BYTE_VECTOR;
typedef struct _WST_ALERT {
    ULONG AlertType;
    WST_BYTE_VECTOR AlertValue;
} WST_ALERT, *PWST_ALERT;

typedef struct _WST_ALERT_HEARTBEAT {
    ULONG cbHeaderLength;
    ULONG Reason;
} WST_ALERT_HEARTBEAT, *PWST_ALERT_HEARTBEAT;

typedef struct _WST_ALERT_MESSAGE {
    WST_MESSAGE_HEADER Header;
    GUID AuthScheme;
    ULONG ErrorCode;
    WST_ALERT_VECTOR Alerts;
} WST_ALERT_MESSAGE, *PWST_ALERT_MESSAGE;

typedef struct _WST_AUTH_SCHEME_VECTOR {
    ULONG AuthSchemeArrayOffset;
    USHORT AuthSchemeCount;
} WST_AUTH_SCHEME_VECTOR, *PWST_AUTH_SCHEME_VECTOR;

typedef struct _WST_CHECKSUM {
    ULONG cbHeaderLength;
    ULONG ChecksumScheme;
    ULONG ChecksumType;
    WST_BYTE_VECTOR ChecksumValue;
} WST_CHECKSUM, *PWST_CHECKSUM;

typedef struct _WST_CONTEXT* PWST_CONTEXT;
typedef struct _WST_CONTEXT_BY_TARGET_TABLE_ENTRY {
    PWST_CONTEXT TableEntryContext;
    TimeStamp Expiration;
} WST_CONTEXT_BY_TARGET_TABLE_ENTRY, *PWST_CONTEXT_BY_TARGET_TABLE_ENTRY;

typedef struct _WST_CREDENTIAL* PWST_CREDENTIAL;
typedef struct _WST_CONTEXT_CREDENTIAL {
    LIST_ENTRY ListEntry;
    PWST_CREDENTIAL ContextCredential;
} WST_CONTEXT_CREDENTIAL, *PWST_CONTEXT_CREDENTIAL;

typedef struct _WST_CONTEXT_SUPPLIED_CREDS {
    USHORT cbHeaderLength;
    UNICODE_STRING UserName;
    UNICODE_STRING DomainName;
    USHORT PackedCredentialsLength;
    PBYTE PackedCredentials;
    ULONG CredFlags;
} WST_CONTEXT_SUPPLIED_CREDS, *PWST_CONTEXT_SUPPLIED_CREDS;

typedef struct _WST_CONTEXT_TABLE_ENTRY {
    PWST_CONTEXT Context;
    TimeStamp Expiration;
} WST_CONTEXT_TABLE_ENTRY, *PWST_CONTEXT_TABLE_ENTRY;

typedef struct _WST_CONTEXT {
    ULONGLONG Signature;
    LONG CallCount;
    LONG RefCount;
    LONG Linked;
    PWST_CREDENTIAL Credential;
    GUID ConversationId;
    WST_CONTEXT_STATE ContextState;
    ULONG ContextAttributes;
    LIST_ENTRY ActiveContexts;
    LIST_ENTRY MessageHistory;
    LIST_ENTRY MessagesToSend;
    LIST_ENTRY MessagesReceived;
    LIST_ENTRY OldCredentials;
    BOOL IsInitiator;
    ULONG SequenceNum;
    PGUID CommonAuthSchemes;
    USHORT CommonAuthSchemeCount;
    BOOL IsClient;
    BOOL HelloDone;
    UNICODE_STRING TargetName;
    UNICODE_STRING TargetHost;
    UNICODE_STRING TargetInfoHost;
    ULONG fContextReq;
    ULONG LastStatus;
    BOOL AuthSchemeSelected;
    GUID ContextAuthScheme;
    BOOL AuthSchemeFinal;
    WST_RESUME_STATE ResumeState;
    ULONG HelloMessageSeqNum;
    BOOL CredentialsUpdated;
    ULONG PackageMask;
    BOOL ContextInserted;
    BOOL ExplicitCredentials;
    SECPKG_CRED_CLASS HighestCredClass;
} WST_CONTEXT, *PWST_CONTEXT;

typedef struct _WST_CRED_TABLE_ENTRY {
    PWST_CREDENTIAL Credential;
    LONG HandleCount;
    WST_CREDENTIAL ShadowCopy;
} WST_CRED_TABLE_ENTRY, *PWST_CRED_TABLE_ENTRY;

typedef struct _WST_CREDUI_CONTEXT_ITEM {
    LIST_ENTRY ListEntry;
    ULONG CredUIContextLength;
    PBYTE CredUIContext;
} WST_CREDUI_CONTEXT_ITEM, *PWST_CREDUI_CONTEXT_ITEM;

typedef struct _WST_CSPDATA_DETAIL {
    ULONG KeySpec;
    UNICODE_STRING CardName;
    UNICODE_STRING ReaderName;
    UNICODE_STRING ContainerName;
    UNICODE_STRING CspName;
} WST_CSPDATA_DETAIL, *PWST_CSPDATA_DETAIL;

typedef struct _WST_EXCHANGE_MESSAGE {
    WST_MESSAGE_HEADER Header;
    GUID AuthScheme;
    WST_BYTE_VECTOR Exchange;
} WST_EXCHANGE_MESSAGE, *PWST_EXCHANGE_MESSAGE;

typedef struct _WST_EXTENSION_VECTOR {
    ULONG ExtensionArrayOffset;
    USHORT ExtensionCount;
} WST_EXTENSION_VECTOR, *PWST_EXTENSION_VECTOR;

typedef struct _WST_EXTENSION {
    ULONG ExtensionType;
    WST_BYTE_VECTOR ExtensionValue;
} WST_EXTENSION, *PWST_EXTENSION;

typedef struct _WST_HELLO_MESSAGE {
    WST_MESSAGE_HEADER Header;
    BYTE Random[32];
    ULONGLONG ProtocolVersion;
    WST_AUTH_SCHEME_VECTOR AuthSchemes;
    WST_EXTENSION_VECTOR Extensions;
} WST_HELLO_MESSAGE, *PWST_HELLO_MESSAGE;

typedef struct _WST_LIST {
    LIST_ENTRY List;
    RTL_CRITICAL_SECTION Lock;
} WST_LIST, *PWST_LIST;

typedef struct _WST_MESSAGE {
    LIST_ENTRY ListEntry;
    ULONGLONG Signature;
    PBYTE Message;
    ULONG MessageSize;
} WST_MESSAGE, *PWST_MESSAGE;

typedef struct _WST_PASSWORD_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    LPWSTR Buffer;
} WST_PASSWORD_UNICODE_STRING, *PWST_PASSWORD_UNICODE_STRING;

typedef struct _WST_SSP_PACKAGE {
    LIST_ENTRY ListEntry;
    ULONGLONG Signature;
    ULONG dwPackageID;
    LONG RefCount;
    SECPKG_FUNCTION_TABLE EngineTable;
    UNICODE_STRING PackageName;
    GUID AuthScheme;
    ULONG Flags;
    ULONG LsaCapabilities;
} WST_SSP_PACKAGE, *PWST_SSP_PACKAGE;

typedef struct _WST_VERIFY_MESSAGE {
    WST_MESSAGE_HEADER Header;
    GUID AuthScheme;
    WST_CHECKSUM Checksum;
} WST_VERIFY_MESSAGE, *PWST_VERIFY_MESSAGE;

#ifdef __cplusplus
} // Closes extern "C" above
namespace NegoExts {
    // Enumerations
    using MESSAGE_TYPE = _NEGOEXTS_MESSAGE_TYPE;

    using FLUSH_CONTEXT_REQUEST = _NEGOTIATE_FLUSH_CONTEXT_REQUEST;
    using GET_CREDUI_CONTEXT_REQUEST = _NEGOTIATE_GET_CREDUI_CONTEXT_REQUEST;
    using GET_CREDUI_CONTEXT_RESPONSE = _NEGOTIATE_GET_CREDUI_CONTEXT_RESPONSE;
    using LOOKUP_CONTEXT_REQUEST = _NEGOTIATE_LOOKUP_CONTEXT_REQUEST;
    using LOOKUP_CONTEXT_RESPONSE = _NEGOTIATE_LOOKUP_CONTEXT_RESPONSE;
    using PACKED_CONTEXT = _NEGOEXTS_PACKED_CONTEXT;
    using REG_PARAMETER = _NEGOEXTS_REG_PARAMETER;
    using UMODE_CONTEXT = _NEGOEXTS_UMODE_CONTEXT;
    using UPDATE_CREDENTIALS_REQUEST = _NEGOTIATE_UPDATE_CREDENTIALS_REQUEST;
}

/// <summary>
/// Windows security type library.
/// </summary>
namespace Wst {
    // Enumerations
    using CONTEXT_STATE = _WST_CONTEXT_STATE;
    using MESSAGE_TYPE = _WST_MESSAGE_TYPE;
    using RESUME_STATE = _WST_RESUME_STATE;
    using STATE = _WST_STATE;

    using ACTIVE_ENGINE_CONTEXT = _WST_ACTIVE_ENGINE_CONTEXT;
    using ALERT = _WST_ALERT;
    using ALERT_HEARTBEAT = _WST_ALERT_HEARTBEAT;
    using ALERT_MESSAGE = _WST_ALERT_MESSAGE;
    using ALERT_VECTOR = _WST_ALERT_VECTOR;
    using AUTH_SCHEME_VECTOR = _WST_AUTH_SCHEME_VECTOR;
    using BYTE_VECTOR = _WST_BYTE_VECTOR;
    using CHECKSUM = _WST_CHECKSUM;
    using CONTEXT = _WST_CONTEXT;
    using CONTEXT_BY_TARGET_TABLE_ENTRY = _WST_CONTEXT_BY_TARGET_TABLE_ENTRY;
    using CONTEXT_CREDENTIAL = _WST_CONTEXT_CREDENTIAL;
    using CONTEXT_SUPPLIED_CREDS = _WST_CONTEXT_SUPPLIED_CREDS;
    using CONTEXT_TABLE_ENTRY = _WST_CONTEXT_TABLE_ENTRY;
    using CRED_TABLE_ENTRY = _WST_CRED_TABLE_ENTRY;
    using CREDENTIAL = _WST_CREDENTIAL;
    using CREDUI_CONTEXT_ITEM = _WST_CREDUI_CONTEXT_ITEM;
    using CSPDATA_DETAIL = _WST_CSPDATA_DETAIL;
    using ENCRYPTION_KEY = _WST_ENCRYPTION_KEY;
    using EXCHANGE_MESSAGE = _WST_EXCHANGE_MESSAGE;
    using EXTENSION = _WST_EXTENSION;
    using EXTENSION_VECTOR = _WST_EXTENSION_VECTOR;
    using HELLO_MESSAGE = _WST_HELLO_MESSAGE;
    using LIST = _WST_LIST;
    using LIST_ENTRY = _WST_LIST_ENTRY;
    using MESSAGE = _WST_MESSAGE;
    using MESSAGE_HEADER = _WST_MESSAGE_HEADER;
    using PASSWORD_UNICODE_STRING = _WST_PASSWORD_UNICODE_STRING;
    using SSP_PACKAGE = _WST_SSP_PACKAGE;
    using VERIFY_MESSAGE = _WST_VERIFY_MESSAGE;
}
#endif