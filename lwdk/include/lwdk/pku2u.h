// Copyright (C) 2024 Evan McBroom
//
// Public key user 2 user (pku2u)
//
#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include "kerberos.h"
#include "krb5.h"
#include <wincrypt.h>
#define SECURITY_WIN32
#include "um/ntsecapi.h"

#define PKU2U_NAME_A "pku2u"

#ifdef __cplusplus
extern "C" {
#endif

enum _PKU2U_CONTEXT_STATE;
enum _PKU2U_CRED_TYPE;

struct _PKU2U_ASSOCIATED_CREDENTIAL;
struct _PKU2U_CONTEXT;
struct _PKU2U_CRED_TABLE_ENTRY;
struct _PKU2U_FLAG_MAPPING;
struct _PKU2U_LOGON_SESSION_TABLE_ENTRY;
struct _PKU2U_LOGON_SESSION;
struct _PKU2U_LOOP_BACK;
struct _PKU2U_PRIMARY_CREDENTIAL;
struct _PKU2U_REG_PARAMETER;
struct _PKU2U_SECONDARY_CREDENTIAL;
struct _PKU2U_SSPI_MESSAGE;
struct _PKU2U_TICKET_CACHE_ENTRY;
struct _PKU2U_TICKET_CACHE;

typedef enum _PKU2U_CONTEXT_STATE {
    PKU2U_CONTEXT_STATE_IDLE = 0,
    PKU2U_CONTEXT_STATE_CLIENT_AS_REQ_SENT = 1,
    PKU2U_CONTEXT_STATE_SERVER_AS_REP_SENT = 2,
    PKU2U_CONTEXT_STATE_CLIENT_AP_REQ_SENT = 3,
    PKU2U_CONTEXT_STATE_SERVER_AP_REP_SENT = 4,
    PKU2U_CONTEXT_STATE_SERVER_ERROR_SENT = 5,
    PKU2U_CONTEXT_STATE_AUTHENTICATED = 6,
    PKU2U_CONTEXT_STATE_ABORTED = 7,
} PKU2U_CONTEXT_STATE,
    *PPKU2U_CONTEXT_STATE;

typedef enum _PKU2U_CRED_TYPE {
    PKU2UCredTypeSuppliedCred = 0,
    PKU2UCredTypeLogonSession = 1,
} PKU2U_CRED_TYPE,
    *PPKU2U_CRED_TYPE;


typedef struct _PKU2U_TICKET_CACHE {
    LIST_ENTRY CacheEntries;
    TimeStamp LastCleanup;
} PKU2U_TICKET_CACHE, *PPKU2U_TICKET_CACHE;

typedef struct _PKU2U_PRIMARY_CREDENTIAL {
    RTL_CRITICAL_SECTION CredLock;
    BOOL IsCredLockInitialized;
    UNICODE_STRING UserName;
    UNICODE_STRING ProvName;
    GUID ProvGuid;
    PKU2U_TICKET_CACHE ServerTicketCache;
    PCERT_CONTEXT CertContext;
    CERT_CHAIN_CONTEXT* CertChain;
    ULONG Peer2PeerKeyCount;
    PKERB_ENCRYPTION_KEY Peer2PeerKeys;
} PKU2U_PRIMARY_CREDENTIAL, *PPKU2U_PRIMARY_CREDENTIAL;

typedef struct _PKU2U_ASSOCIATED_CREDENTIAL {
    LIST_ENTRY ListEntry;
    ULONGLONG Signature;
    LONG RefCount;
    LUID LogonId;
    PKU2U_PRIMARY_CREDENTIAL PrimaryCredential;
} PKU2U_ASSOCIATED_CREDENTIAL, *PPKU2U_ASSOCIATED_CREDENTIAL;

typedef struct _PKU2U_TICKET_CACHE_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    BOOL Linked;
    PKERB_INTERNAL_NAME ServiceName;
    PKERB_INTERNAL_NAME ClientName;
    ULONG TicketFlags;
    KERB_ENCRYPTION_KEY SessionKey;
    TimeStamp StartTime;
    TimeStamp EndTime;
    TimeStamp RenewUntil;
    KERB_TICKET Ticket;
    LONG TimeShift;
} PKU2U_TICKET_CACHE_ENTRY, *PPKU2U_TICKET_CACHE_ENTRY;

typedef struct _PKU2U_SECONDARY_CREDENTIAL {
    ULONGLONG Signature;
    LONG References;
    BOOL Linked;
    LPVOID CredentialKey;
    PSECPKG_CREDENTIAL SecPkgCredential;
    PKU2U_CRED_TYPE CredType;
    union {
        LUID LogonID;
        PKU2U_PRIMARY_CREDENTIAL PrimaryCredential;
    };
} PKU2U_SECONDARY_CREDENTIAL, *PPKU2U_SECONDARY_CREDENTIAL;

typedef struct _PKU2U_CONTEXT {
    ULONGLONG Signature;
    LONG RefCount;
    PPKU2U_SECONDARY_CREDENTIAL ContextCredential;
    PPKU2U_SECONDARY_CREDENTIAL CredmanCredential;
    PPKU2U_ASSOCIATED_CREDENTIAL AssociatedCredential;
    ULONG ContextFlags;
    TimeStamp ExpirationTime;
    BOOL IsClient;
    ULONG fContextReq;
    ULONG ContextAttr;
    PKU2U_CONTEXT_STATE Pku2uContextState;
    LONG LastStatus;
    PKERB_INTERNAL_NAME TargetInternalName;
    UNICODE_STRING TargetName;
    UNICODE_STRING InputTargetName;
    HANDLE hDhKey;
    BYTE ClientDHNonce[32];
    TimeStamp TimeSkew;
    ULONG AsRequestNonce;
    ULONG ContextRetries;
    PPKU2U_TICKET_CACHE_ENTRY TicketCacheEntry;
    UNICODE_STRING ClientName;
    KERB_ENCRYPTION_KEY OldSessionKey;
    KERB_ENCRYPTION_KEY SessionKey;
    KERB_ENCRYPTION_KEY TicketKey;
    HANDLE TokenHandle;
    TimeStamp AuthenticatorTime;
    ULONGLONG Nonce;
    ULONGLONG ReceiveNonce;
    LIST_ENTRY SSPIMessages;
    LONG CallCount;
    UNICODE_STRING WorkstationName;
    PSID UserSid;
    LUID LogonId;
    BOOL IsPromptingNeeded;
    const PCERT_CHAIN_CONTEXT CertChainContext;
    PBYTE pMarshalledTargetInfo;
    ULONG cbMarshalledTargetInfo;
    SECPKG_CRED_CLASS CredmanCredClass;
    BOOL bCredmanQueried;
} PKU2U_CONTEXT, *PPKU2U_CONTEXT;

typedef struct _PKU2U_CRED_TABLE_ENTRY {
    PPKU2U_SECONDARY_CREDENTIAL TableEntryCredential;
    LONG HandleCount;
} PKU2U_CRED_TABLE_ENTRY, *PPKU2U_CRED_TABLE_ENTRY;

typedef struct _PKU2U_FLAG_MAPPING {
    LONG InitFlag;
    LONG AcceptFlag;
} PKU2U_FLAG_MAPPING, *PPKU2U_FLAG_MAPPING;

typedef struct _PKU2U_LOGON_SESSION {
    ULONGLONG Signature;
    LONG References;
    LUID LogonId;
    LIST_ENTRY AssociatedCredentials;
    RTL_CRITICAL_SECTION LogonSessionLock;
    HANDLE NotificationItemHandle;
} PKU2U_LOGON_SESSION, *PPKU2U_LOGON_SESSION;

typedef struct _PKU2U_LOGON_SESSION_TABLE_ENTRY {
    PPKU2U_LOGON_SESSION TableEntryLogonSession;
} PKU2U_LOGON_SESSION_TABLE_ENTRY, *PPKU2U_LOGON_SESSION_TABLE_ENTRY;

typedef struct _PKU2U_LOOP_BACK {
    PPKU2U_SECONDARY_CREDENTIAL Credential;
    ULONGLONG TickCount;
} PKU2U_LOOP_BACK, *PPKU2U_LOOP_BACK;

typedef struct _PKU2U_REG_PARAMETER {
    LPWSTR Name;
    PULONG Address;
    ULONG DefaultValue;
    BOOL ReverseSense;
    BOOL GPEnabled;
} PKU2U_REG_PARAMETER, *PPKU2U_REG_PARAMETER;

typedef struct _PKU2U_SSPI_MESSAGE {
    LIST_ENTRY ListEntry;
    ULONGLONG Signature;
    PBYTE Message;
    ULONG MessageSize;
} PKU2U_SSPI_MESSAGE, *PPKU2U_SSPI_MESSAGE;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Pku2u {
    // Enumerations
    using CONTEXT_STATE = _PKU2U_CONTEXT_STATE;
    using CRED_TYPE = _PKU2U_CRED_TYPE;

    using ASSOCIATED_CREDENTIAL = _PKU2U_ASSOCIATED_CREDENTIAL;
    using CERT_BLOB = _PKU2U_CERT_BLOB;
    using CERTIFICATE_S4U_LOGON = _PKU2U_CERTIFICATE_S4U_LOGON;
    using CONTEXT = _PKU2U_CONTEXT;
    using CRED_TABLE_ENTRY = _PKU2U_CRED_TABLE_ENTRY;
    using CREDUI_CONTEXT = PKU2U_CREDUI_CONTEXT;
    using FLAG_MAPPING = _PKU2U_FLAG_MAPPING;
    using LOGON_SESSION = _PKU2U_LOGON_SESSION;
    using LOGON_SESSION_TABLE_ENTRY = _PKU2U_LOGON_SESSION_TABLE_ENTRY;
    using LOGON_SUBMIT_TYPE = PKU2U_LOGON_SUBMIT_TYPE;
    using LOOP_BACK = _PKU2U_LOOP_BACK;
    using PRIMARY_CREDENTIAL = _PKU2U_PRIMARY_CREDENTIAL;
    using REG_PARAMETER = _PKU2U_REG_PARAMETER;
    using SECONDARY_CREDENTIAL = _PKU2U_SECONDARY_CREDENTIAL;
    using SSPI_MESSAGE = _PKU2U_SSPI_MESSAGE;
    using TICKET_CACHE = _PKU2U_TICKET_CACHE;
    using TICKET_CACHE_ENTRY = _PKU2U_TICKET_CACHE_ENTRY;
}
#endif