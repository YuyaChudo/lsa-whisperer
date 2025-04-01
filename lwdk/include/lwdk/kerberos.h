// Copyright (C) 2024 Evan McBroom
//
// Kerberos
//
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>

#include <wincred.h>
#define SECURITY_WIN32
#include "um/ntsecpkg.h"
#include "um/ntsecapi.h"
// clang-format on

// Included because it defines the DS_*_FLAG values that populate
// KERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE.DsFlags
#include <dsgetdc.h>

#include "crypt.h"
#include "krb5.h"
#include "lsa.h"
#include "native.h"
#include "netlogon.h"
#include <evntrace.h>
#include <sspi.h>
#include <wincrypt.h>
#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

enum KERB_REG_TELEMETRY_FLAG;
enum _STANDALONE_KDC_VALIDATION_LEVEL;
enum _KERBEROS_STATE;
enum _KERBEROS_MACHINE_ROLE;
enum _KERB_SMARTCARD_CSP_INFO_TYPE;
enum _KERB_PLAINTEXT_PASSWORD_PROTECTION;
enum _KERB_ODJ_STATE;
enum _KERB_KDC_TYPE;
enum _KERB_DEVICE_PKINIT_BEHAVIOR;
enum _KERB_CONTEXT_STATE;
enum _KERB_ACCOUNT_TYPE;
enum _KDC_VALIDATION_LEVEL;

union _KERB_PLAINTEXT_PASSWORD_STORAGE;

struct _EXTRA_CRED_LIST;
struct _HOST_TO_REALM_KEY;
struct _KDC_PROXY_CACHE;
struct _KDC_PROXY_CACHE_ENTRY;
struct _KERB_ACCEPTSC_INFO;
struct _KERB_ADD_CREDENTIALS_REQUEST;
struct _KERB_ADD_CREDENTIALS_REQUEST_EX;
struct _KERB_ASN1_DATA;
struct _KERB_AUTH_PROXY;
struct _KERB_AUTH_PROXY_CRED;
struct _KERB_AUTHEN_HEADER;
struct _KERB_BINDING_CACHE_ENTRY;
struct _KERB_CHANGE_MACH_PWD_REQUEST;
struct _KERB_CHANGE_PASSWORD_KDC_RESPONSE_HEADER;
struct _KERB_CHANGE_PASSWORD_RESTRICTIONS_RESPONSE;
struct _KERB_CHANGEPASS_INFO;
struct _KERB_CONTEXT;
struct _KERB_CREDENTIAL;
struct _KERB_CREDMAN_CRED;
struct _KERB_CRYPTO_KEY_WOW64;
struct _KERB_DEBUG_REPLY;
struct _KERB_DEBUG_REQUEST;
struct _KERB_DEBUG_STATS;
struct _KERB_DH_DOMAIN_PARAMETERS;
struct _KERB_DNS_SUFFIX_COMPONENT;
struct _KERB_DNS_SUFFIX_TABLE;
struct _KERB_DOMAIN_CACHE;
struct _KERB_DOMAIN_CACHE_ENTRY;
struct _KERB_ECC_CURVE_INFO;
struct _KERB_ENCRYPTION_KEY;
struct _KERB_ENCRYPTION_KEY32;
struct _KERB_EXTRA_CRED;
struct _KERB_FLAG_MAPPING;
struct _KERB_FSO_BINDING_HANDLE;
struct _KERB_FSO_CACHE_ENTRY;
struct _KERB_FSO_COMMON_FUNCTION_TABLE;
struct _KERB_GSS_CHECKSUM;
struct _KERB_GSS_SEAL_SIGNATURE;
struct _KERB_GSS_SEAL_SIGNATURE_NEW;
struct _KERB_GSS_SIGNATURE;
struct _KERB_GSS_SIGNATURE_HEADER;
struct _KERB_GSS_SIGNATURE_NEW;
struct _KERB_INIT_CONTEXT_DATA;
struct _KERB_INITSC_INFO;
struct _KERB_INTERNAL_NAME;
struct _KERB_KDC_CALL_INFO;
struct _KERB_KDC_PROXY;
struct _KERBEROS_LIST;
struct _KERBEROS_LIST_ENTRY;
struct _KERBEROS_LIST2;
struct _KERB_KEY_AND_CRED;
struct _KERB_KEY_DATA;
struct _KERB_KEY_DATA_OLD;
struct _KERB_KEY_DATA32;
struct _KERB_KEY_DATA32_OLD;
struct _KERB_KPASSWD_REP;
struct _KERB_KPASSWD_REQ;
struct _KERB_LOGON_INFO;
struct _KERB_LOGON_SESSION;
struct _KERB_LOGON_SESSION_TABLE_ENTRY;
struct _KERB_LOOP_BACK;
struct _KERB_MESSAGE_BUFFER;
struct _KERB_MIT_REALM;
struct _KERB_MIT_SERVER_LIST;
struct _KERB_PACKED_CONTEXT;
struct _KERB_PARSED_DNS_SUFFIX;
struct _KERB_PIN_KDC_ENTRY;
struct _KERB_PLAINTEXT_PASSWORD;
struct _KERB_PREAUTH_DATA;
struct _KERB_PRIMARY_CREDENTIAL;
struct _KERB_PROCESS_TABLE_ENTRY;
struct _KERB_PROXY_LOGON_CRED;
struct _KERB_PROXY_SERVER;
struct _KERB_PROXY_SERVER_LIST;
struct _KERB_PUBLIC_KEY_CREDENTIALS;
struct _KERB_QUERY_SUPPLEMENTAL_CREDS_REQUEST;
struct _KERB_QUERY_SUPPLEMENTAL_CREDS_RESPONSE;
struct _KERB_REG_PARAMETER;
struct _KERB_REPLAY_AUDIT_INFO;
struct _KERB_RPC_CRYPT_BIT_BLOB;
struct _KERB_RPC_CRYPTO_API_BLOB;
struct _KERB_RPC_FAST_ARMOR;
struct _KERB_RPC_INTERNAL_NAME;
struct _KERB_RPC_OCTET_STRING;
struct _KERB_RPC_PA_DATA;
struct _KERB_S4U2PROXY_CACHE;
struct _KERB_S4U2PROXY_CACHE_ENTRY;
struct _KERB_SESSION_KEY_ENTRY;
struct _KERB_SETPASS_INFO;
struct _KERB_SMARTCARD_CSP_INFO;
struct _KERB_SPN_CACHE_ENTRY;
struct _KERB_STORED_CREDENTIAL;
struct _KERB_STORED_CREDENTIAL_OLD;
struct _KERB_STORED_CREDENTIAL32;
struct _KERB_STORED_CREDENTIAL32_OLD;
struct _KERB_SUPPLEMENTAL_CREDENTIAL;
struct _KERB_TICKET_CACHE;
struct _KERB_TICKET_CACHE_ENTRY;
struct _KERB_TICKET_LOGON_SUPP_CRED;
struct _KERB_TIME_SKEW_ENTRY;
struct _KERB_TIME_SKEW_STATE;
struct _KERB_UPDATE_ADDRESSES_REQUEST;
struct _KERB_VERIFY_CREDENTIALS_REQUEST;
struct _KERB_VERIFY_PAC_REQUEST;
struct _SPN_CACHE_RESULT;

#ifdef __cplusplus
// Only defined to allow other types to reference a pointer to the class.
class KerbCredIsoApi;
typedef KerbCredIsoApi* PKerbCredIsoApi;
#endif

typedef ULONG KERB_NULL_SIGNATURE, *PKERB_NULL_SIGNATURE;

typedef enum KERB_REG_TELEMETRY_FLAG {
    NO_TELEMETRY = 0,
    RECORD_TELEMETRY = 1,
} KERB_REG_TELEMETRY_FLAG;

typedef enum _KDC_VALIDATION_LEVEL {
    KERB_KDC_VALIDATION_OFF = 0,
    KERB_KDC_VALIDATION_NT_AUTH = 1,
    KERB_KDC_VALIDATION_MATCH_REALM_NAME_AND_REQUIRE_EKU = 2,
} KDC_VALIDATION_LEVEL,
    *PKDC_VALIDATION_LEVEL;

typedef enum _KERB_ACCOUNT_TYPE {
    UserAccount = 0,
    MachineAccount = 1,
    DomainTrustAccount = 2,
    UnknownAccount = 3,
} KERB_ACCOUNT_TYPE,
    *PKERB_ACCOUNT_TYPE;

/// <summary>
/// Members were given a prefix to prevent conflicting type names.
/// </summary>
typedef enum _KERB_CONTEXT_STATE {
    KerbIdleState = 0,
    KerbTgtRequestSentState = 1,
    KerbTgtReplySentState = 2,
    KerbApRequestSentState = 3,
    KerbApReplySentState = 4,
    KerbAuthenticatedState = 5,
    KerbErrorMessageSentState = 6,
    KerbInvalidState = 7,
} KERB_CONTEXT_STATE,
    *PKERB_CONTEXT_STATE;

typedef enum _KERB_DEVICE_PKINIT_BEHAVIOR {
    KERB_DEVICE_PKINIT_AUTOMATIC = 0,
    KERB_DEVICE_PKINIT_FORCE = 1,
} KERB_DEVICE_PKINIT_BEHAVIOR,
    *PKERB_DEVICE_PKINIT_BEHAVIOR;

typedef enum _KERB_KDC_TYPE {
    KdcAny = 0,
    KdcOnPDC = 1,
    KdcOnHub = 2,
    KdcOnRodcOrHub = 3,
} KERB_KDC_TYPE,
    *PKERB_KDC_TYPE;

typedef enum _KERB_ODJ_STATE {
    KerbODJUnknown = 0,
    KerbODJInit = 1,
    KerbODJPending = 2,
} KERB_ODJ_STATE,
    *PKERB_ODJ_STATE;

typedef enum _KERB_PLAINTEXT_PASSWORD_PROTECTION {
    KERB_PASSWORD_NO_PROTECTION = 0,
    KERB_PASSWORD_ENCRYPTED_BY_LSA_ISO = 1,
    KERB_PASSWORD_LSA_PROTECTED = 2,
} KERB_PLAINTEXT_PASSWORD_PROTECTION,
    *PKERB_PLAINTEXT_PASSWORD_PROTECTION;

typedef enum _KERB_SMARTCARD_CSP_INFO_TYPE {
    LogonInfo2 = 1,
    KERB_SMARTCARD_CSP_INFO_MAX_TYPE = 10,
} KERB_SMARTCARD_CSP_INFO_TYPE,
    *PKERB_SMARTCARD_CSP_INFO_TYPE;

typedef enum _KERBEROS_MACHINE_ROLE {
    KerbRoleRealmlessWksta = 0,
    KerbRoleStandalone = 1,
    KerbRoleWorkstation = 2,
    KerbRoleDomainController = 3,
} KERBEROS_MACHINE_ROLE,
    *PKERBEROS_MACHINE_ROLE;

typedef enum _KERBEROS_STATE {
    KerberosLsaMode = 1,
    KerberosUserMode = 2,
} KERBEROS_STATE,
    *PKERBEROS_STATE;

typedef enum _STANDALONE_KDC_VALIDATION_LEVEL {
    KERB_STANDALONE_KDC_VALIDATION_OFF = 0,
    KERB_STANDALONE_KDC_VALIDATION_MATCH_REALM_NAME_AND_REQUIRE_EKU = 1,
} STANDALONE_KDC_VALIDATION_LEVEL,
    *PSTANDALONE_KDC_VALIDATION_LEVEL;

typedef struct _KERB_RPC_OCTET_STRING {
    ULONG length;
    PBYTE value;
} KERB_RPC_OCTET_STRING, *PKERB_RPC_OCTET_STRING;

typedef union _KERB_PLAINTEXT_PASSWORD_STORAGE {
    KERB_RPC_OCTET_STRING EncryptedData;
    UNICODE_STRING Text;
} KERB_PLAINTEXT_PASSWORD_STORAGE, *PKERB_PLAINTEXT_PASSWORD_STORAGE;

typedef struct _KERBEROS_LIST {
    LIST_ENTRY List;
    RTL_CRITICAL_SECTION Lock;
} KERBEROS_LIST, *PKERBEROS_LIST;

typedef struct _EXTRA_CRED_LIST {
    KERBEROS_LIST CredList;
    ULONG Count;
} EXTRA_CRED_LIST, *PEXTRA_CRED_LIST;

typedef struct _HOST_TO_REALM_KEY {
    UNICODE_STRING SpnSuffix;
    UNICODE_STRING TargetRealm;
#pragma warning(disable : 4200)
    WCHAR NameBuffer[];
#pragma warning(default : 4200)
} HOST_TO_REALM_KEY, *PHOST_TO_REALM_KEY;

typedef struct _KDC_PROXY_CACHE {
    UCHAR Initialized;
    UCHAR GlobalCache;
    KERBEROS_LIST CacheEntries;
} KDC_PROXY_CACHE, *PKDC_PROXY_CACHE;

typedef struct _KERBEROS_LIST_ENTRY {
    LIST_ENTRY Next;
    ULONG ReferenceCount;
} KERBEROS_LIST_ENTRY, *PKERBEROS_LIST_ENTRY;

typedef struct _KERB_PROXY_SERVER {
    UNICODE_STRING ServerName;
    USHORT ServerPort;
    UNICODE_STRING ServerVdir;
} KERB_PROXY_SERVER, *PKERB_PROXY_SERVER;

typedef struct _KERB_AUTH_PROXY_CRED {
    UCHAR Initialized;
    ULONG Epoch;
    UNICODE_STRING DomainAndUserName;
    UNICODE_STRING Password;
} KERB_AUTH_PROXY_CRED, *PKERB_AUTH_PROXY_CRED;

typedef struct _KERB_AUTH_PROXY {
    UNICODE_STRING Proxy;
    UNICODE_STRING ProxyBypass;
    ULONG ProxyEpoch;
    KERB_AUTH_PROXY_CRED AuthProxyCreds[2];
} KERB_AUTH_PROXY, *PKERB_AUTH_PROXY;

typedef struct _KDC_PROXY_CACHE_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    TimeStamp LastUsedTime;
    UNICODE_STRING DomainName;
    KERB_PROXY_SERVER ProxyServer;
    KERB_AUTH_PROXY AuthProxy;
    HANDLE SessionHandle;
    HANDLE ConnectHandle;
    CERT_CONTEXT CertContext;
    LUID LogonId;
} KDC_PROXY_CACHE_ENTRY, *PKDC_PROXY_CACHE_ENTRY;

typedef struct _KERB_ACCEPTSC_INFO {
    // Start {No Data}, End {Status, CredSource, DomainName, UserName, Target}
    EVENT_TRACE_HEADER EventTrace;
    MOF_FIELD MofData[9];
} KERB_ACCEPTSC_INFO, *PKERB_ACCEPTSC_INFO;

typedef struct _KERB_ASN1_DATA {
    ULONG Pdu;
    DWORD Length;
    PBYTE Asn1Buffer;
} KERB_ASN1_DATA, *PKERB_ASN1_DATA;

#define KERB_MAX_AUTHEN_SIZE 1024
typedef struct _KERB_AUTHEN_HEADER {
    TimeStamp tsTime;
    ULONG Count;
    BYTE Checksum[16]; // Md5 digest
} KERB_AUTHEN_HEADER, *PKERB_AUTHEN_HEADER;

typedef struct _KERB_BINDING_CACHE_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    TimeStamp DiscoveryTime;
    UNICODE_STRING RealmName;
    UNICODE_STRING KdcAddress;
    ULONG AddressType;
    ULONG Flags; // These are requested flags for DsGetDcName
    ULONG DcFlags; // These are flags returned by DsGetDcName
#define KERB_BINDING_LOCAL          0x80000000
#define KERB_BINDING_NO_TCP         0x40000000
#define KERB_BINDING_NEGATIVE_ENTRY 0x20000000
#define KERB_NO_DC_FLAGS            0x10000000
    ULONG CacheFlags;
    // Added after NT 5.2
    UNICODE_STRING KdcName;
} KERB_BINDING_CACHE_ENTRY, *PKERB_BINDING_CACHE_ENTRY;

typedef struct _KERB_CHANGE_MACH_PWD_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    UNICODE_STRING NewPassword;
    UNICODE_STRING OldPassword;
} KERB_CHANGE_MACH_PWD_REQUEST, *PKERB_CHANGE_MACH_PWD_REQUEST;

typedef struct _KERB_CHANGE_PASSWORD_KDC_RESPONSE_HEADER {
    BYTE ErrorCode[2];
} KERB_CHANGE_PASSWORD_KDC_RESPONSE_HEADER, *PKERB_CHANGE_PASSWORD_KDC_RESPONSE_HEADER;

typedef struct _KERB_CHANGE_PASSWORD_RESTRICTIONS_RESPONSE {
    KERB_CHANGE_PASSWORD_KDC_RESPONSE_HEADER Header;
    BYTE ResultString[2];
    ULONG MinPasswordLength;
    ULONG PasswordHistoryLength;
    ULONG PasswordProperties;
    TimeStamp MaxPasswordAge;
    TimeStamp MinPasswordAge;
} KERB_CHANGE_PASSWORD_RESTRICTIONS_RESPONSE, *PKERB_CHANGE_PASSWORD_RESTRICTIONS_RESPONSE;

typedef struct _KERB_CHANGEPASS_INFO {
    // Start {No Data}, End {Status, AccountName, AccountRealm}
    EVENT_TRACE_HEADER EventTrace;
    MOF_FIELD MofData[5];
} KERB_CHANGEPASS_INFO, *PKERB_CHANGEPASS_INFO;

typedef struct _KERB_KDC_PROXY {
    LUID LogonId;
    ULONG Flags;
    BYTE ForceProxy;
    KERB_PROXY_SERVER ProxyServer;
    UNICODE_STRING TlsUserName;
    UNICODE_STRING TlsPin;
    const PCERT_CONTEXT CertContext;
} KERB_KDC_PROXY, *PKERB_KDC_PROXY;

typedef struct _KERB_CREDENTIAL {
    KERBEROS_LIST_ENTRY ListEntry;
    ULONG HandleCount;
    LUID LogonId;
    TimeStamp Lifetime;
    UNICODE_STRING CredentialName;
    ULONG CredentialFlags;
    ULONG ClientProcess;
    _KERB_PRIMARY_CREDENTIAL* SuppliedCredentials;
    PPKERB_AUTHORIZATION_DATA AuthData;
    ULONG CredentialTag; // Defined as KERB_CREDENTIAL_TAG_ACTIVE or KERB_CREDENTIAL_TAG_DELETE
    // Added after NT 5.2
    PLSA_TOKEN_INFO_HEADER TokenRestrictions;
    HANDLE ClientToken;
    LUID ModifiedId;
    UCHAR ClientProcessIsSystemProc;
    ULONGLONG CredId;
    PKERB_KDC_PROXY KdcProxy;
} KERB_CREDENTIAL, *PKERB_CREDENTIAL;

typedef struct _KERB_ENCRYPTION_KEY {
#ifdef __cplusplus
    PKerbCredIsoApi credisoobj;
#else
    void* credisoobj;
#endif
    LONG keytype;
    KERB_RPC_OCTET_STRING keyvalue;
} KERB_ENCRYPTION_KEY, *PKERB_ENCRYPTION_KEY;

typedef struct _KERB_INTERNAL_NAME {
    SHORT NameType;
    USHORT NameCount;
    UNICODE_STRING Names[ANYSIZE_ARRAY];
} KERB_INTERNAL_NAME, *PKERB_INTERNAL_NAME;

typedef struct _KERB_TICKET_CACHE_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    volatile LONG Linked;
    PKERB_INTERNAL_NAME ServiceName;
    PKERB_INTERNAL_NAME TargetName;
    UNICODE_STRING DomainName;
    UNICODE_STRING TargetDomainName;
    UNICODE_STRING AltTargetDomainName;
    UNICODE_STRING ClientDomainName;
    UNICODE_STRING KdcCalled; // Added after NT 5.2
    UNICODE_STRING CredSuppliedDomainName; // Added after NT 5.2
    PKERB_INTERNAL_NAME ClientName;
    PKERB_INTERNAL_NAME AltClientName;
    ULONG TicketFlags;
    ULONG CacheFlags;
    KERB_ENCRYPTION_KEY SessionKey;
    KERB_ENCRYPTION_KEY CredentialKey; // Only used for pkinit
    TimeStamp StartTime;
    TimeStamp EndTime;
    TimeStamp RenewUntil;
    KERB_TICKET Ticket;
    LONG TimeShift; // Originally named TimeSkew and typed as a TimeStamp in NT 5.2 and below
    LUID EvidenceLogonId;
    void* ScavengerHandle;
    // All remaining members were added after NT 5.2
    RTL_CRITICAL_SECTION Lock;
    GUID LogonGuid;
    ULONG ServerSupportedEncryptionTypes;
    ULONGLONG CredId;
    struct _KERB_TICKET_CACHE_ENTRY* HubTicket;
} KERB_TICKET_CACHE_ENTRY, *PKERB_TICKET_CACHE_ENTRY;

typedef struct _KERB_PLAINTEXT_PASSWORD {
#ifdef __cplusplus
    class KerbCredIsoApi* CredIsoObj;
#else
    void* CredIsoObj;
#endif
    KERB_PLAINTEXT_PASSWORD_PROTECTION Protection;
    KERB_PLAINTEXT_PASSWORD_STORAGE Storage;
} KERB_PLAINTEXT_PASSWORD, *PKERB_PLAINTEXT_PASSWORD;

typedef struct _KERB_KEY_DATA {
    UNICODE_STRING Salt;
    ULONG IterationCount;
    KERB_ENCRYPTION_KEY Key;
} KERB_KEY_DATA, *PKERB_KEY_DATA;

typedef struct _KERB_STORED_CREDENTIAL {
    USHORT Revision;
    USHORT Flags;
    USHORT CredentialCount;
    USHORT ServiceCredentialCount;
    USHORT OldCredentialCount;
    USHORT OlderCredentialCount;
    UNICODE_STRING DefaultSalt;
    ULONG DefaultIterationCount;
    KERB_KEY_DATA Credentials[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL, *PKERB_STORED_CREDENTIAL;

typedef struct _KERB_TICKET_CACHE {
    LIST_ENTRY CacheEntries;
    TimeStamp LastCleanup;
} KERB_TICKET_CACHE, *PKERB_TICKET_CACHE;

typedef struct _KERB_PUBLIC_KEY_CREDENTIALS {
    UNICODE_STRING Pin;
    UNICODE_STRING AlternateDomainName;
    const PCERT_CONTEXT CertContext;
    const PCERT_CONTEXT ClientCertContext;
    unsigned __int64 KerbHProvOrKeyHandle;
    ULONG KeySpec;
#define CSP_DATA_INITIALIZED 0x01
#define CSP_DATA_REUSED      0x02
// Info which determines how the pin is cached
#define CONTEXT_INITIALIZED_WITH_CRED_MAN_CREDS 0x10
#define CONTEXT_INITIALIZED_WITH_ACH            0x20
    ULONG InitializationInfo;
    class KerbPrivateKeyOperations* PkFunctions;
    ULONG CspDataLength;
    BYTE CspData[ANYSIZE_ARRAY];
} KERB_PUBLIC_KEY_CREDENTIALS, *PKERB_PUBLIC_KEY_CREDENTIALS;

typedef struct _KERB_S4U2PROXY_CACHE {
    BYTE Initialized;
    LUID LogonId;
    ULONG Flags;
    LONG LastStatus;
    TimeStamp Expiry;
    RTL_AVL_TREE AvlTree;
    KERBEROS_LIST CacheEntries;
} KERB_S4U2PROXY_CACHE, *PKERB_S4U2PROXY_CACHE;

typedef struct _KERB_PRIMARY_CREDENTIAL {
    UNICODE_STRING UserName;
    UNICODE_STRING DomainName;
    KERB_PLAINTEXT_PASSWORD ClearPassword; // Present until a ticket is recieved for the logon session
    KERB_PLAINTEXT_PASSWORD OldClearPassword;
    UNICODE_STRING OldUserName; // User name used in explicitly passed credentials
    UNICODE_STRING OldDomainName; // Domain name used in explicitly passed credentials
    LM_OWF_PASSWORD OldHashPassword; // Hash of encrypted ClearPassword
    PKERB_STORED_CREDENTIAL Passwords;
    PKERB_STORED_CREDENTIAL OldPasswords;
    KERB_TICKET_CACHE ServerTicketCache;
    KERB_TICKET_CACHE S4UTicketCache;
    KERB_TICKET_CACHE AuthenticationTicketCache;
    PKERB_PUBLIC_KEY_CREDENTIALS PublicKeyCreds;
    // All remaining members were added after NT 5.2
    LUID LogonId;
    TimeStamp AuthTime;
    ULONG NumKdcSuppliedKeys;
    PKERB_ENCRYPTION_KEY KdcSuppliedKeys;
    ULONG PackedCredentialsSize;
    PBYTE PackedCredentials;
    UNICODE_STRING LsaUserName;
    UNICODE_STRING LsaDomainName;
    UNICODE_STRING LsaDnsDomainName;
    PSID UserSid;
    ULONG ServerNameCount;
    PUNICODE_STRING ServerNames;
    ULONG Flags;
    FILETIME GmsaFileTime;
    KDC_PROXY_CACHE KdcProxyCache;
    KERB_S4U2PROXY_CACHE S4U2ProxyCache;
    PBYTE SavedPaDataList;
    ULONG SavedPaDataListSize;
} KERB_PRIMARY_CREDENTIAL, *PKERB_PRIMARY_CREDENTIAL;

typedef struct _KERB_CREDMAN_CRED {
    KERBEROS_LIST_ENTRY ListEntry;
    ULONG CredentialFlags;
    // The user name and domain name are included for their
    // tracking when a TGT overwrites a primary credential.
    UNICODE_STRING CredmanUserName;
    UNICODE_STRING CredmanDomainName;
    PKERB_PRIMARY_CREDENTIAL SuppliedCredentials;
} KERB_CREDMAN_CRED, *PKERB_CREDMAN_CRED;

#define KERB_CONTEXT_TAG_ACTIVE ULONG('AxtC')
#define KERB_CONTEXT_TAG_DELETE ULONG('DxtC')
typedef struct _KERB_CONTEXT {
    KERBEROS_LIST_ENTRY ListEntry;
    TimeStamp Lifetime; // Expiration time
    TimeStamp RenewTime;
    TimeStamp StartTime;
    TimeStamp LogoffTime; // Added after NT 5.2
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
    UNICODE_STRING ClientDnsRealm;
    union {
        ULONG ClientProcess;
        ULONG LsaContextHandle;
    };
    LUID LogonId;
    HANDLE TokenHandle;
    PKERB_CREDENTIAL ContextCredential;
    KERB_ENCRYPTION_KEY SessionKey;
    ULONGLONG Nonce; // Was originally typed as a ULONG
    ULONGLONG ReceiveNonce; // Was originally typed as a ULONG
    ULONG ContextFlags;
    ULONG ContextAttributes;
    ULONG NegotiationInfo; // Added after NT 5.2
    ULONG EncryptionType;
    PSID UserSid;
    KERB_CONTEXT_STATE ContextState;
    ULONG Retries;
    KERB_ENCRYPTION_KEY TicketKey;
    PKERB_TICKET_CACHE_ENTRY TicketCacheEntry;
    // Except for the marshalled target info entries, all of
    // the following fields were added after NT 5.2
    UNICODE_STRING ClientPrincipalName;
    UNICODE_STRING ServerPrincipalName;
    PKERB_CREDMAN_CRED CredManCredentials;
    PUCHAR pbMarshalledTargetInfo;
    ULONG cbMarshalledTargetInfo;
    TimeStamp AuthenticatorTime;
    ULONG ContextTag; // Defined as KERB_CONTEXT_TAG_ACTIVE or KERB_CONTEXT_TAG_DELETE
    KERB_ENCRYPTION_KEY OldSessionKey;
    PUCHAR pbMarshalledClientSpecifiedTargetInfo;
    ULONG cbMarshalledClientSpecifiedTargetInfo;
} KERB_CONTEXT, *PKERB_CONTEXT;

typedef struct _KERB_CRYPTO_KEY_WOW64 {
    LONG KeyType;
    ULONG Length;
    ULONG Value;
} KERB_CRYPTO_KEY_WOW64, *PKERB_CRYPTO_KEY_WOW64;

typedef struct _KERB_DEBUG_REPLY {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    UCHAR Data[ANYSIZE_ARRAY];
} KERB_DEBUG_REPLY, *PKERB_DEBUG_REPLY;

typedef struct _KERB_DEBUG_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
#define KERB_DEBUG_REQ_BREAKPOINT 0x1
#define KERB_DEBUG_REQ_CALL_PACK  0x2
#define KERB_DEBUG_REQ_DATAGRAM   0x3
#define KERB_DEBUG_REQ_STATISTICS 0x4
#define KERB_DEBUG_CREATE_TOKEN   0x5
    ULONG DebugRequest;
} KERB_DEBUG_REQUEST, *PKERB_DEBUG_REQUEST;

typedef struct _KERB_DEBUG_STATS {
    ULONG CacheHits;
    ULONG CacheMisses;
    ULONG SkewedRequests;
    ULONG SuccessRequests;
    // LastSync was originally typed as a LARGE_INTEGER, but
    // Microsoft likely intended it to be interpreted as a
    // TimeStamp value.
    LARGE_INTEGER LastSync;
} KERB_DEBUG_STATS, *PKERB_DEBUG_STATS;

typedef struct _KERB_DH_DOMAIN_PARAMETERS {
    ULONG ModulusSize;
    CERT_X942_DH_PARAMETERS X942Params;
} KERB_DH_DOMAIN_PARAMETERS, *PKERB_DH_DOMAIN_PARAMETERS;

typedef struct _KERB_PROXY_SERVER_LIST {
    PKERB_PROXY_SERVER ServerList;
    ULONG NumOfServers;
    ULONG Index;
} KERB_PROXY_SERVER_LIST, *PKERB_PROXY_SERVER_LIST;

typedef struct _KERB_DNS_SUFFIX_COMPONENT {
    UNICODE_STRING Name;
    ULONG Flags;
    RTL_AVL_TABLE SubComponents;
    KERB_PROXY_SERVER_LIST SuffixMatchProxyServerList;
    KERB_PROXY_SERVER_LIST FullMatchProxyServerList;
} KERB_DNS_SUFFIX_COMPONENT, *PKERB_DNS_SUFFIX_COMPONENT;

typedef struct _KERB_DNS_SUFFIX_TABLE {
    BYTE Initialized;
    BYTE Global;
    RTL_CRITICAL_SECTION Lock;
    PRTL_AVL_TABLE Root;
    KERB_PROXY_SERVER_LIST DefaultProxyServerList;
} KERB_DNS_SUFFIX_TABLE, *PKERB_DNS_SUFFIX_TABLE;

typedef struct _KERB_DOMAIN_CACHE {
    BYTE Initialized;
    KERBEROS_LIST CacheEntries;
} KERB_DOMAIN_CACHE, *PKERB_DOMAIN_CACHE;

typedef struct _KERB_DOMAIN_CACHE_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    ULONGLONG Identifier;
    TimeStamp CreateTime;
    UNICODE_STRING DomainName;
    UNICODE_STRING DnsDomainName;
    ULONG CacheType;
} KERB_DOMAIN_CACHE_ENTRY, *PKERB_DOMAIN_CACHE_ENTRY;

typedef struct _KERB_ECC_CURVE_INFO {
    ULONG KeyBitLength;
    LPCSTR Oid;
    LPCSTR HashName;
    LPCWSTR AlgorithmName;
    HANDLE AlgorithmHandle;
    KERB_ALGORITHM_IDENTIFIER AlgorithmId;
} KERB_ECC_CURVE_INFO, *PKERB_ECC_CURVE_INFO;

typedef struct _KERB_ENCRYPTION_KEY32 {
    LONG keytype;
    ULONG keyvaluelength;
    ULONG keyvaluevalue;
} KERB_ENCRYPTION_KEY32, *PKERB_ENCRYPTION_KEY32;

typedef struct _KERB_EXTRA_CRED {
    KERBEROS_LIST_ENTRY ListEntry;
    volatile LONG Linked;
    ULONG CredentialFlags; // Added after NT 5.2
    UNICODE_STRING cName;
    UNICODE_STRING cRealm;
    // In NT 5.2 the remaining content was defined as such:
    // - PKERB_STORED_CREDENTIAL Passwords;
    // - PKERB_STORED_CREDENTIAL OldPasswords;
    // Sometime after NT 5.2 the end of the structure was
    // defined as the following.
    PKERB_PRIMARY_CREDENTIAL SuppliedCredentials;
    ULONG PrincipalNameCount;
    PUNICODE_STRING PrincipalNames;
} KERB_EXTRA_CRED, *PKERB_EXTRA_CRED;

/// <summary>
/// Was originally used to define an array named KerbContextFlagMappingTable
/// which was used to map the following ISC_RET_xx flags to ASC_RET_xxx flags:
/// - ISC_RET_EXTENDED_ERROR = ASC_RET_EXTENDED_ERROR
/// - ISC_RET_INTEGRITY = ASC_RET_INTEGRITY
/// - ISC_RET_IDENTIFY = ASC_RET_IDENTIFY
/// - ISC_RET_NULL_SESSION = ASC_RET_NULL_SESSION
/// </summary>
typedef struct _KERB_FLAG_MAPPING {
    ULONG InitFlag;
    ULONG AcceptFlag;
} KERB_FLAG_MAPPING, *PKERB_FLAG_MAPPING;

typedef struct _KERB_FSO_BINDING_HANDLE {
    HANDLE hDs;
    ULONG ReferenceCount;
} KERB_FSO_BINDING_HANDLE, *PKERB_FSO_BINDING_HANDLE;

typedef struct _KERB_FSO_CACHE_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    RTL_RESOURCE Resource;
    TimeStamp DiscoveryTime;
    UNICODE_STRING ForestName;
    UNICODE_STRING DomainName;
    UNICODE_STRING DCName;
    ULONG Flags;
    PKERB_FSO_BINDING_HANDLE Binding;
} KERB_FSO_CACHE_ENTRY, *PKERB_FSO_CACHE_ENTRY;

typedef struct _KERB_FSO_COMMON_FUNCTION_TABLE {
    // clang-format off
    LPVOID (* FsoAllocate)(ULONG);
    VOID (* FsoFree)(LPVOID);
    VOID (* FsoReportInvalid)(PUNICODE_STRING);
    // clang-format on
    ULONG FsoLockLevel;
} KERB_FSO_COMMON_FUNCTION_TABLE, *PKERB_FSO_COMMON_FUNCTION_TABLE;

#define GSS_CHECKSUM_TYPE          0x8003
#define GSS_CHECKSUM_SIZE          24
#define GSS_DELEGATE_CHECKSUM_SIZE 28
typedef struct _KERB_GSS_CHECKSUM {
    ULONG BindLength;
    ULONG BindHash[4];
#define GSS_C_DELEG_FLAG          0x01
#define GSS_C_MUTUAL_FLAG         0x02
#define GSS_C_REPLAY_FLAG         0x04
#define GSS_C_SEQUENCE_FLAG       0x08
#define GSS_C_CONF_FLAG           0x10
#define GSS_C_INTEG_FLAG          0x20
#define GSS_C_ANON_FLAG           0x40
#define GSS_C_DCE_STYLE           0x1000
#define GSS_C_IDENTIFY_FLAG       0x2000
#define GSS_C_EXTENDED_ERROR_FLAG 0x4000
    ULONG GssFlags;
    USHORT Delegation;
    USHORT DelegationLength;
    BYTE DelegationInfo[ANYSIZE_ARRAY];
} KERB_GSS_CHECKSUM, *PKERB_GSS_CHECKSUM;

typedef struct _KERB_GSS_SIGNATURE {
    // Options for the first byte
#define KERB_GSS_SIG_DES_MAC_MD5 0x00
#define KERB_GSS_SIG_MD25        0x01
#define KERB_GSS_SIG_DES_MAC     0x02
#define KERB_GSS_SIG_HMAC        0x11
    // Options for the second byte
#define KERB_GSS_SIG_SECOND 0x00
    BYTE SignatureAlgorithm[2];
    union {
        BYTE SignFiller[4];
        struct
        {
#define KERB_GSS_SEAL_DES_CBC   0x00
#define KERB_GSS_SEAL_RC4_OLD   0x11
#define KERB_GSS_SEAL_RC4       0x10
#define KERB_GSS_NO_SEAL        0xff
#define KERB_GSS_NO_SEAL_SECOND 0xff
            BYTE SealAlgorithm[2];
            BYTE SealFiller[2];
        };
    };
    BYTE SequenceNumber[8];
    BYTE Checksum[8];
} KERB_GSS_SIGNATURE, *PKERB_GSS_SIGNATURE;

#define KERB_GSS_SIG_CONFOUNDER_SIZE 8
typedef struct _KERB_GSS_SEAL_SIGNATURE {
    KERB_GSS_SIGNATURE Signature;
    BYTE Confounder[KERB_GSS_SIG_CONFOUNDER_SIZE];
} KERB_GSS_SEAL_SIGNATURE, *PKERB_GSS_SEAL_SIGNATURE;

typedef struct _KERB_GSS_SIGNATURE_HEADER {
    BYTE Flags;
    BYTE Filler;
    union {
        BYTE SignFiller[4];
        struct
        {
            BYTE EC[2];
            BYTE RRC[2];
        };
    };
    BYTE SequenceNumber[8];
} KERB_GSS_SIGNATURE_HEADER, *PKERB_GSS_SIGNATURE_HEADER;

#define KERB_GSS_SIG_NEW_CONFOUNDER_SIZE 16
typedef struct _KERB_GSS_SEAL_SIGNATURE_NEW {
    KERB_GSS_SIGNATURE_HEADER Header;
    BYTE EncryptedHeader[32];
    BYTE Checksum[12];
    BYTE Confounder[KERB_GSS_SIG_NEW_CONFOUNDER_SIZE];
} KERB_GSS_SEAL_SIGNATURE_NEW, *PKERB_GSS_SEAL_SIGNATURE_NEW;

typedef struct _KERB_GSS_SIGNATURE_NEW {
    KERB_GSS_SIGNATURE_HEADER Header;
    BYTE Checksum[12];
} KERB_GSS_SIGNATURE_NEW, *PKERB_GSS_SIGNATURE_NEW;

typedef struct _KERB_INIT_CONTEXT_DATA {
    TimeStamp StartTime;
    TimeStamp EndTime;
    TimeStamp RenewUntilTime;
    ULONG TicketOptions;
#define KERB_INIT_RETURN_TICKET     0x1 // Return raw ticket
#define KERB_INIT_RETURN_MIT_AP_REQ 0x2 // Return mit style AP request
    ULONG RequestOptions; // Options for what to return
} KERB_INIT_CONTEXT_DATA, *PKERB_INIT_CONTEXT_DATA;

typedef struct _KERB_INITSC_INFO {
    // Start {No Data}, End {Status, CredSource, DomainName, UserName, Target, (KerbExtError), (Klininfo)}
    EVENT_TRACE_HEADER EventTrace;
    MOF_FIELD MofData[11];
} KERB_INITSC_INFO, *PKERB_INITSC_INFO;

typedef struct _KERB_MESSAGE_BUFFER {
    ULONG BufferSize;
    PUCHAR Buffer;
} KERB_MESSAGE_BUFFER, *PKERB_MESSAGE_BUFFER;

typedef struct _KERB_KDC_CALL_INFO {
    // clang-format off
    LONG (* KdcVerifyPac)(ULONG, PUCHAR, ULONG, ULONG, PUCHAR);
    LONG (* KdcGetTicket)(PVOID, sockaddr*, sockaddr*, PKERB_MESSAGE_BUFFER, PKERB_MESSAGE_BUFFER);
    LONG (* KdcChangePassword)(PVOID, sockaddr*, sockaddr*, PKERB_MESSAGE_BUFFER, PKERB_MESSAGE_BUFFER);
    VOID (* KdcFreeMemory)(PVOID);
    // clang-format on
} KERB_KDC_CALL_INFO, *PKERB_KDC_CALL_INFO;

typedef struct _KERBEROS_LIST2 {
    LIST_ENTRY List2;
    RTL_CRITICAL_SECTION Lock2;
} KERBEROS_LIST2, *PKERBEROS_LIST2;

typedef struct _KERB_KEY_AND_CRED {
    PKERB_ENCRYPTION_KEY Key;
    PKERB_PRIMARY_CREDENTIAL PrimaryCred;
} KERB_KEY_AND_CRED, *PKERB_KEY_AND_CRED;

/// <summary>
/// When kerberos changed from the _KERB_KEY_DATA_OLD structure
/// has not been determined, but it was used for at least NT 5.2
/// and prior.
/// </summary>
typedef struct _KERB_KEY_DATA_OLD {
    UNICODE_STRING Salt;
    KERB_ENCRYPTION_KEY Key;
} KERB_KEY_DATA_OLD, *PKERB_KEY_DATA_OLD;

typedef struct _KERB_KEY_DATA32 {
    UNICODE_STRING32 Salt;
    ULONG IterationCount;
    KERB_ENCRYPTION_KEY32 Key;
} KERB_KEY_DATA32, *PKERB_KEY_DATA32;

/// <summary>
/// When kerberos changed from the _KERB_KEY_DATA32_OLD structure
/// has not been determined, but it was used for at least NT 5.2
/// and prior.
/// </summary>
typedef struct _KERB_KEY_DATA32_OLD {
    UNICODE_STRING32 Salt;
    KERB_ENCRYPTION_KEY32 Key;
} KERB_KEY_DATA32_OLD, *PKERB_KEY_DATA32_OLD;

typedef struct _KERB_KPASSWD_REP {
    BYTE MessageLength[2];
    BYTE Version[2];
    BYTE ApRepLength[2];
    BYTE Data[ANYSIZE_ARRAY]; // Populated for KERB_AP_REPLY, KERB_PRIV, and KERB_ERROR
} KERB_KPASSWD_REP, *PKERB_KPASSWD_REP;

typedef struct _KERB_KPASSWD_REQ {
    BYTE MessageLength[2];
    BYTE Version[2];
    BYTE ApReqLength[2];
    BYTE Data[ANYSIZE_ARRAY]; // Populated for KERB_AP_REQUEST-REQ and KERB_PRIV
} KERB_KPASSWD_REQ, *PKERB_KPASSWD_REQ;

typedef struct _KERB_LOGON_INFO {
    // Start {No Data}, End {Status, LogonType, (UserName), (LogonDomain)}
    EVENT_TRACE_HEADER EventTrace;
    MOF_FIELD MofData[7];
} KERB_LOGON_INFO, *PKERB_LOGON_INFO;

typedef struct _KERB_LOGON_SESSION {
    // The first member was originally the following:
    // - KERBEROS_LIST_ENTRY ListEntry
    // The list of kerberos logon sessions are now managed
    // by the KERB_LOGON_SESSION_TABLE_ENTRY structure and
    // the first member was replaced by a reference count.
    LONG References;
    KERBEROS_LIST CredmanCredentials;
    LUID LogonId;
    TimeStamp Lifetime;
    RTL_CRITICAL_SECTION Lock;
    KERB_PRIMARY_CREDENTIAL PrimaryCredentials;
    EXTRA_CRED_LIST ExtraCredentials;
    ULONG LogonSessionFlags;
    HANDLE TaskHandle;
    // These members were added after NT 5.2
    BYTE UseProcessTable;
    struct _LUID LinkedLogonId;
} KERB_LOGON_SESSION, *PKERB_LOGON_SESSION;

typedef struct _KERB_LOGON_SESSION_TABLE_ENTRY {
    PKERB_LOGON_SESSION LogonSession;
} KERB_LOGON_SESSION_TABLE_ENTRY, *PKERB_LOGON_SESSION_TABLE_ENTRY;

typedef struct _KERB_LOOP_BACK {
    PKERB_CREDENTIAL Credential;
    ULONGLONG TickCount;
} KERB_LOOP_BACK, *PKERB_LOOP_BACK;

typedef struct _KERB_MIT_SERVER_LIST {
    LONG ServerCount;
    LONG LastServerUsed;
    PUNICODE_STRING ServerNames;
} KERB_MIT_SERVER_LIST, *PKERB_MIT_SERVER_LIST;

typedef struct _KERB_MIT_REALM {
    KERBEROS_LIST_ENTRY Next;
#define KERB_MIT_REALM_SEND_ADDRESS           0x00000001
#define KERB_MIT_REALM_TCP_SUPPORTED          0x00000002
#define KERB_MIT_REALM_TRUSTED_FOR_DELEGATION 0x00000004
#define KERB_MIT_REALM_DOES_CANONICALIZE      0x00000008
#define KERB_MIT_REALM_KDC_LOOKUP             0x00010000
#define KERB_MIT_REALM_KPWD_LOOKUP            0x00020000
    ULONG Flags;
    ULONG ApReqChecksumType;
    ULONG PreAuthType;
    ULONG RealmNameCount;
    UNICODE_STRING RealmName;
    PUNICODE_STRING AlternateRealmNames;
    KERB_MIT_SERVER_LIST KdcNames;
    KERB_MIT_SERVER_LIST KpasswdNames;
    LARGE_INTEGER LastLookup;
    LARGE_INTEGER LastLookupKpasswd; // Added after NT 5.2
} KERB_MIT_REALM, *PKERB_MIT_REALM;

typedef struct _KERB_PACKED_CONTEXT {
    ULONG ContextType;
    ULONG Pad;
    TimeStamp Lifetime; // Expiration time
    TimeStamp RenewTime;
    TimeStamp StartTime;
    TimeStamp LogoffTime; // Added after NT 5.2
    UNICODE_STRING32 ClientName;
    UNICODE_STRING32 ClientRealm;
    ULONG LsaContextHandle;
    LUID LogonId;
    ULONG TokenHandle;
    ULONG CredentialHandle;
    ULONG SessionKeyType;
    ULONG SessionKeyOffset;
    ULONG SessionKeyLength;
    ULONGLONG Nonce; // Was originally typed as a ULONG
    ULONGLONG ReceiveNonce; // Was originally typed as a ULONG
    ULONG ContextFlags;
    ULONG ContextAttributes;
    ULONG EncryptionType;
    KERB_CONTEXT_STATE ContextState;
    ULONG Retries;
    ULONG MarshalledTargetInfo;
    ULONG MarshalledTargetInfoLength;
    // All of the following fields were added after NT 5.2
    ULONG OldSessionKeyType;
    ULONG OldSessionKeyOffset;
    ULONG OldSessionKeyLength;
    ULONG MarshalledClientSpecifiedTargetInfo;
    ULONG MarshalledClientSpecifiedTargetInfoLength;
} KERB_PACKED_CONTEXT, *PKERB_PACKED_CONTEXT;

typedef struct _KERB_PARSED_DNS_SUFFIX {
    UNICODE_STRING ParsedString;
    PUNICODE_STRING ComponentStrings;
    ULONG NumOfComponentStrings;
    ULONG RemainingComponentStrings;
    ULONG LeadingDot;
    BYTE MatchAny;
} KERB_PARSED_DNS_SUFFIX, *PKERB_PARSED_DNS_SUFFIX;

typedef struct _KERB_PIN_KDC_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    LUID LogonId;
    ULONG ProcessId;
    ULONG ThreadId;
    UNICODE_STRING DomainName;
    UNICODE_STRING DcName;
    ULONG DcFlags;
    ULONGLONG CreationTime;
} KERB_PIN_KDC_ENTRY, *PKERB_PIN_KDC_ENTRY;

typedef struct _KERB_PREAUTH_DATA {
#define KERBFLAG_LOGON       0x1
#define KERBFLAG_INTERACTIVE 0x2
    ULONG Flags;
} KERB_PREAUTH_DATA, *PKERB_PREAUTH_DATA;

typedef struct _KERB_PROCESS_TABLE_ENTRY {
    ULONG ProcessId;
    KERBEROS_LIST PinKdcEntries;
} KERB_PROCESS_TABLE_ENTRY, *PKERB_PROCESS_TABLE_ENTRY;

typedef struct _KERB_PROXY_LOGON_CRED {
    PKERB_LOGON_SESSION LogonSession;
    PKERB_CREDENTIAL Credential;
} KERB_PROXY_LOGON_CRED, *PKERB_PROXY_LOGON_CRED;

typedef struct _KERB_QUERY_SUPPLEMENTAL_CREDS_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    UNICODE_STRING PackageName;
    PCREDENTIALW MarshalledCreds;
    LUID LogonId;
    ULONG Flags;
} KERB_QUERY_SUPPLEMENTAL_CREDS_REQUEST, *PKERB_QUERY_SUPPLEMENTAL_CREDS_REQUEST;

typedef struct _KERB_QUERY_SUPPLEMENTAL_CREDS_RESPONSE {
    ENCRYPTED_CREDENTIALW ReturnedCreds;
} KERB_QUERY_SUPPLEMENTAL_CREDS_RESPONSE, *PKERB_QUERY_SUPPLEMENTAL_CREDS_RESPONSE;

typedef struct _KERB_REG_PARAMETER {
    LPWSTR Name;
    PULONG Address;
    ULONG DefaultValue;
    DWORD ReverseSense;
    DWORD GPEnabled;
    DWORD WasInRegistry;
    ULONG RegistryValue;
    KERB_REG_TELEMETRY_FLAG TelemetryFlag;
} KERB_REG_PARAMETER, *PKERB_REG_PARAMETER;

typedef struct _KERB_REPLAY_AUDIT_INFO {
    UNICODE_STRING ClientName;
    UNICODE_STRING ClientRealm;
} KERB_REPLAY_AUDIT_INFO, *PKERB_REPLAY_AUDIT_INFO;

typedef struct _KERB_RPC_CRYPT_BIT_BLOB {
    ULONG cbData;
    PBYTE pbData;
    ULONG cUnusedBits;
} KERB_RPC_CRYPT_BIT_BLOB, *PKERB_RPC_CRYPT_BIT_BLOB;

typedef struct _KERB_RPC_CRYPTO_API_BLOB {
    ULONG cbData;
    PBYTE pbData;
} KERB_RPC_CRYPTO_API_BLOB, *PKERB_RPC_CRYPTO_API_BLOB;

typedef struct _KERB_RPC_FAST_ARMOR {
    DWORD armor_type;
    KERB_RPC_OCTET_STRING armor_value;
} KERB_RPC_FAST_ARMOR, *PKERB_RPC_FAST_ARMOR;

typedef struct _KERB_RPC_INTERNAL_NAME {
    SHORT NameType;
    USHORT NameCount;
    PUNICODE_STRING Names;
} KERB_RPC_INTERNAL_NAME, *PKERB_RPC_INTERNAL_NAME;

typedef struct _KERB_RPC_PA_DATA {
    DWORD preauth_data_type;
    KERB_RPC_OCTET_STRING preauth_data;
} KERB_RPC_PA_DATA, *PKERB_RPC_PA_DATA;

typedef struct _KERB_S4U2PROXY_CACHE_ENTRY {
    RTL_BALANCED_NODE AvlLink;
    KERBEROS_LIST_ENTRY ListEntry;
    PKERB_INTERNAL_NAME ServerName;
    UNICODE_STRING ServerNameString;
    ULONG Flags;
    LONG LastStatus;
    TimeStamp Expiry;
} KERB_S4U2PROXY_CACHE_ENTRY, *PKERB_S4U2PROXY_CACHE_ENTRY;

typedef struct _KERB_SESSION_KEY_ENTRY {
    LIST_ENTRY ListEntry;
    LUID LogonId; // Added after NT 5.2
    KERB_ENCRYPTION_KEY SessionKey;
    FILETIME ExpireTime;
    HANDLE ClientToken; // Added after NT 5.2
} KERB_SESSION_KEY_ENTRY, *PKERB_SESSION_KEY_ENTRY;

typedef struct _KERB_SETPASS_INFO {
    // Start {No Data}, End {Status, AccountName, AccountRealm, (ClientName), (ClientRealm), (KdcAddress)}
    EVENT_TRACE_HEADER EventTrace;
    MOF_FIELD MofData[11];
} KERB_SETPASS_INFO, *PKERB_SETPASS_INFO;

typedef struct _KERB_SMARTCARD_CSP_INFO {
    ULONG dwLogonInfoLen;
    ULONG MessageType;
    union {
        LPVOID ContextInformation;
        ULONGLONG SpaceHolderForWow64;
    };
    ULONG flags;
    ULONG KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    WCHAR bBuffer[4];
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

typedef struct _SPN_CACHE_RESULT {
    UNICODE_STRING AccountRealm;
    UNICODE_STRING TargetRealm;
#define KERB_SPN_UNKNOWN 0x1
#define KERB_SPN_KNOWN   0x2
    ULONG CacheFlags;
    TimeStamp CacheStartTime;
} SPN_CACHE_RESULT, *PSPN_CACHE_RESULT;

typedef struct _KERB_SPN_CACHE_ENTRY {
    KERBEROS_LIST_ENTRY ListEntry;
    PKERB_INTERNAL_NAME Spn;
    RTL_RESOURCE ResultLock;
    ULONG ResultCount;
    SPN_CACHE_RESULT Results[16]; // 16 is the maximum amount of results
} KERB_SPN_CACHE_ENTRY, *PKERB_SPN_CACHE_ENTRY;

/// <summary>
/// KERB_STORED_CREDENTIAL changed sometime after NT 5.2.
/// KERB_STORED_CREDENTIAL_OLD is what Microsoft renamed
/// the original structure to. The structure format can
/// be determined at runtime by the revision number.
/// </summary>
typedef struct _KERB_STORED_CREDENTIAL_OLD {
    USHORT Revision; // Set to 3
    USHORT Flags;
    USHORT CredentialCount;
    USHORT OldCredentialCount;
    UNICODE_STRING DefaultSalt;
    KERB_KEY_DATA_OLD Credentials[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL_OLD, *PKERB_STORED_CREDENTIAL_OLD;

/// <summary>
/// KERB_STORED_CREDENTIALS are stored in the DS as a blob.
/// They are stored in a 32 bit format for compatibility
/// with NT 5.0 and 3s-bit DCs.
/// </summary>
typedef struct _KERB_STORED_CREDENTIAL32 {
    USHORT Revision;
    USHORT Flags;
    USHORT CredentialCount;
    USHORT ServiceCredentialCount;
    USHORT OldCredentialCount;
    USHORT OlderCredentialCount;
    UNICODE_STRING32 DefaultSalt;
    ULONG DefaultIterationCount;
    KERB_KEY_DATA32 Credentials[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL32, *PKERB_STORED_CREDENTIAL32;

/// <summary>
/// KERB_STORED_CREDENTIAL32 changed sometime after NT 5.2.
/// KERB_STORED_CREDENTIAL32_OLD is what Microsoft renamed
/// the original structure to. The structure format can
/// be determined at runtime by the revision number.
/// </summary>
typedef struct _KERB_STORED_CREDENTIAL32_OLD {
    USHORT Revision; // Set to 3
    USHORT Flags;
    USHORT CredentialCount;
    USHORT OldCredentialCount;
    UNICODE_STRING32 DefaultSalt;
    KERB_KEY_DATA32_OLD Credentials[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL32_OLD, *PKERB_STORED_CREDENTIAL32_OLD;

typedef struct _KERB_SUPPLEMENTAL_CREDENTIAL {
    ULONG Version;
    ULONG Flags;
    LPVOID CertificateContext;
    ULONG CspDataLength;
    ULONG CspDataOffset;
    ULONG UserNameLength;
    ULONG UserNameOffset;
    ULONG DomainNameLength;
    ULONG DomainNameOffset;
    LUID LogonId;
    ULONG NtlmSuppCredLength;
    ULONG NtlmSuppCredOffset;
#ifdef __cplusplus
    class KerbCredIsoApi* CredIsoObj;
#else
    void* CredIsoObj;
#endif
    ULONG ServiceTicketOffset;
    ULONG ServiceTicketLength;
    ULONG TicketGrantingTicketOffset;
    ULONG TicketGrantingTicketLength;
} KERB_SUPPLEMENTAL_CREDENTIAL, *PKERB_SUPPLEMENTAL_CREDENTIAL;

typedef struct _KERB_TICKET_LOGON_SUPP_CRED {
#ifdef __cplusplus
    class KerbCredIsoApi* CredIsoObj;
#else
    void* CredIsoObj;
#endif
    PBYTE ServiceTicket;
    ULONG ServiceTicketLength;
    PBYTE TicketGrantingTicket;
    ULONG TicketGrantingTicketLength;
} KERB_TICKET_LOGON_SUPP_CRED, *PKERB_TICKET_LOGON_SUPP_CRED;

typedef struct _KERB_TIME_SKEW_ENTRY {
    TimeStamp RequestTime;
    BYTE Skewed;
} KERB_TIME_SKEW_ENTRY, *PKERB_TIME_SKEW_ENTRY;

typedef struct _KERB_TIME_SKEW_STATE {
    TimeStamp LastSync;
    TimeStamp MinimumSyncLapse;
    ULONG SkewThreshold;
    ULONG TotalRequests;
    ULONG SkewedRequests;
    ULONG SuccessRequests;
    ULONG LastRequest;
    LONG ActiveSyncs;
    PKERB_TIME_SKEW_ENTRY SkewEntries;
    RTL_CRITICAL_SECTION Lock;
} KERB_TIME_SKEW_STATE, *PKERB_TIME_SKEW_STATE;

#include <pshpack1.h>
/// <summary>
/// Used to update kerberos's list of addresses. The address count should
/// be the number of addresses and the addresses should be an array of
/// SOCKET_ADDRESS structures.
/// </summary>
typedef struct _KERB_UPDATE_ADDRESSES_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG AddressCount;
    ULONG Addresses[ANYSIZE_ARRAY];
} KERB_UPDATE_ADDRESSES_REQUEST, *PKERB_UPDATE_ADDRESSES_REQUEST;
#include <poppack.h>

typedef struct _KERB_VERIFY_CREDENTIALS_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    UNICODE_STRING UserName;
    UNICODE_STRING DomainName;
    UNICODE_STRING Password;
    ULONG VerifyFlags;
} KERB_VERIFY_CREDENTIALS_REQUEST, *PKERB_VERIFY_CREDENTIALS_REQUEST;

#include <pshpack1.h>
/// <summary>
/// Sent from a workstation to a DC in the workstation's domain to verify
/// that the PAC in a ticket is valid.
/// </summary>
/// <returns>
/// Either no message or the same message with a PAC updated with the local
/// groups from the DC are sent back on success. The message is immediately
/// followed by a checksup and then a signature.
/// </returns>
typedef struct _KERB_VERIFY_PAC_REQUEST {
    KERB_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG ChecksumLength;
    ULONG SignatureType;
    ULONG SignatureLength;
    BYTE ChecksumAndSignature[ANYSIZE_ARRAY];
} KERB_VERIFY_PAC_REQUEST, *PKERB_VERIFY_PAC_REQUEST;
#include <poppack.h>

// AcceptSecurityContext Guid
DEFINE_GUID(/* 94acefe3-9e56-49e3-9895-7240a231c371 */
    KerbAcceptSCGuid,
    0x94acefe3,
    0x9e56,
    0x49e3,
    0x98, 0x95, 0x72, 0x40, 0xa2, 0x31, 0xc3, 0x71);

DEFINE_GUID(/* c55e606b-334a-488b-b907-384abaa97b04 */
    KerbChangePassGuid,
    0xc55e606b,
    0x334a,
    0x488b,
    0xb9, 0x07, 0x38, 0x4a, 0xba, 0xa9, 0x7b, 0x04);

// Control Guid
DEFINE_GUID(/* bba3add2-c229-4cdb-ae2b-57eb6966b0c4 */
    KerbControlGuid,
    0xbba3add2,
    0xc229,
    0x4cdb,
    0xae, 0x2b, 0x57, 0xeb, 0x69, 0x66, 0xb0, 0xc4);

// InitializeSecurityContext Guid
DEFINE_GUID(/* 52e82f1a-7cd4-47ed-b5e5-fde7bf64cea6 */
    KerbInitSCGuid,
    0x52e82f1a,
    0x7cd4,
    0x47ed,
    0xb5, 0xe5, 0xfd, 0xe7, 0xbf, 0x64, 0xce, 0xa6);

// LogonUser Guid
DEFINE_GUID(/* 8a3b8d86-db1e-47a9-9264-146e097b3c64 */
    KerbLogonGuid,
    0x8a3b8d86,
    0xdb1e,
    0x47a9,
    0x92, 0x64, 0x14, 0x6e, 0x09, 0x7b, 0x3c, 0x64);

DEFINE_GUID(/* 94c79108-b23b-4418-9b7f-e6d75a3a0ab2 */
    KerbSetPassGuid,
    0x94c79108,
    0xb23b,
    0x4418,
    0x9b, 0x7f, 0xe6, 0xd7, 0x5a, 0x3a, 0x0a, 0xb2);

#ifdef __cplusplus
} // Closes extern "C" above
namespace Kerberos {
    // Enumerations
    using ACCOUNT_TYPE = _KERB_ACCOUNT_TYPE;
    using CERTIFICATE_INFO_TYPE = _KERB_CERTIFICATE_INFO_TYPE;
    using CONTEXT_STATE = _KERB_CONTEXT_STATE;
    using DEVICE_PKINIT_BEHAVIOR = _KERB_DEVICE_PKINIT_BEHAVIOR;
    using KDC_TYPE = _KERB_KDC_TYPE;
    using KDC_VALIDATION_LEVEL = _KDC_VALIDATION_LEVEL;
    using KERBEROS_MACHINE_ROLE = _KERBEROS_MACHINE_ROLE;
    using KERBEROS_STATE = _KERBEROS_STATE;
    using LOGON_SUBMIT_TYPE = _KERB_LOGON_SUBMIT_TYPE;
    using ODJ_STATE = _KERB_ODJ_STATE;
    using PLAINTEXT_PASSWORD_PROTECTION = _KERB_PLAINTEXT_PASSWORD_PROTECTION;
    using PROFILE_BUFFER_TYPE = _KERB_PROFILE_BUFFER_TYPE;
    using PROTOCOL_MESSAGE_TYPE = _KERB_PROTOCOL_MESSAGE_TYPE;
    using REG_TELEMETRY_FLAG = KERB_REG_TELEMETRY_FLAG;
    using SMARTCARD_CSP_INFO_TYPE = _KERB_SMARTCARD_CSP_INFO_TYPE;
    using STANDALONE_KDC_VALIDATION_LEVEL = _STANDALONE_KDC_VALIDATION_LEVEL;

    // Structures
    using ACCEPTSC_INFO = _KERB_ACCEPTSC_INFO;
    using ADD_BINDING_CACHE_ENTRY_EX_REQUEST = _KERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST;
    using ADD_BINDING_CACHE_ENTRY_REQUEST = _KERB_ADD_BINDING_CACHE_ENTRY_REQUEST;
    using ADD_CREDENTIALS_REQUEST = _KERB_ADD_CREDENTIALS_REQUEST;
    using ADD_CREDENTIALS_REQUEST_EX = _KERB_ADD_CREDENTIALS_REQUEST_EX;
    using ASN1_DATA = _KERB_ASN1_DATA;
    using AUTH_DATA = _KERB_AUTH_DATA;
    using AUTH_PROXY = _KERB_AUTH_PROXY;
    using AUTH_PROXY_CRED = _KERB_AUTH_PROXY_CRED;
    using AUTHEN_HEADER = _KERB_AUTHEN_HEADER;
    using BINDING_CACHE_ENTRY = _KERB_BINDING_CACHE_ENTRY;
    using CERTIFICATE_HASHINFO = _KERB_CERTIFICATE_HASHINFO;
    using CERTIFICATE_INFO = _KERB_CERTIFICATE_INFO;
    using CERTIFICATE_LOGON = _KERB_CERTIFICATE_LOGON;
    using CERTIFICATE_S4U_LOGON = _KERB_CERTIFICATE_S4U_LOGON;
    using CERTIFICATE_UNLOCK_LOGON = _KERB_CERTIFICATE_UNLOCK_LOGON;
    using CHANGE_MACH_PWD_REQUEST = _KERB_CHANGE_MACH_PWD_REQUEST;
    using CHANGE_PASSWORD_KDC_RESPONSE_HEADER = _KERB_CHANGE_PASSWORD_KDC_RESPONSE_HEADER;
    using CHANGE_PASSWORD_RESTRICTIONS_RESPONSE = _KERB_CHANGE_PASSWORD_RESTRICTIONS_RESPONSE;
    using CHANGEPASS_INFO = _KERB_CHANGEPASS_INFO;
    using CHANGEPASSWORD_REQUEST = _KERB_CHANGEPASSWORD_REQUEST;
    using CLEANUP_MACHINE_PKINIT_CREDS_REQUEST = _KERB_CLEANUP_MACHINE_PKINIT_CREDS_REQUEST;
    using CONTEXT = _KERB_CONTEXT;
    using CREDENTIAL = _KERB_CREDENTIAL;
    using CREDMAN_CRED = _KERB_CREDMAN_CRED;
    using CRYPTO_KEY = KERB_CRYPTO_KEY;
    using CRYPTO_KEY_WOW64 = _KERB_CRYPTO_KEY_WOW64;
    using CRYPTO_KEY32 = KERB_CRYPTO_KEY32;
    using DEBUG_REPLY = _KERB_DEBUG_REPLY;
    using DEBUG_REQUEST = _KERB_DEBUG_REQUEST;
    using DEBUG_STATS = _KERB_DEBUG_STATS;
    using DECRYPT_REQUEST = _KERB_DECRYPT_REQUEST;
    using DECRYPT_RESPONSE = _KERB_DECRYPT_RESPONSE;
    using DH_DOMAIN_PARAMETERS = _KERB_DH_DOMAIN_PARAMETERS;
    using DNS_SUFFIX_COMPONENT = _KERB_DNS_SUFFIX_COMPONENT;
    using DNS_SUFFIX_TABLE = _KERB_DNS_SUFFIX_TABLE;
    using DOMAIN_CACHE = _KERB_DOMAIN_CACHE;
    using DOMAIN_CACHE_ENTRY = _KERB_DOMAIN_CACHE_ENTRY;
    using ECC_CURVE_INFO = _KERB_ECC_CURVE_INFO;
    using ENCRYPTION_KEY = _KERB_ENCRYPTION_KEY;
    using ENCRYPTION_KEY32 = _KERB_ENCRYPTION_KEY32;
    using EXTERNAL_NAME = _KERB_EXTERNAL_NAME;
    using EXTERNAL_TICKET = _KERB_EXTERNAL_TICKET;
    using EXTRA_CRED = _KERB_EXTRA_CRED;
    using EXTRA_CRED_LIST = _EXTRA_CRED_LIST;
    using FLAG_MAPPING = _KERB_FLAG_MAPPING;
    using FSO_BINDING_HANDLE = _KERB_FSO_BINDING_HANDLE;
    using FSO_CACHE_ENTRY = _KERB_FSO_CACHE_ENTRY;
    using FSO_COMMON_FUNCTION_TABLE = _KERB_FSO_COMMON_FUNCTION_TABLE;
    using GSS_CHECKSUM = _KERB_GSS_CHECKSUM;
    using GSS_SEAL_SIGNATURE = _KERB_GSS_SEAL_SIGNATURE;
    using GSS_SEAL_SIGNATURE_NEW = _KERB_GSS_SEAL_SIGNATURE_NEW;
    using GSS_SIGNATURE = _KERB_GSS_SIGNATURE;
    using GSS_SIGNATURE_HEADER = _KERB_GSS_SIGNATURE_HEADER;
    using GSS_SIGNATURE_NEW = _KERB_GSS_SIGNATURE_NEW;
    using HOST_TO_REALM_KEY = _HOST_TO_REALM_KEY;
    using INIT_CONTEXT_DATA = _KERB_INIT_CONTEXT_DATA;
    using INITSC_INFO = _KERB_INITSC_INFO;
    using INTERACTIVE_LOGON = _KERB_INTERACTIVE_LOGON;
    using INTERACTIVE_PROFILE = _KERB_INTERACTIVE_PROFILE;
    using INTERACTIVE_UNLOCK_LOGON = _KERB_INTERACTIVE_UNLOCK_LOGON;
    using INTERNAL_NAME = _KERB_INTERNAL_NAME;
    using KDC_CALL_INFO = _KERB_KDC_CALL_INFO;
    using KDC_PROXY = _KERB_KDC_PROXY;
    using KDC_PROXY_CACHE = ::KDC_PROXY_CACHE;
    using KDC_PROXY_CACHE_ENTRY = ::KDC_PROXY_CACHE_ENTRY;
    using KDC_PROXY_CACHE_ENTRY_DATA = ::KDC_PROXY_CACHE_ENTRY_DATA;
    using KERBEROS_LIST = _KERBEROS_LIST;
    using KERBEROS_LIST_ENTRY = _KERBEROS_LIST_ENTRY;
    using KERBEROS_LIST2 = _KERBEROS_LIST2;
    using KEY_AND_CRED = _KERB_KEY_AND_CRED;
    using KEY_DATA = _KERB_KEY_DATA;
    using KEY_DATA_OLD = _KERB_KEY_DATA_OLD;
    using KEY_DATA32 = _KERB_KEY_DATA32;
    using KEY_DATA32_OLD = _KERB_KEY_DATA32_OLD;
    using KPASSWD_REP = _KERB_KPASSWD_REP;
    using KPASSWD_REQ = _KERB_KPASSWD_REQ;
    using LOGON_INFO = _KERB_LOGON_INFO;
    using LOGON_SESSION = _KERB_LOGON_SESSION;
    using LOGON_SESSION_TABLE_ENTRY = _KERB_LOGON_SESSION_TABLE_ENTRY;
    using LOOP_BACK = _KERB_LOOP_BACK;
    using MESSAGE_BUFFER = _KERB_MESSAGE_BUFFER;
    using MIT_REALM = _KERB_MIT_REALM;
    using MIT_SERVER_LIST = _KERB_MIT_SERVER_LIST;
    using NET_ADDRESS = _KERB_NET_ADDRESS;
    using NET_ADDRESSES = _KERB_NET_ADDRESSES;
    using NULL_SIGNATURE = KERB_NULL_SIGNATURE;
    using PACKED_CONTEXT = _KERB_PACKED_CONTEXT;
    using PARSED_DNS_SUFFIX = _KERB_PARSED_DNS_SUFFIX;
    using PIN_KDC_ENTRY = _KERB_PIN_KDC_ENTRY;
    using PLAINTEXT_PASSWORD = _KERB_PLAINTEXT_PASSWORD;
    using PLAINTEXT_PASSWORD_STORAGE = _KERB_PLAINTEXT_PASSWORD_STORAGE;
    using PREAUTH_DATA = _KERB_PREAUTH_DATA;
    using PRIMARY_CREDENTIAL = _KERB_PRIMARY_CREDENTIAL;
    using PROCESS_TABLE_ENTRY = _KERB_PROCESS_TABLE_ENTRY;
    using PROXY_LOGON_CRED = _KERB_PROXY_LOGON_CRED;
    using PROXY_SERVER = _KERB_PROXY_SERVER;
    using PROXY_SERVER_LIST = _KERB_PROXY_SERVER_LIST;
    using PUBLIC_KEY_CREDENTIALS = _KERB_PUBLIC_KEY_CREDENTIALS;
    using PURGE_BINDING_CACHE_REQUEST = _KERB_PURGE_BINDING_CACHE_REQUEST;
    using PURGE_KDC_PROXY_CACHE_REQUEST = _KERB_PURGE_KDC_PROXY_CACHE_REQUEST;
    using PURGE_KDC_PROXY_CACHE_RESPONSE = _KERB_PURGE_KDC_PROXY_CACHE_RESPONSE;
    using PURGE_TKT_CACHE_EX_REQUEST = _KERB_PURGE_TKT_CACHE_EX_REQUEST;
    using PURGE_TKT_CACHE_REQUEST = _KERB_PURGE_TKT_CACHE_REQUEST;
    using QUERY_BINDING_CACHE_REQUEST = _KERB_QUERY_BINDING_CACHE_REQUEST;
    using QUERY_BINDING_CACHE_RESPONSE = _KERB_QUERY_BINDING_CACHE_RESPONSE;
    using QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST = _KERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST;
    using QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE = _KERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE;
    using QUERY_KDC_PROXY_CACHE_REQUEST = _KERB_QUERY_KDC_PROXY_CACHE_REQUEST;
    using QUERY_KDC_PROXY_CACHE_RESPONSE = _KERB_QUERY_KDC_PROXY_CACHE_RESPONSE;
    using QUERY_S4U2PROXY_CACHE_REQUEST = _KERB_QUERY_S4U2PROXY_CACHE_REQUEST;
    using QUERY_S4U2PROXY_CACHE_RESPONSE = _KERB_QUERY_S4U2PROXY_CACHE_RESPONSE;
    using QUERY_SUPPLEMENTAL_CREDS_REQUEST = _KERB_QUERY_SUPPLEMENTAL_CREDS_REQUEST;
    using QUERY_SUPPLEMENTAL_CREDS_RESPONSE = _KERB_QUERY_SUPPLEMENTAL_CREDS_RESPONSE;
    using QUERY_TKT_CACHE_EX_RESPONSE = _KERB_QUERY_TKT_CACHE_EX_RESPONSE;
    using QUERY_TKT_CACHE_EX2_RESPONSE = _KERB_QUERY_TKT_CACHE_EX2_RESPONSE;
    using QUERY_TKT_CACHE_EX3_RESPONSE = _KERB_QUERY_TKT_CACHE_EX3_RESPONSE;
    using QUERY_TKT_CACHE_REQUEST = _KERB_QUERY_TKT_CACHE_REQUEST;
    using QUERY_TKT_CACHE_RESPONSE = _KERB_QUERY_TKT_CACHE_RESPONSE;
    using REFRESH_SCCRED_REQUEST = _KERB_REFRESH_SCCRED_REQUEST;
    using REG_PARAMETER = _KERB_REG_PARAMETER;
    using REPLAY_AUDIT_INFO = _KERB_REPLAY_AUDIT_INFO;
    using RETRIEVE_TKT_REQUEST = _KERB_RETRIEVE_TKT_REQUEST;
    using RETRIEVE_TKT_RESPONSE = _KERB_RETRIEVE_TKT_RESPONSE;
    using RPC_CRYPT_BIT_BLOB = _KERB_RPC_CRYPT_BIT_BLOB;
    using RPC_CRYPTO_API_BLOB = _KERB_RPC_CRYPTO_API_BLOB;
    using RPC_FAST_ARMOR = _KERB_RPC_FAST_ARMOR;
    using RPC_INTERNAL_NAME = _KERB_RPC_INTERNAL_NAME;
    using RPC_OCTET_STRING = _KERB_RPC_OCTET_STRING;
    using RPC_PA_DATA = _KERB_RPC_PA_DATA;
    using S4U_LOGON = _KERB_S4U_LOGON;
    using S4U2PROXY_CACHE = _KERB_S4U2PROXY_CACHE;
    using S4U2PROXY_CACHE_ENTRY = _KERB_S4U2PROXY_CACHE_ENTRY;
    using S4U2PROXY_CACHE_ENTRY_INFO = _KERB_S4U2PROXY_CACHE_ENTRY_INFO;
    using S4U2PROXY_CRED = _KERB_S4U2PROXY_CRED;
    using SESSION_KEY_ENTRY = _KERB_SESSION_KEY_ENTRY;
    using SETPASS_INFO = _KERB_SETPASS_INFO;
    using SETPASSWORD_EX_REQUEST = _KERB_SETPASSWORD_EX_REQUEST;
    using SETPASSWORD_REQUEST = _KERB_SETPASSWORD_REQUEST;
    using SMART_CARD_LOGON = _KERB_SMART_CARD_LOGON;
    using SMART_CARD_PROFILE = _KERB_SMART_CARD_PROFILE;
    using SMART_CARD_UNLOCK_LOGON = _KERB_SMART_CARD_UNLOCK_LOGON;
    using SMARTCARD_CSP_INFO = _KERB_SMARTCARD_CSP_INFO;
    using SPN_CACHE_ENTRY = _KERB_SPN_CACHE_ENTRY;
    using SPN_CACHE_RESULT = _SPN_CACHE_RESULT;
    using STORED_CREDENTIAL = _KERB_STORED_CREDENTIAL;
    using STORED_CREDENTIAL_OLD = _KERB_STORED_CREDENTIAL_OLD;
    using STORED_CREDENTIAL32 = _KERB_STORED_CREDENTIAL32;
    using STORED_CREDENTIAL32_OLD = _KERB_STORED_CREDENTIAL32_OLD;
    using SUBMIT_TKT_REQUEST = _KERB_SUBMIT_TKT_REQUEST;
    using SUPPLEMENTAL_CREDENTIAL = _KERB_SUPPLEMENTAL_CREDENTIAL;
    using TICKET_CACHE = _KERB_TICKET_CACHE;
    using TICKET_CACHE_ENTRY = _KERB_TICKET_CACHE_ENTRY;
    using TICKET_CACHE_INFO = _KERB_TICKET_CACHE_INFO;
    using TICKET_CACHE_INFO_EX = _KERB_TICKET_CACHE_INFO_EX;
    using TICKET_CACHE_INFO_EX2 = _KERB_TICKET_CACHE_INFO_EX2;
    using TICKET_CACHE_INFO_EX3 = _KERB_TICKET_CACHE_INFO_EX3;
    using TICKET_LOGON = _KERB_TICKET_LOGON;
    using TICKET_LOGON_SUPP_CRED = _KERB_TICKET_LOGON_SUPP_CRED;
    using TICKET_PROFILE = _KERB_TICKET_PROFILE;
    using TICKET_UNLOCK_LOGON = _KERB_TICKET_UNLOCK_LOGON;
    using TIME_SKEW_ENTRY = _KERB_TIME_SKEW_ENTRY;
    using TIME_SKEW_STATE = _KERB_TIME_SKEW_STATE;
    using TRANSFER_CRED_REQUEST = _KERB_TRANSFER_CRED_REQUEST;
    using UPDATE_ADDRESSES_REQUEST = _KERB_UPDATE_ADDRESSES_REQUEST;
    using VERIFY_CREDENTIALS_REQUEST = _KERB_VERIFY_CREDENTIALS_REQUEST;
    using VERIFY_PAC_REQUEST = _KERB_VERIFY_PAC_REQUEST;
}
#endif