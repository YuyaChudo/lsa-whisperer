// Copyright (C) 2024 Evan McBroom
//
// Microsoft authentication package version 1.0 (msv1_0)
//
// Although much of the msv1_0 macros and types are defined in the SDK's
// um headers, the km headers have additional definitions. These are defined
// in ntifs.h following the 'end_ntsecapi' comment. These definitions are
// included here for convenience so the lwdk does not depend on kernel headers.
//
#pragma once
#include <phnt_windows.h>

#define SECURITY_WIN32
#include "um/ntsecapi.h"

#include "crypt.h"

// Macros that are not present in the SDK
#define MSV1_0_NTLMV2_OWF_LENGTH      16
#define MSV1_0_NTLMV2_RESPONSE_LENGTH 16

#ifdef __cplusplus
extern "C" {
#endif

enum _LM_PROTOCOL_SUPPORT;
enum _MSV1_0_CACHE_SUPPLEMENTAL_TYPE;
enum _MSV1_0_GETSTRONGCREDKEY_REQUEST_TYPE;
enum ELogonTypeSubType;
enum MSV1_0_DPAPI_KEY_TYPE;
struct _CREDENTIAL_KEY_HELPER;
struct _MSV1_0_CACHE_LOGON_REQUEST;
struct _MSV1_0_CACHE_LOGON_REQUEST_OLD;
struct _MSV1_0_CACHE_LOGON_REQUEST_W2K;
struct _MSV1_0_CACHE_LOOKUP_REQUEST;
struct _MSV1_0_CACHE_LOOKUP_RESPONSE;
struct _MSV1_0_CACHE_SUPPLEMENTAL_DATA;
struct _MSV1_0_CACHE_SUPPLEMENTAL_ENTRY;
struct _MSV1_0_CHANGEPASSWORD_REQUEST_WOW64;
struct _MSV1_0_CHANGEPASSWORD_RESPONSE_WOW64;
struct _MSV1_0_CLEAR_CACHED_CREDENTIALS_REQUEST;
struct _MSV1_0_CONFIG_LOCAL_ALIASES_REQUEST;
struct _MSV1_0_CONFIG_LOCAL_ALIASES_RESPONSE;
struct _MSV1_0_DECRYPTDPAPIMK_REQUEST;
struct _MSV1_0_DECRYPTDPAPIMK_RESPONSE;
struct _MSV1_0_DERIVECRED_REQUEST;
struct _MSV1_0_DERIVECRED_RESPONSE;
struct _MSV1_0_ENUMUSERS_REQUEST;
struct _MSV1_0_ENUMUSERS_RESPONSE;
struct _MSV1_0_ENUMUSERS_RESPONSE_WOW64;
struct _MSV1_0_GETCHALLENRESP_REQUEST;
struct _MSV1_0_GETCHALLENRESP_REQUEST_V1;
struct _MSV1_0_GETCHALLENRESP_RESPONSE;
struct _MSV1_0_GETCREDKEY_REQUEST;
struct _MSV1_0_GETCREDKEY_RESPONSE;
struct _MSV1_0_GETSTRONGCREDKEY_REQUEST;
struct _MSV1_0_GETSTRONGCREDKEY_RESPONSE;
struct _MSV1_0_GETUSERINFO_REQUEST;
struct _MSV1_0_GETUSERINFO_RESPONSE;
struct _MSV1_0_GETUSERINFO_RESPONSE_WOW64;
struct _MSV1_0_INTERACTIVE_LOGON_WOW64;
struct _MSV1_0_INTERACTIVE_PROFILE_WOW64;
struct _MSV1_0_LM20_CHALLENGE_REQUEST;
struct _MSV1_0_LM20_CHALLENGE_RESPONSE;
struct _MSV1_0_LM20_LOGON_PROFILE_WOW64;
struct _MSV1_0_LM20_LOGON_WOW64;
struct _MSV1_0_LOOKUP_TOKEN_REQUEST;
struct _MSV1_0_LOOKUP_TOKEN_RESPONSE;
struct _MSV1_0_NTLMV2_RESPONSE;
struct _MSV1_0_PRIMARY_CREDENTIAL;
struct _MSV1_0_PRIMARY_CREDENTIAL_OLD;
struct _MSV1_0_PRIMARY_CREDENTIAL_XP;
struct _MSV1_0_PROVISION_TBAL_REQUEST;
struct _MSV1_0_RELOGON_REQUEST;
struct _MSV1_0_REMOTE_ENCRYPTED_SECRETS;
struct _MSV1_0_REMOTE_PLAINTEXT_SECRETS;
struct _MSV1_0_S4U_LOGON_WOW64;
struct _MSV1_0_SECRETS;
struct _MSV1_0_SECRETS_WRAPPER;
struct _MSV1_0_SECRETS_WRAPPER_1507;
struct _MSV1_0_SECRETS_WRAPPER_1511;
struct _MSV1_0_SERIALIZED_TBAL_CREDENTIAL_V0;
struct _MSV1_0_SETPROCESSOPTION_REQUEST;
struct _MSV1_0_SETTHREADOPTION_REQUEST;
struct _MSV1_0_SUPPLEMENTAL_CREDENTIAL_INT;
struct _MSV1_0_VALIDATE_LOGON_REPLY;
struct _MSV1_0_VALIDATE_LOGON_REQUEST;
struct _MSV1_0_VALIDATION_INFO;
struct _MSV1_0_VERIFY_TARGET_REQUEST;
struct MSV1_0_LM3_RESPONSE;
union _MSV1_0_SECRETS_U;

typedef enum _LM_PROTOCOL_SUPPORT {
    UseLm,
    AllowLm,
    NoLm,
    UseNtlm3,
    RefuseLm,
    RefuseNtlm,
    RefuseNtlm3NoTarget
} LM_PROTOCOL_SUPPORT,
    *PLM_PROTOCOL_SUPPORT;

typedef enum _MSV1_0_CACHE_SUPPLEMENTAL_TYPE {
    MsV1_0CacheSupplementalSmartcard = 0,
    MsV1_0CacheSupplementalClaims = 1,
} MSV1_0_CACHE_SUPPLEMENTAL_TYPE,
    *PMSV1_0_CACHE_SUPPLEMENTAL_TYPE;

typedef enum _MSV1_0_GETSTRONGCREDKEY_REQUEST_TYPE {
    MSV1_0_GETSTRONGCREDKEY_USE_LOGON_ID = 0,
    MSV1_0_GETSTRONGCREDKEY_USE_SOURCE_BUFFER = 1,
} MSV1_0_GETSTRONGCREDKEY_REQUEST_TYPE,
    *PMSV1_0_GETSTRONGCREDKEY_REQUEST_TYPE;

typedef enum ELogonTypeSubType {
    kNetworkLogonInvalid,
    kNetworkLogonNtlmv1,
    kNetworkLogonNtlmv2,
    kSubAuthLogon,
} ELogonTypeSubType,
    *PELogonTypeSubType;

typedef enum MSV1_0_DPAPI_KEY_TYPE {
    MSV1_0_DPAPI_KEY_TYPE_NTOWF = 0,
    MSV1_0_DPAPI_KEY_TYPE_SHA = 1,
} MSV1_0_DPAPI_KEY_TYPE,
    *PMSV1_0_DPAPI_KEY_TYPE;

typedef struct _CREDENTIAL_KEY_HELPER {
    MSV1_0_CREDENTIAL_KEY LocalUserKey;
    MSV1_0_CREDENTIAL_KEY DomainUserKey;
} CREDENTIAL_KEY_HELPER, *PCREDENTIAL_KEY_HELPER;

typedef struct _MSV1_0_CACHE_LOGON_REQUEST_OLD {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PVOID LogonInformation;
    PVOID ValidationInformation;
} MSV1_0_CACHE_LOGON_REQUEST_OLD, *PMSV1_0_CACHE_LOGON_REQUEST_OLD;

typedef struct _MSV1_0_CACHE_LOGON_REQUEST_W2K {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PVOID LogonInformation;
    PVOID ValidationInformation;
    PVOID SupplementalCacheData;
    ULONG SupplementalCacheDataLength;
} MSV1_0_CACHE_LOGON_REQUEST_W2K, *PMSV1_0_CACHE_LOGON_REQUEST_W2K;

typedef struct _MSV1_0_CACHE_LOGON_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PVOID LogonInformation;
    PVOID ValidationInformation;
    PVOID SupplementalCacheData;
    ULONG SupplementalCacheDataLength;
#define MSV1_0_CACHE_LOGON_REQUEST_MIT_LOGON      0x00000001
#define MSV1_0_CACHE_LOGON_REQUEST_INFO4          0x00000002
#define MSV1_0_CACHE_LOGON_DELETE_ENTRY           0x00000004
#define MSV1_0_CACHE_LOGON_REQUEST_SMARTCARD_ONLY 0x00000008
    ULONG RequestFlags;
} MSV1_0_CACHE_LOGON_REQUEST, *PMSV1_0_CACHE_LOGON_REQUEST;

/// <summary>
/// Used for both MsV1_0CacheLookup and MsV1_0CacheLookupEx requests.
/// </summary>
typedef struct _MSV1_0_CACHE_LOOKUP_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    UNICODE_STRING UserName;
    UNICODE_STRING DomainName;
#define MSV1_0_CACHE_LOOKUP_CREDTYPE_NONE  0
#define MSV1_0_CACHE_LOOKUP_CREDTYPE_RAW   1 // Used for public-key smart card data
#define MSV1_0_CACHE_LOOKUP_CREDTYPE_NTOWF 2
    ULONG CredentialType;
    ULONG CredentialInfoLength;
    UCHAR CredentialSubmitBuffer[ANYSIZE_ARRAY]; // Included data of size CredentialInfoLength
} MSV1_0_CACHE_LOOKUP_REQUEST, *PMSV1_0_CACHE_LOOKUP_REQUEST;

/// <summary>
/// Used for both MsV1_0CacheLookup and MsV1_0CacheLookupEx responses.
/// </summary>
typedef struct _MSV1_0_CACHE_LOOKUP_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PVOID ValidationInformation;
    PVOID SupplementalCacheData;
    ULONG SupplementalCacheDataLength;
} MSV1_0_CACHE_LOOKUP_RESPONSE, *PMSV1_0_CACHE_LOOKUP_RESPONSE;

typedef struct _MSV1_0_CACHE_SUPPLEMENTAL_ENTRY {
    MSV1_0_CACHE_SUPPLEMENTAL_TYPE Type;
    ULONG Offset;
    ULONG Length;
} MSV1_0_CACHE_SUPPLEMENTAL_ENTRY, *PMSV1_0_CACHE_SUPPLEMENTAL_ENTRY;

typedef struct _MSV1_0_CACHE_SUPPLEMENTAL_DATA {
    ULONGLONG Magic;
    ULONG EntryCount;
    MSV1_0_CACHE_SUPPLEMENTAL_ENTRY Entries[ANYSIZE_ARRAY];
} MSV1_0_CACHE_SUPPLEMENTAL_DATA, *PMSV1_0_CACHE_SUPPLEMENTAL_DATA;

typedef struct _MSV1_0_CHANGEPASSWORD_REQUEST_WOW64 {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    STRING32 DomainName;
    STRING32 AccountName;
    STRING32 OldPassword;
    STRING32 NewPassword;
    BOOLEAN Impersonating;
} MSV1_0_CHANGEPASSWORD_REQUEST_WOW64, *PMSV1_0_CHANGEPASSWORD_REQUEST_WOW64;

typedef struct _MSV1_0_CHANGEPASSWORD_RESPONSE_WOW64 {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    BOOLEAN PasswordInfoValid;
    DOMAIN_PASSWORD_INFORMATION DomainPasswordInfo;
} MSV1_0_CHANGEPASSWORD_RESPONSE_WOW64, *PMSV1_0_CHANGEPASSWORD_RESPONSE_WOW64;

typedef struct _MSV1_0_CLEAR_CACHED_CREDENTIALS_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG Flags;
} MSV1_0_CLEAR_CACHED_CREDENTIALS_REQUEST, *PMSV1_0_CLEAR_CACHED_CREDENTIALS_REQUEST;

typedef struct _MSV1_0_CONFIG_LOCAL_ALIASES_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG Flags;
    UNICODE_STRING Alias;
} MSV1_0_CONFIG_LOCAL_ALIASES_REQUEST, *PMSV1_0_CONFIG_LOCAL_ALIASES_REQUEST;

typedef struct _MSV1_0_CONFIG_LOCAL_ALIASES_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    UNICODE_STRING MultszAliases;
} MSV1_0_CONFIG_LOCAL_ALIASES_RESPONSE, *PMSV1_0_CONFIG_LOCAL_ALIASES_RESPONSE;

typedef struct _MSV1_0_DECRYPTDPAPIMK_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    MSV1_0_DPAPI_KEY_TYPE KeyType; // Used in NtlmCredIsoInProc::DecryptDpapiMasterKey
    LUID LogonId;
    ULONG SaltLength;
    PBYTE Salt;
    ULONG EncryptedMasterKeyLength;
    PBYTE EncryptedMasterKey;
    BYTE KeyId[32];
} MSV1_0_DECRYPTDPAPIMK_REQUEST, *PMSV1_0_DECRYPTDPAPIMK_REQUEST;

typedef struct _MSV1_0_DECRYPTDPAPIMK_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG DecryptedMasterKeyLength;
    BYTE DecryptedMasterKey[ANYSIZE_ARRAY];
} MSV1_0_DECRYPTDPAPIMK_RESPONSE, *PMSV1_0_DECRYPTDPAPIMK_RESPONSE;

typedef struct _MSV1_0_DERIVECRED_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
// Defined and naming based on manual auditing
#define MSV1_0_DERIVE_SHA1   0
#define MSV1_0_DERIVE_SHA1V2 1
    ULONG DeriveCredType;
    ULONG DeriveCredInfoLength;
    BYTE DeriveCredSubmitBuffer[ANYSIZE_ARRAY];
} MSV1_0_DERIVECRED_REQUEST, *PMSV1_0_DERIVECRED_REQUEST;

typedef struct _MSV1_0_DERIVECRED_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG DeriveCredInfoLength;
    PBYTE DeriveCredReturnBuffer[ANYSIZE_ARRAY];
} MSV1_0_DERIVECRED_RESPONSE, *PMSV1_0_DERIVECRED_RESPONSE;

typedef struct _MSV1_0_ENUMUSERS_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
} MSV1_0_ENUMUSERS_REQUEST, *PMSV1_0_ENUMUSERS_REQUEST;

typedef struct _MSV1_0_ENUMUSERS_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG NumberOfLoggedOnUsers;
    PLUID LogonIds;
    PULONG EnumHandles;
} MSV1_0_ENUMUSERS_RESPONSE, *PMSV1_0_ENUMUSERS_RESPONSE;

typedef struct _MSV1_0_ENUMUSERS_RESPONSE_WOW64 {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG NumberOfLoggedOnUsers;
    PLUID LogonIds;
    PULONG EnumHandles;
} MSV1_0_ENUMUSERS_RESPONSE_WOW64, *PMSV1_0_ENUMUSERS_RESPONSE_WOW64;

typedef struct _MSV1_0_GETCHALLENRESP_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
#define USE_PRIMARY_PASSWORD            0x01
#define RETURN_PRIMARY_USERNAME         0x02
#define RETURN_PRIMARY_LOGON_DOMAINNAME 0x02
#define RETURN_NON_NT_USER_SESSION_KEY  0x08
#define GENERATE_CLIENT_CHALLENGE       0x10
#define GCR_NTLM3_PARMS                 0x20
#define GCR_TARGET_INFO                 0x40 // ServerName field should contains target info AV pairs
#define RETURN_RESERVED_PARAMETER       0x80 // Previously 0x10
#define GCR_ALLOW_NTLM                  0x100 // Allow the use of NTLM
#define GCR_USE_OEM_SET                 0x200 // Response will use oem character set
#define GCR_MACHINE_CREDENTIAL          0x400
#define GCR_USE_OWF_PASSWORD            0x800 // Use owf passwords
// Windows Server XP SP2 and above
#define GCR_ALLOW_LM        0x1000 // Allow the use of LM
#define GCR_ALLOW_NO_TARGET 0x2000 // Allow no target server or target domain name
// Windows 10 and above
#define GCR_VSM_PROTECTED_PASSWORD 0x4000 // Password is VSM protected
    ULONG ParameterControl;
    LUID LogonId;
    UNICODE_STRING Password;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
    // Remaining members are only present if ParameterControl includes GCR_NTLM3_PARMS (0x20)
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING ServerName; // Server domain or target info AV pairs
} MSV1_0_GETCHALLENRESP_REQUEST, *PMSV1_0_GETCHALLENRESP_REQUEST;

/// <summary>
// Version 1 of the GETCHALLENRESP structure, which was used by RAS and other
// hosts. Compiled before the additional fields whereadded to GETCHALLENRESP_REQUEST.
// Defined here to (and in ntifs.h) allow sizing operations for backwards compatibility.
/// </summary>
typedef struct _MSV1_0_GETCHALLENRESP_REQUEST_V1 {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG ParameterControl;
    LUID LogonId;
    UNICODE_STRING Password;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
} MSV1_0_GETCHALLENRESP_REQUEST_V1, *PMSV1_0_GETCHALLENRESP_REQUEST_V1;

typedef struct _MSV1_0_GETCHALLENRESP_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    STRING CaseSensitiveChallengeResponse;
    STRING CaseInsensitiveChallengeResponse;
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UCHAR UserSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR LanmanSessionKey[MSV1_0_LANMAN_SESSION_KEY_LENGTH];
} MSV1_0_GETCHALLENRESP_RESPONSE, *PMSV1_0_GETCHALLENRESP_RESPONSE;

typedef struct _MSV1_0_GETCREDKEY_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
    GUID KeyId;
} MSV1_0_GETCREDKEY_REQUEST, *PMSV1_0_GETCREDKEY_REQUEST;

/// <summary>
/// May be used for both MsV1_0GetCredentialKey and MsV1_0GetStrongCredentialKey responses
/// </summary>
typedef struct _MSV1_0_GETCREDKEY_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    GUID KeyId;
    ULONG CredKeyLength; // sizeof(CREDENTIAL_KEY_HELPER) (currently 0x28)
    BYTE CredKeyReturnBuffer[ANYSIZE_ARRAY]; // Formatted as a CREDENTIAL_KEY_HELPER
} MSV1_0_GETCREDKEY_RESPONSE, *PMSV1_0_GETCREDKEY_RESPONSE;

typedef struct _MSV1_0_GETSTRONGCREDKEY_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    MSV1_0_GETSTRONGCREDKEY_REQUEST_TYPE RequestType; // Specifies the mode of operation
    // Used in MSV1_0_GETSTRONGCREDKEY_USE_LOGON_ID requests
    BYTE KeyId[32]; // Ignored
    LUID LogonId;
    // Used in MSV1_0_GETSTRONGCREDKEY_USE_SOURCE_BUFFER requests
    LSA_CREDENTIAL_KEY_SOURCE_TYPE SourceType; // Must be eFromClearPassword or eFromNtOwf
    ULONG SourceBufferSize;
    PBYTE SourceBuffer; // The clear password or NtOwf hash
    ULONG UserSidSize;
    PBYTE UserSid; // Used to lookup the account type to
    ULONG Flags; // Set to 1 to specify a protected user. Determined from lsasrv!LsapGetStrongCredentialKeyFromMSV
} MSV1_0_GETSTRONGCREDKEY_REQUEST, *PMSV1_0_GETSTRONGCREDKEY_REQUEST;

/// <summary>
/// The same structure as MSV1_0_GETCREDKEY_RESPONSE, but only
/// one key will be returned in the CredKeyReturnBuffer member
/// depending on if the logon session is for a local account
/// or a domain account.
/// </summary>
typedef struct _MSV1_0_GETSTRONGCREDKEY_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    GUID KeyId;
    ULONG CredKeyLength;
    BYTE CredKeyReturnBuffer[ANYSIZE_ARRAY];
} MSV1_0_GETSTRONGCREDKEY_RESPONSE, *PMSV1_0_GETSTRONGCREDKEY_RESPONSE;

typedef struct _MSV1_0_GETUSERINFO_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
} MSV1_0_GETUSERINFO_REQUEST, *PMSV1_0_GETUSERINFO_REQUEST;

typedef struct _MSV1_0_GETUSERINFO_RESPONSE_WOW64 {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PSID UserSid;
    STRING32 UserName;
    STRING32 LogonDomainName;
    STRING32 LogonServer;
    SECURITY_LOGON_TYPE LogonType;
} MSV1_0_GETUSERINFO_RESPONSE_WOW64, *PMSV1_0_GETUSERINFO_RESPONSE_WOW64;

typedef struct _MSV1_0_GETUSERINFO_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    PSID UserSid;
    UNICODE_STRING UserName;
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING LogonServer;
    SECURITY_LOGON_TYPE LogonType;
} MSV1_0_GETUSERINFO_RESPONSE, *PMSV1_0_GETUSERINFO_RESPONSE;

typedef struct _MSV1_0_INTERACTIVE_LOGON_WOW64 {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    STRING32 LogonDomainName;
    STRING32 UserName;
    STRING32 Password;
} MSV1_0_INTERACTIVE_LOGON_WOW64, *PMSV1_0_INTERACTIVE_LOGON_WOW64;

typedef struct _MSV1_0_INTERACTIVE_PROFILE_WOW64 {
    MSV1_0_PROFILE_BUFFER_TYPE MessageType;
    USHORT LogonCount;
    USHORT BadPasswordCount;
    TimeStamp LogonTime;
    TimeStamp LogoffTime;
    TimeStamp KickOffTime;
    TimeStamp PasswordLastSet;
    TimeStamp PasswordCanChange;
    TimeStamp PasswordMustChange;
    STRING32 LogonScript;
    STRING32 HomeDirectory;
    STRING32 FullName;
    STRING32 ProfilePath;
    STRING32 HomeDirectoryDrive;
    STRING32 LogonServer;
    ULONG UserFlags;
} MSV1_0_INTERACTIVE_PROFILE_WOW64, *PMSV1_0_INTERACTIVE_PROFILE_WOW64;

typedef struct _MSV1_0_LM20_CHALLENGE_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
} MSV1_0_LM20_CHALLENGE_REQUEST, *PMSV1_0_LM20_CHALLENGE_REQUEST;

typedef struct _MSV1_0_LM20_CHALLENGE_RESPONSE {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    BYTE ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
} MSV1_0_LM20_CHALLENGE_RESPONSE, *PMSV1_0_LM20_CHALLENGE_RESPONSE;

typedef struct _MSV1_0_LM20_LOGON_PROFILE_WOW64 {
    MSV1_0_PROFILE_BUFFER_TYPE MessageType;
    TimeStamp KickOffTime;
    TimeStamp LogoffTime;
    ULONG UserFlags;
    UCHAR UserSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    STRING32 LogonDomainName;
    UCHAR LanmanSessionKey[MSV1_0_LANMAN_SESSION_KEY_LENGTH];
    STRING32 LogonServer;
    STRING32 UserParameters;
} MSV1_0_LM20_LOGON_PROFILE_WOW64, *PMSV1_0_LM20_LOGON_PROFILE_WOW64;

typedef struct _MSV1_0_LM20_LOGON_WOW64 {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    STRING32 LogonDomainName;
    STRING32 UserName;
    STRING32 Workstation;
    UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
    STRING32 CaseSensitiveChallengeResponse;
    STRING32 CaseInsensitiveChallengeResponse;
    ULONG ParameterControl;
} MSV1_0_LM20_LOGON_WOW64, *PMSV1_0_LM20_LOGON_WOW64;

typedef struct _MSV1_0_LOOKUP_TOKEN_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
} MSV1_0_LOOKUP_TOKEN_REQUEST, *PMSV1_0_LOOKUP_TOKEN_REQUEST;

typedef struct _MSV1_0_LOOKUP_TOKEN_RESPONSE {
    ULONG TokenHandle;
} MSV1_0_LOOKUP_TOKEN_RESPONSE, *PMSV1_0_LOOKUP_TOKEN_RESPONSE;

/// <summary>
/// This is the structure of the NTLMv2 response which is sent by clients in
/// the NtChallengeResponse member of the NETLOGON_NETWORK_INFO type. The
/// intended method for differentiating it from from NTLMv1 responses was by
/// its length to allow it to pass though servers which do not understand
/// NTLMv2 but will pass responses of arbitrary length.
/// </summary>
typedef struct _MSV1_0_NTLMV2_RESPONSE {
    UCHAR Response[MSV1_0_NTLMV2_RESPONSE_LENGTH]; // Hash of OWF password and all of the following members
    UCHAR RespType; // The response id number (ids start at 1)
    UCHAR HiRespType; // The highest id number the client will understand
    USHORT Flags; // Reserved and must be set to zero
    ULONG MsgWord; // A 32 bit message sent by the client to the server which is used by the authentication protocol
    TimeStamp TimeStamp; // When the client generated the response, which is sources from the NT system time
    UCHAR ChallengeFromClient[MSV1_0_CHALLENGE_LENGTH];
    ULONG AvPairsOff; // Offset to the start of the AvPairs
    UCHAR Buffer[ANYSIZE_ARRAY]; // The buffer containing the AV pairs
} MSV1_0_NTLMV2_RESPONSE, *PMSV1_0_NTLMV2_RESPONSE;

typedef struct _MSV1_0_SECRETS {
    LM_OWF_PASSWORD NtOwfPassword;
    LM_OWF_PASSWORD LmOwfPassword;
    SHA_OWF_PASSWORD ShaOwfPassword;
} MSV1_0_SECRETS, *PMSV1_0_SECRETS;

#ifdef __cplusplus
class NtlmCredIsoApi;
#else
    #define NtlmCredIsoApi VOID;
#endif

typedef union _MSV1_0_SECRETS_U {
    MSV1_0_SECRETS Clear;
    BYTE Encrypted[180];
} MSV1_0_SECRETS_U, *PMSV1_0_SECRETS_U;

/// <summary>
/// The last known change of MSV1_0_SECRETS_WRAPPER is in NT 10
/// 1607 which introduced the a credential isolotation API
/// pointer and credential key management to the type definition.
///
/// Microsoft's choice to use the BOOLEAN (e.g. BYTE) type for
/// structure members which act as flags instead of a bit field
/// causes additional padding after CredentialKeyPresent. It
/// should be noted the the offsets of structure members will
/// maintain the same if Microsoft decides in the future to add
/// 1-3 additional flags (assuming no other structure changes)
/// but the will change due to packing if 4 or more are added.
/// </summary>
typedef struct _MSV1_0_SECRETS_WRAPPER {
    NtlmCredIsoApi* CredIsoObj;
    BOOLEAN IsEncrypted;
    BOOLEAN NtPasswordPresent;
    BOOLEAN LmPasswordPresent;
    BOOLEAN ShaPasswordPresent;
    BOOLEAN CredentialKeyPresent;
    MSV1_0_CREDENTIAL_KEY_TYPE CredentialKeyType;
    USHORT EncryptedSize;
    MSV1_0_CREDENTIAL_KEY CredentialKeySecret;
    MSV1_0_SECRETS_U Secrets;
} MSV1_0_SECRETS_WRAPPER, *PMSV1_0_SECRETS_WRAPPER;

#include <pshpack1.h>
/// <summary>
/// MSV1_0_SECRETS_WRAPPER was included with the first release of
/// NT 10 (e.g. 1507). The structure is largely documented by Benjamin
/// Delpy in Mimikatz with 2 unaccounted bytes. These bytes have
/// been named here as EncryptedSize, due to its use in the current
/// definition of MSV1_0_SECRETS_WRAPPER and it being the most likely
/// use of the field.
///
/// It should also be noted that the structure's fields are not at the
/// default packing boundaries for MSVC which can be explained by
/// Microsoft having used a 1 byte packing for this type in 1507. It
/// is possible that Microsoft used 1 byte packing for other or all
/// types defined in the same header in 10 1507, but an audit for
/// such packing discrepancies for 10 1507 has not been done.
/// </summary>
typedef struct _MSV1_0_SECRETS_WRAPPER_1507 {
    BOOLEAN IsEncrypted;
    BOOLEAN NtPasswordPresent;
    BOOLEAN LmPasswordPresent;
    BOOLEAN ShaPasswordPresent;
    USHORT EncryptedSize;
    MSV1_0_SECRETS_U Secrets;
} MSV1_0_SECRETS_WRAPPER_1507, *PMSV1_0_SECRETS_WRAPPER_1507;
#include <poppack.h>

/// <summary>
/// MSV1_0_SECRETS_WRAPPER's definition in 10 1511 is the same
/// as its definition in NT 10 1507 but with Microsoft's removal
/// of the 1 byte packing to allow type members to align at
/// their normal boundaries for MSVC.
/// </summary>
typedef struct _MSV1_0_SECRETS_WRAPPER_1511 {
    BOOLEAN IsEncrypted;
    BOOLEAN NtPasswordPresent;
    BOOLEAN LmPasswordPresent;
    BOOLEAN ShaPasswordPresent;
    USHORT EncryptedSize;
    MSV1_0_SECRETS_U Secrets;
} MSV1_0_SECRETS_WRAPPER_1511, *PMSV1_0_SECRETS_WRAPPER_1511;

/// <summary>
/// This type has only change in XP (e.g., in either NT 5.1 or 5.2)
/// and in NT 10 and the following is its current form.
/// </summary>
typedef struct _MSV1_0_PRIMARY_CREDENTIAL {
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    MSV1_0_SECRETS_WRAPPER SecretsWrapper;
} MSV1_0_PRIMARY_CREDENTIAL, *PMSV1_0_PRIMARY_CREDENTIAL;

/// <summary>
/// This is the structure of primary credentials prior to its
/// change for Windows XP (e.g., in either NT 5.1 or 5.2). The
/// following structure existed as far back as NT 4.0, but likely
/// existed since its introduction to Windows.
/// </summary>
typedef struct _MSV1_0_PRIMARY_CREDENTIAL_OLD {
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    NT_OWF_PASSWORD NtOwfPassword;
    LM_OWF_PASSWORD LmOwfPassword;
    BOOLEAN NtPasswordPresent;
    BOOLEAN LmPasswordPresent;
} MSV1_0_PRIMARY_CREDENTIAL_OLD, *PMSV1_0_PRIMARY_CREDENTIAL_OLD;

/// <summary>
/// This is the structure of primary credentials from Windows
/// XP to its current form in NT 10. The exact time of its change
/// from its original form this this has not been determined yet,
/// but occured in either NT 5.1 or 5.2.
/// </summary>
typedef struct _MSV1_0_PRIMARY_CREDENTIAL_XP {
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    NT_OWF_PASSWORD NtOwfPassword;
    LM_OWF_PASSWORD LmOwfPassword;
    SHA_OWF_PASSWORD ShaOwfPassword;
    BOOLEAN NtPasswordPresent;
    BOOLEAN LmPasswordPresent;
    BOOLEAN ShaPasswordPresent;
} MSV1_0_PRIMARY_CREDENTIAL_XP, *PMSV1_0_PRIMARY_CREDENTIAL_XP;

typedef struct _MSV1_0_PROVISION_TBAL_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    LUID LogonId;
} MSV1_0_PROVISION_TBAL_REQUEST, *PMSV1_0_PROVISION_TBAL_REQUEST;

typedef struct _MSV1_0_RELOGON_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    UNICODE_STRING LogonServer;
} MSV1_0_RELOGON_REQUEST, *PMSV1_0_RELOGON_REQUEST;

typedef struct _MSV1_0_REMOTE_ENCRYPTED_SECRETS {
    BOOLEAN NtPasswordPresent;
    BOOLEAN LmPasswordPresent;
    BOOLEAN ShaPasswordPresent;
    MSV1_0_CREDENTIAL_KEY_TYPE CredentialKeyType;
    MSV1_0_CREDENTIAL_KEY CredentialKeySecret;
    ULONG EncryptedSize;
    PBYTE EncryptedSecrets;
} MSV1_0_REMOTE_ENCRYPTED_SECRETS, *PMSV1_0_REMOTE_ENCRYPTED_SECRETS;

typedef struct _MSV1_0_REMOTE_PLAINTEXT_SECRETS {
    BOOLEAN NtPasswordPresent;
    BOOLEAN LmPasswordPresent;
    BOOLEAN ShaPasswordPresent;
    MSV1_0_CREDENTIAL_KEY_TYPE CredentialKeyType;
    MSV1_0_CREDENTIAL_KEY CredentialKeySecret;
    LM_OWF_PASSWORD NtOwfPassword;
    LM_OWF_PASSWORD LmOwfPassword;
    SHA_OWF_PASSWORD ShaOwfPassword;
} MSV1_0_REMOTE_PLAINTEXT_SECRETS, *PMSV1_0_REMOTE_PLAINTEXT_SECRETS;

typedef struct _MSV1_0_S4U_LOGON_WOW64 {
    MSV1_0_LOGON_SUBMIT_TYPE MessageType;
    ULONG Flags;
    STRING32 UserPrincipalName;
    STRING32 DomainName;
} MSV1_0_S4U_LOGON_WOW64, *PMSV1_0_S4U_LOGON_WOW64;

typedef struct _MSV1_0_SERIALIZED_TBAL_CREDENTIAL_V0 {
    ULONG Version;
    ULONG Length;
    ULONG Flags;
    MSV1_0_CREDENTIAL_KEY_TYPE CredentialKeyType;
    LM_OWF_PASSWORD NtOwfPassword;
    LM_OWF_PASSWORD LmOwfPassword;
    SHA_OWF_PASSWORD ShaOwfPassword;
    MSV1_0_CREDENTIAL_KEY CredentialKey;
    ULONG LogonDomainNameOffset;
    USHORT LogonDomainNameLength;
    USHORT LogonDomainNameMaximumLength;
    ULONG UserNameOffset;
    USHORT UserNameLength;
    USHORT UserNameMaximumLength;
} MSV1_0_SERIALIZED_TBAL_CREDENTIAL_V0, *PMSV1_0_SERIALIZED_TBAL_CREDENTIAL_V0;

typedef struct _MSV1_0_SETPROCESSOPTION_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
#define MSV1_0_PROCESSOPTION_ALLOW_BLANK_PASSWORD  0x01
#define MSV1_0_PROCESSOPTION_DISABLE_ADMIN_LOCKOUT 0x02
#define MSV1_0_PROCESSOPTION_DISABLE_FORCE_GUEST   0x04
#define MSV1_0_PROCESSOPTION_ALLOW_OLD_PASSWORD    0x08
#define MSV1_0_PROCESSOPTION_TRY_CACHE_FIRST       0x10
    ULONG ProcessOptions;
    BOOLEAN DisableOptions;
} MSV1_0_SETPROCESSOPTION_REQUEST, *PMSV1_0_SETPROCESSOPTION_REQUEST;

typedef struct _MSV1_0_SETTHREADOPTION_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    ULONG ThreadOptions;
    BOOLEAN DisableOptions;
    BOOLEAN Revert;
} MSV1_0_SETTHREADOPTION_REQUEST, *PMSV1_0_SETTHREADOPTION_REQUEST;

typedef struct _MSV1_0_SUPPLEMENTAL_CREDENTIAL_INT {
    ULONG Version;
    ULONG Flags;
    ULONG FlagsInt;
    BYTE LmPassword[LM_OWF_PASSWORD_LENGTH];
    BYTE NtPassword[NT_OWF_PASSWORD_LENGTH];
    BYTE ShaPassword[SHA_OWF_PASSWORD_LENGTH];
} MSV1_0_SUPPLEMENTAL_CREDENTIAL_INT, *PMSV1_0_SUPPLEMENTAL_CREDENTIAL_INT;

typedef struct _MSV1_0_VALIDATE_LOGON_REPLY {
    LPVOID ValidationInformation;
    BOOLEAN Authoritative;
    BOOLEAN BadPasswordCountZeroed;
} MSV1_0_VALIDATE_LOGON_REPLY, *PMSV1_0_VALIDATE_LOGON_REPLY;

typedef struct _MSV1_0_VALIDATE_LOGON_REQUEST {
    MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
    HANDLE DomainHandle;
    BOOLEAN UasCompatibilityRequired;
    ULONG SecureChannelType;
    PUNICODE_STRING LogonServer;
    PUNICODE_STRING LogonDomainName;
    LPVOID LogonDomainId;
    ULONG LogonLevel;
    LPVOID LogonInfo;
    ULONG ValidationLevel;
    ULONG AccountsToTry;
} MSV1_0_VALIDATE_LOGON_REQUEST, *PMSV1_0_VALIDATE_LOGON_REQUEST;

typedef struct _MSV1_0_VALIDATION_INFO {
    TimeStamp LogoffTime;
    TimeStamp KickoffTime;
    UNICODE_STRING LogonServer;
    UNICODE_STRING LogonDomainName;
    USER_SESSION_KEY SessionKey;
    BOOLEAN Authoritative;
    ULONG UserFlags;
    ULONG WhichFields;
    ULONG UserId;
} MSV1_0_VALIDATION_INFO, *PMSV1_0_VALIDATION_INFO;

typedef struct _MSV1_0_VERIFY_TARGET_REQUEST {
    ULONG LogonLevel;
    LPVOID LogonInfo;
} MSV1_0_VERIFY_TARGET_REQUEST, *PMSV1_0_VERIFY_TARGET_REQUEST;

/// <summary>
/// The following type shares the same structure as its predecessor,
/// MSV1_0_LMV2_RESPONSE. MSV1_0_LMV2_RESPONSE is no longer used in
/// Microsoft sources and has been replaced by MSV1_0_LM3_RESPONSE.
/// </summary>
typedef struct MSV1_0_LM3_RESPONSE {
    UCHAR Response[MSV1_0_NTLM3_RESPONSE_LENGTH];
    UCHAR ChallengeFromClient[MSV1_0_CHALLENGE_LENGTH];
} MSV1_0_LM3_RESPONSE, *PMSV1_0_LM3_RESPONSE, MSV1_0_LMV2_RESPONSE, *PMSV1_0_LMV2_RESPONSE;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Msv1_0 {
    // Enumerations
    using AVID = ::MSV1_0_AVID;
    using CACHE_SUPPLEMENTAL_TYPE = ::_MSV1_0_CACHE_SUPPLEMENTAL_TYPE;
    using CREDENTIAL_KEY_TYPE = ::_MSV1_0_CREDENTIAL_KEY_TYPE;
    using DPAPI_KEY_TYPE = ::MSV1_0_DPAPI_KEY_TYPE;
    using ELogonTypeSubType = ::ELogonTypeSubType;
    using GETSTRONGCREDKEY_REQUEST_TYPE = ::_MSV1_0_GETSTRONGCREDKEY_REQUEST_TYPE;
    using LM_PROTOCOL_SUPPORT = ::_LM_PROTOCOL_SUPPORT;
    using LOGON_SUBMIT_TYPE = ::_MSV1_0_LOGON_SUBMIT_TYPE;
    using PROFILE_BUFFER_TYPE = ::_MSV1_0_PROFILE_BUFFER_TYPE;
    using PROTOCOL_MESSAGE_TYPE = ::_MSV1_0_PROTOCOL_MESSAGE_TYPE;

    using AV_PAIR = ::_MSV1_0_AV_PAIR;
    using CACHE_LOGON_REQUEST = ::_MSV1_0_CACHE_LOGON_REQUEST;
    using CACHE_LOGON_REQUEST_OLD = ::_MSV1_0_CACHE_LOGON_REQUEST_OLD;
    using CACHE_LOGON_REQUEST_W2K = ::_MSV1_0_CACHE_LOGON_REQUEST_W2K;
    using CACHE_LOOKUP_REQUEST = ::_MSV1_0_CACHE_LOOKUP_REQUEST;
    using CACHE_LOOKUP_RESPONSE = ::_MSV1_0_CACHE_LOOKUP_RESPONSE;
    using CACHE_SUPPLEMENTAL_DATA = ::_MSV1_0_CACHE_SUPPLEMENTAL_DATA;
    using CACHE_SUPPLEMENTAL_ENTRY = ::_MSV1_0_CACHE_SUPPLEMENTAL_ENTRY;
    using CHANGEPASSWORD_REQUEST = ::_MSV1_0_CHANGEPASSWORD_REQUEST;
    using CHANGEPASSWORD_REQUEST_WOW64 = ::_MSV1_0_CHANGEPASSWORD_REQUEST_WOW64;
    using CHANGEPASSWORD_RESPONSE = ::_MSV1_0_CHANGEPASSWORD_RESPONSE;
    using CHANGEPASSWORD_RESPONSE_WOW64 = ::_MSV1_0_CHANGEPASSWORD_RESPONSE_WOW64;
    using CLEAR_CACHED_CREDENTIALS_REQUEST = ::_MSV1_0_CLEAR_CACHED_CREDENTIALS_REQUEST;
    using CONFIG_LOCAL_ALIASES_REQUEST = ::_MSV1_0_CONFIG_LOCAL_ALIASES_REQUEST;
    using CONFIG_LOCAL_ALIASES_RESPONSE = ::_MSV1_0_CONFIG_LOCAL_ALIASES_RESPONSE;
    using CREDENTIAL_KEY = ::_MSV1_0_CREDENTIAL_KEY;
    using CREDENTIAL_KEY_HELPER = ::_CREDENTIAL_KEY_HELPER;
    using DECRYPTDPAPIMK_REQUEST = ::_MSV1_0_DECRYPTDPAPIMK_REQUEST;
    using DECRYPTDPAPIMK_RESPONSE = ::_MSV1_0_DECRYPTDPAPIMK_RESPONSE;
    using DERIVECRED_REQUEST = ::_MSV1_0_DERIVECRED_REQUEST;
    using DERIVECRED_RESPONSE = ::_MSV1_0_DERIVECRED_RESPONSE;
    using ENUMUSERS_REQUEST = ::_MSV1_0_ENUMUSERS_REQUEST;
    using ENUMUSERS_RESPONSE = ::_MSV1_0_ENUMUSERS_RESPONSE;
    using ENUMUSERS_RESPONSE_WOW64 = ::_MSV1_0_ENUMUSERS_RESPONSE_WOW64;
    using GETCHALLENRESP_REQUEST = ::_MSV1_0_GETCHALLENRESP_REQUEST;
    using GETCHALLENRESP_REQUEST_V1 = ::_MSV1_0_GETCHALLENRESP_REQUEST_V1;
    using GETCHALLENRESP_RESPONSE = ::_MSV1_0_GETCHALLENRESP_RESPONSE;
    using GETCREDKEY_REQUEST = ::_MSV1_0_GETCREDKEY_REQUEST;
    using GETCREDKEY_RESPONSE = ::_MSV1_0_GETCREDKEY_RESPONSE;
    using GETSTRONGCREDKEY_REQUEST = ::_MSV1_0_GETSTRONGCREDKEY_REQUEST;
    using GETSTRONGCREDKEY_RESPONSE = ::_MSV1_0_GETSTRONGCREDKEY_RESPONSE;
    using GETUSERINFO_REQUEST = ::_MSV1_0_GETUSERINFO_REQUEST;
    using GETUSERINFO_RESPONSE = ::_MSV1_0_GETUSERINFO_RESPONSE;
    using GETUSERINFO_RESPONSE_WOW64 = ::_MSV1_0_GETUSERINFO_RESPONSE_WOW64;
    using INTERACTIVE_LOGON = ::_MSV1_0_INTERACTIVE_LOGON;
    using INTERACTIVE_LOGON_WOW64 = ::_MSV1_0_INTERACTIVE_LOGON_WOW64;
    using INTERACTIVE_PROFILE = ::_MSV1_0_INTERACTIVE_PROFILE;
    using INTERACTIVE_PROFILE_WOW64 = ::_MSV1_0_INTERACTIVE_PROFILE_WOW64;
    using IUM_SUPPLEMENTAL_CREDENTIAL = ::_MSV1_0_IUM_SUPPLEMENTAL_CREDENTIAL;
    using LM20_CHALLENGE_REQUEST = ::_MSV1_0_LM20_CHALLENGE_REQUEST;
    using LM20_CHALLENGE_RESPONSE = ::_MSV1_0_LM20_CHALLENGE_RESPONSE;
    using LM20_LOGON = ::_MSV1_0_LM20_LOGON;
    using LM20_LOGON_PROFILE = ::_MSV1_0_LM20_LOGON_PROFILE;
    using LM20_LOGON_PROFILE_WOW64 = ::_MSV1_0_LM20_LOGON_PROFILE_WOW64;
    using LM20_LOGON_WOW64 = ::_MSV1_0_LM20_LOGON_WOW64;
    using LM3_RESPONSE = ::MSV1_0_LM3_RESPONSE;
    using LOOKUP_TOKEN_REQUEST = ::_MSV1_0_LOOKUP_TOKEN_REQUEST;
    using LOOKUP_TOKEN_RESPONSE = ::_MSV1_0_LOOKUP_TOKEN_RESPONSE;
    using NTLM3_RESPONSE = ::_MSV1_0_NTLM3_RESPONSE;
    using PASSTHROUGH_REQUEST = ::_MSV1_0_PASSTHROUGH_REQUEST;
    using PASSTHROUGH_RESPONSE = ::_MSV1_0_PASSTHROUGH_RESPONSE;
    using PRIMARY_CREDENTIAL = ::_MSV1_0_PRIMARY_CREDENTIAL;
    using PRIMARY_CREDENTIAL_OLD = ::_MSV1_0_PRIMARY_CREDENTIAL_OLD;
    using PRIMARY_CREDENTIAL_XP = ::_MSV1_0_PRIMARY_CREDENTIAL_XP;
    using PROVISION_TBAL_REQUEST = ::_MSV1_0_PROVISION_TBAL_REQUEST;
    using RELOGON_REQUEST = ::_MSV1_0_RELOGON_REQUEST;
    using REMOTE_ENCRYPTED_SECRETS = ::_MSV1_0_REMOTE_ENCRYPTED_SECRETS;
    using REMOTE_PLAINTEXT_SECRETS = ::_MSV1_0_REMOTE_PLAINTEXT_SECRETS;
    using REMOTE_SUPPLEMENTAL_CREDENTIAL = ::_MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL;
    using S4U_LOGON = ::_MSV1_0_S4U_LOGON;
    using S4U_LOGON_WOW64 = ::_MSV1_0_S4U_LOGON_WOW64;
    using SECRETS = ::_MSV1_0_SECRETS;
    using SECRETS_WRAPPER = ::_MSV1_0_SECRETS_WRAPPER;
    using SECRETS_WRAPPER_1507 = _MSV1_0_SECRETS_WRAPPER_1507;
    using SECRETS_WRAPPER_1511 = _MSV1_0_SECRETS_WRAPPER_1511;
    using SERIALIZED_TBAL_CREDENTIAL_V0 = ::_MSV1_0_SERIALIZED_TBAL_CREDENTIAL_V0;
    using SETPROCESSOPTION_REQUEST = ::_MSV1_0_SETPROCESSOPTION_REQUEST;
    using SETTHREADOPTION_REQUEST = ::_MSV1_0_SETTHREADOPTION_REQUEST;
    using SUBAUTH_LOGON = ::_MSV1_0_SUBAUTH_LOGON;
    using SUBAUTH_REQUEST = ::_MSV1_0_SUBAUTH_REQUEST;
    using SUBAUTH_RESPONSE = ::_MSV1_0_SUBAUTH_RESPONSE;
    using SUPPLEMENTAL_CREDENTIAL = ::_MSV1_0_SUPPLEMENTAL_CREDENTIAL;
    using SUPPLEMENTAL_CREDENTIAL_INT = ::_MSV1_0_SUPPLEMENTAL_CREDENTIAL_INT;
    using SUPPLEMENTAL_CREDENTIAL_V2 = ::_MSV1_0_SUPPLEMENTAL_CREDENTIAL_V2;
    using SUPPLEMENTAL_CREDENTIAL_V3 = ::_MSV1_0_SUPPLEMENTAL_CREDENTIAL_V3;
    using VALIDATE_LOGON_REPLY = ::_MSV1_0_VALIDATE_LOGON_REPLY;
    using VALIDATE_LOGON_REQUEST = ::_MSV1_0_VALIDATE_LOGON_REQUEST;
    using VALIDATION_INFO = ::_MSV1_0_VALIDATION_INFO;
    using VERIFY_TARGET_REQUEST = ::_MSV1_0_VERIFY_TARGET_REQUEST;

    // Unions
    using SECRETS_U = ::_MSV1_0_SECRETS_U;
}
#endif