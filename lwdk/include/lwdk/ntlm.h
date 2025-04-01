// Copyright (C) 2024 Evan McBroom
//
// Nt lan manager (ntlm) protocol and their
// associated in-memory data structures.
//
#pragma once
#include <phnt_windows.h>

#include "lsa.h"

#define NTLMSP_MAX_TOKEN_SIZE  0x770
#define NTLMSP_NAME_A          "NTLM"
#define NTLMSP_NTLM_CREDENTIAL 1 // Supply as GetKeyArgument in call to ACH to indicate that LM is required
#define NTLMSP_RPCID           10 // RPC_C_AUTHN_WINNT

// Maximum lifetime of a context. Was originally 2 minutes (e.g., 120000L),
// but was updated to 5 minutes to allow negotiation in wide-area networks
// with long retry timeouts.
#define NTLMSSP_MAX_LIFETIME      (5 * 60 * 1000)
#define NTLMSSP_SIGN_VERSION      1
#define NTLMSSP_SIGNATURE         "NTLMSSP"
#define NTLMSSP_KEY_SALT          0xBD
#define NTLMSSP_REVISION_W2K3_RC1 10
#define NTLMSSP_REVISION_W2K3     15

// Valid values for the NegotiateFlags member of various NTLM message types
#define NTLMSSP_NEGOTIATE_UNICODE                  0x00000001 // Text strings are in unicode
#define NTLMSSP_NEGOTIATE_OEM                      0x00000002 // Text strings are in OEM
#define NTLMSSP_REQUEST_TARGET                     0x00000004 // Server should return its authentication realm
#define NTLMSSP_NEGOTIATE_SIGN                     0x00000010 // Request signature capability
#define NTLMSSP_NEGOTIATE_SEAL                     0x00000020 // Request confidentiality
#define NTLMSSP_NEGOTIATE_DATAGRAM                 0x00000040 // Use datagram style authentication
#define NTLMSSP_NEGOTIATE_LM_KEY                   0x00000080 // Use LM session key for sign/seal
#define NTLMSSP_NEGOTIATE_NETWARE                  0x00000100 // NetWare authentication
#define NTLMSSP_NEGOTIATE_NTLM                     0x00000200 // NTLM authentication
#define NTLMSSP_NEGOTIATE_NT_ONLY                  0x00000400 // NT authentication only (no LM)
#define NTLMSSP_NEGOTIATE_NULL_SESSION             0x00000800 // NULL Sessions on NT 5.0 and beyand
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      0x00001000 // Domain Name supplied on negotiate
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED 0x00002000 // Workstation Name supplied on negotiate
#define NTLMSSP_NEGOTIATE_LOCAL_CALL               0x00004000 // Indicates client/server are same machine
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN              0x00008000 // Sign for all security levels

// Valid target types returned by the server in NegotiateFlags
#define NTLMSSP_TARGET_TYPE_DOMAIN 0x00010000 // TargetName is a domain name
#define NTLMSSP_TARGET_TYPE_SERVER 0x00020000 // TargetName is a server name
#define NTLMSSP_TARGET_TYPE_SHARE  0x00040000 // TargetName is a share name
#define NTLMSSP_NEGOTIATE_NTLM2    0x00080000 // NTLM2 authentication added for NT4-SP4
#define NTLMSSP_NEGOTIATE_IDENTIFY 0x00100000 // Create identify level token

// Valid requests for additional output buffers
#define NTLMSSP_REQUEST_INIT_RESPONSE      0x00100000 // get back session keys
#define NTLMSSP_REQUEST_ACCEPT_RESPONSE    0x00200000 // get back session key, LUID
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY 0x00400000 // request non-nt session key
#define NTLMSSP_NEGOTIATE_TARGET_INFO      0x00800000 // target info present in challenge message
#define NTLMSSP_NEGOTIATE_EXPORTED_CONTEXT 0x01000000 // It's an exported context
#define NTLMSSP_NEGOTIATE_VERSION          0x02000000 // version control
#define NTLMSSP_NEGOTIATE_128              0x20000000 // negotiate 128 bit encryption
#define NTLMSSP_NEGOTIATE_KEY_EXCH         0x40000000 // exchange a key using key exchange key
#define NTLMSSP_NEGOTIATE_56               0x80000000 // negotiate 56 bit encryption

// Flags used by a client to control signing and sealing
#define NTLMSSP_APP_SEQ 0x0040 // Use the application's provided sequence number

// Signing and sealing constants
#define CSSEALMAGIC "session key to client-to-server sealing key magic constant"
#define SCSEALMAGIC "session key to server-to-client sealing key magic constant"
#define CSSIGNMAGIC "session key to client-to-server signing key magic constant"
#define SCSIGNMAGIC "session key to server-to-client signing key magic constant"

// The valid qop (e.g. security) options
#define QOP_NTLMV2 0x00000001

#ifdef __cplusplus
extern "C" {
#endif

enum _eSignSealOp;
enum NTLM_MESSAGE_TYPE;
enum SSP_CONTEXT_STATE;

struct _AUTHENTICATE_MESSAGE;
struct _CHALLENGE_MESSAGE;
struct _NEGOTIATE_MESSAGE;
struct _NTLM_ACCEPT_RESPONSE;
struct _NTLM_AUTHENTICATE_MESSAGE;
struct _NTLM_CHALLENGE_MESSAGE;
struct _NTLM_CLIENT_CONTEXT;
struct _NTLM_INITIALIZE_RESPONSE;
struct _NTLM_PACKED_CONTEXT;
struct _NTLM_VER_INFO;
struct _NTLMSSP_MESSAGE_SIGNATURE;
struct _NTLMV2_DERIVED_SKEYS;
struct _OLD_AUTHENTICATE_MESSAGE;
struct _OLD_CHALLENGE_MESSAGE;
struct _OLD_NEGOTIATE_MESSAGE;
struct _OLD_NTLM_CLIENT_CONTEXT;
struct _OLD_NTLM_PACKED_CONTEXT;
struct _SSP_CONTEXT;
struct _SSP_CREDENTIAL;
struct _SSP_OPTIONS_ENTRY;
struct _SSP_PROCESSOPTIONS;

typedef enum _eSignSealOp {
    eSign, // MakeSignature is calling
    eVerify, // VerifySignature is calling
    eSeal, // SealMessage is calling
    eUnseal // UnsealMessage is calling
} eSignSealOp;

/// <summary>
/// Members were given a prefix to prevent conflicting type names.
/// </summary>
typedef enum SSP_CONTEXT_STATE {
    NtlmIdleState = 0,
    NtlmNegotiateSentState = 1, // Outbound context only
    NtlmChallengeSentState = 2, // Inbound context only
    NtlmAuthenticateSentState = 3, // Outbound context only
    NtlmAuthenticatedState = 4, // Inbound context only
    NtlmPassedToServiceState = 5 // Outbound context only
} SSP_CONTEXT_STATE;

typedef enum NTLM_MESSAGE_TYPE {
    NtLmNegotiate = 1,
    NtLmChallenge,
    NtLmAuthenticate,
    NtLmUnknown
} NTLM_MESSAGE_TYPE;

/// <summary>
/// Opaque data returned by second call to InitializeSecurityContext.
/// </summary>
typedef struct _AUTHENTICATE_MESSAGE {
    UCHAR Signature[sizeof(NTLMSSP_SIGNATURE)];
    NTLM_MESSAGE_TYPE MessageType;
    STRING32 LmChallengeResponse;
    STRING32 NtChallengeResponse;
    STRING32 DomainName;
    STRING32 UserName;
    STRING32 Workstation;
    STRING32 SessionKey;
    ULONG NegotiateFlags;
    ULONG64 Version;
    UCHAR HandShakeMessagesMIC[16]; // Added after NT 5.2
} AUTHENTICATE_MESSAGE, *PAUTHENTICATE_MESSAGE;

/// <summary>
/// Opaque data returned by first call to AcceptSecurityContext.
/// </summary>
typedef struct _CHALLENGE_MESSAGE {
    UCHAR Signature[sizeof(NTLMSSP_SIGNATURE)];
    NTLM_MESSAGE_TYPE MessageType;
    STRING32 TargetName;
    ULONG NegotiateFlags;
    UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH];
    ULONG64 ServerContextHandle;
    STRING32 TargetInfo;
    ULONG64 Version;
} CHALLENGE_MESSAGE, *PCHALLENGE_MESSAGE;

/// <summary>
/// Opaque data returned by first call to InitializeSecurityContext.
/// </summary>
typedef struct _NEGOTIATE_MESSAGE {
    UCHAR Signature[sizeof(NTLMSSP_SIGNATURE)];
    NTLM_MESSAGE_TYPE MessageType;
    ULONG NegotiateFlags;
    STRING32 OemDomainName;
    STRING32 OemWorkstationName;
    ULONG64 Version;
} NEGOTIATE_MESSAGE, *PNEGOTIATE_MESSAGE;

/// <summary>
/// Non-opaque data returned by second call to AcceptSecurityContext.
/// </summary>
typedef struct _NTLM_ACCEPT_RESPONSE {
    LUID LogonId;
    LARGE_INTEGER KickoffTime;
    ULONG UserFlags;
    UCHAR UserSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR LanmanSessionKey[MSV1_0_LANMAN_SESSION_KEY_LENGTH];
} NTLM_ACCEPT_RESPONSE, *PNTLM_ACCEPT_RESPONSE;

/// <summary>
/// Additional input to AcceptSecurityContext for trusted clients who supply their own challenge to skip the first call to ASC.
/// </summary>
typedef struct _NTLM_AUTHENTICATE_MESSAGE {
    CHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
    ULONG ParameterControl;
} NTLM_AUTHENTICATE_MESSAGE, *PNTLM_AUTHENTICATE_MESSAGE;

/// <summary>
/// Additional input to InitializeSecurityContext for clients supplying a password.
/// </summary>
typedef struct _NTLM_CHALLENGE_MESSAGE {
    UNICODE_STRING32 Password;
    UNICODE_STRING32 UserName;
    UNICODE_STRING32 DomainName;
} NTLM_CHALLENGE_MESSAGE, *PNTLM_CHALLENGE_MESSAGE;

struct _NTLM_CLIENT_CONTEXT {
    union {
        LIST_ENTRY Next;
        KSEC_LIST_ENTRY KernelNext;
    };
    ULONG_PTR LsaContext;
    ULONG NegotiateFlags;
    HANDLE ClientTokenHandle;
    PACCESS_TOKEN AccessToken;
    PULONG pSendNonce;
    PULONG pRecvNonce;
    PHANDLE phSealRc4Key;
    PHANDLE phUnsealRc4Key;
    HANDLE hSealRc4Key;
    HANDLE hUnsealRc4Key;
    ULONG SendNonce;
    ULONG RecvNonce;
    LPWSTR ContextNames;
    PUCHAR pbMarshalledTargetInfo;
    ULONG cbMarshalledTargetInfo;
    UCHAR SessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    ULONG ContextSignature;
    ULONG References;
    TimeStamp PasswordExpiry;
    TimeStamp LogoffTime;
    ULONG UserFlags;
    UCHAR SignSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR VerifySessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR SealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR UnsealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    PBYTE pbMarshalledClientSpecifiedTargetInfo;
    ULONG cbMarshalledClientSpecifiedTargetInfo;
};

/// <summary>
/// Non-opaque data returned by second call to InitializeSecurityContext.
/// </summary>
typedef struct _NTLM_INITIALIZE_RESPONSE {
    UCHAR UserSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR LanmanSessionKey[MSV1_0_LANMAN_SESSION_KEY_LENGTH];
} NTLM_INITIALIZE_RESPONSE, *PNTLM_INITIALIZE_RESPONSE;

typedef struct _NTLM_PACKED_CONTEXT {
    ULONG Tag;
    ULONG NegotiateFlags;
    LONG ClientTokenHandle;
    ULONG SendNonce;
    ULONG RecvNonce;
    UCHAR SessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    ULONG ContextSignature;
    TimeStamp PasswordExpiry;
    TimeStamp LogoffTime;
    ULONG UserFlags;
    ULONG ContextNames;
    ULONG ContextNameLength;
    ULONG MarshalledTargetInfo; // The offset to the data
    ULONG MarshalledTargetInfoLength;
    UCHAR SignSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR VerifySessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR SealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR UnsealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    ULONG MarshalledClientSpecifiedTargetInfo;
    ULONG MarshalledClientSpecifiedTargetInfoLength;
    ULONG SealRc4Key;
    ULONG SealRc4KeyLength;
    ULONG UnsealRc4Key;
    ULONG UnsealRc4KeyLength;
} NTLM_PACKED_CONTEXT, *PNTLM_PACKED_CONTEXT;

typedef struct _NTLM_VER_INFO {
    ULONG64 Major : 8;
    ULONG64 Minor : 8;
    ULONG64 Build : 16;
    ULONG64 Reserved : 24;
    ULONG64 Revision : 8;
} NTLM_VER_INFO, *PNTLM_VER_INFO;

typedef struct _NTLMSSP_MESSAGE_SIGNATURE {
// Version 1 indicates that an RC4 stream is used to encrypt the trailing 12 bytes
#define NTLM_SIGN_VERSION 1
    ULONG Version;
    ULONG RandomPad;
    ULONG CheckSum;
    ULONG Nonce;
} NTLMSSP_MESSAGE_SIGNATURE, *PNTLMSSP_MESSAGE_SIGNATURE;

/// <summary>
/// Defined in Windows sources in rc4.h and included here
/// for its use in multiple structures.
/// </summary>
typedef struct _RC4_KEYSTRUCT {
    unsigned char S[256];
    unsigned char i, j;
} RC4_KEYSTRUCT, *PRC4_KEYSTRUCT;

/// <summary>
/// This structure is not used anymore but is
/// included for older versions of NT.
/// </summary>
typedef struct _NTLMV2_DERIVED_SKEYS {
    ULONG KeyLen; // Length is specified in octets
    ULONG* pSendNonce;
    ULONG* pRecvNonce;
    RC4_KEYSTRUCT pSealRc4Sched; // Key schedule for sealing
    RC4_KEYSTRUCT pUnsealRc4Sched; // Key schedule for unsealing
    ULONG SendNonce;
    ULONG RecvNonce;
    UCHAR SignSessionKey[sizeof(USER_SESSION_KEY)];
    UCHAR VerifySessionKey[sizeof(USER_SESSION_KEY)];
    UCHAR SealSessionKey[sizeof(USER_SESSION_KEY)];
    UCHAR UnsealSessionKey[sizeof(USER_SESSION_KEY)];
    ULONG64 Pad1;
    RC4_KEYSTRUCT SealRc4Sched; // Key for sealing
    ULONG64 Pad2;
    RC4_KEYSTRUCT UnsealRc4Sched; // Key for unsealing
} NTLMV2_DERIVED_SKEYS, *PNTLMV2_DERIVED_SKEYS;

/// <summary>
/// The legacy structure for AUTHENTICATE_MESSAGE.
/// </summary>
typedef struct _OLD_AUTHENTICATE_MESSAGE {
    UCHAR Signature[sizeof(NTLMSSP_SIGNATURE)];
    NTLM_MESSAGE_TYPE MessageType;
    STRING32 LmChallengeResponse;
    STRING32 NtChallengeResponse;
    STRING32 DomainName;
    STRING32 UserName;
    STRING32 Workstation;
} OLD_AUTHENTICATE_MESSAGE, *POLD_AUTHENTICATE_MESSAGE;

/// <summary>
/// The legacy structure for CHALLENGE_MESSAGE.
/// </summary>
typedef struct _OLD_CHALLENGE_MESSAGE {
    UCHAR Signature[sizeof(NTLMSSP_SIGNATURE)];
    NTLM_MESSAGE_TYPE MessageType;
    STRING32 TargetName;
    ULONG NegotiateFlags;
    UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH];
} OLD_CHALLENGE_MESSAGE, *POLD_CHALLENGE_MESSAGE;

/// <summary>
/// The legacy structure for NEGOTIATE_MESSAGE.
/// </summary>
typedef struct _OLD_NEGOTIATE_MESSAGE {
    UCHAR Signature[sizeof(NTLMSSP_SIGNATURE)];
    NTLM_MESSAGE_TYPE MessageType;
    ULONG NegotiateFlags;
} OLD_NEGOTIATE_MESSAGE, *POLD_NEGOTIATE_MESSAGE;

/// <summary>
/// The legacy structure for NTLM_CLIENT_CONTEXT.
/// </summary>
typedef struct _OLD_NTLM_CLIENT_CONTEXT {
    union {
        LIST_ENTRY Next;
        KSEC_LIST_ENTRY KernelNext;
    };
    ULONG_PTR LsaContext;
    ULONG NegotiateFlags;
    HANDLE ClientTokenHandle;
    PACCESS_TOKEN AccessToken;
    PULONG pSendNonce;
    PULONG pRecvNonce;
    PRC4_KEYSTRUCT pSealRc4Sched;
    PRC4_KEYSTRUCT pUnsealRc4Sched;
    ULONG SendNonce;
    ULONG RecvNonce;
    LPWSTR ContextNames;
    PBYTE pbMarshalledTargetInfo;
    ULONG cbMarshalledTargetInfo;
    UCHAR SessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    ULONG ContextSignature;
    ULONG References;
    TimeStamp PasswordExpiry;
    ULONG UserFlags;
    UCHAR SignSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR VerifySessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR SealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR UnsealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    ULONG64 Pad1;
    RC4_KEYSTRUCT SealRc4Sched;
    ULONG64 Pad2;
    RC4_KEYSTRUCT UnsealRc4Sched;
} OLD_NTLM_CLIENT_CONTEXT, *POLD_NTLM_CLIENT_CONTEXT;

/// <summary>
/// The legacy structure for NTLM_PACKED_CONTEXT.
/// </summary>
typedef struct _OLD_NTLM_PACKED_CONTEXT {
    ULONG Tag;
    ULONG NegotiateFlags;
    ULONG ClientTokenHandle;
    ULONG SendNonce;
    ULONG RecvNonce;
    UCHAR SessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    ULONG ContextSignature;
    TimeStamp PasswordExpiry;
    ULONG UserFlags;
    ULONG ContextNames;
    ULONG ContextNameLength;
    ULONG MarshalledTargetInfo;
    ULONG MarshalledTargetInfoLength;
    UCHAR SignSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR VerifySessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR SealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    UCHAR UnsealSessionKey[MSV1_0_USER_SESSION_KEY_LENGTH];
    RC4_KEYSTRUCT SealRc4Sched;
    RC4_KEYSTRUCT UnsealRc4Sched;
} OLD_NTLM_PACKED_CONTEXT, *POLD_NTLM_PACKED_CONTEXT;

typedef struct _SSP_CREDENTIAL {
    LIST_ENTRY Next;
    ULONG References; // Reference tracking for the credential
    ULONG CredentialUseFlags; // SECPKG_CRED_* flags for how the credential may be used
    LUID LogonId; // Logon id of the client
    ULONG ClientProcessID; // Process id of the client
    ULONG CredentialTag; // Indicated if the credential is valid for fast reference
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; // The impersonation level of the caller at time that AcquireCredentialsHandle was called
    // For client contexts, these members act as the default credentials.
    // For server contexts, only UserName should be valid and it should
    // hold a domain\user formatted user name.
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
    BOOLEAN Unlinked; // Was the credential unlinked from the credential list?
    BOOLEAN KernelClient; // Was the credential granted for a user mode caller?
    UCHAR IsPasswordVsmProtected; // Was added after NT 5.2
    // The previous struct member (e.g., IsPasswordVsmProtected) and
    // all of the following members were added after NT 5.2
#define SSP_CREDENTIAL_FLAG_WAS_NETWORK_SERVICE 0x1
    ULONG MutableCredFlags;
    PLSA_TOKEN_INFO_HEADER TokenRestrictions;
    LPVOID ClientToken;
    LUID ModifiedId;
    UNICODE_STRING SavedDomainName;
    UNICODE_STRING SavedUserName;
    UNICODE_STRING SavedPassword;
} SSP_CREDENTIAL, *PSSP_CREDENTIAL;

typedef struct _SSP_CONTEXT {
    LIST_ENTRY ListEntry; // Added after NT 5.2
#define SSP_CONTEXT_TAG_ACTIVE    (ULONG64)('AxtC')
#define SSP_CONTEXT_TAG_DELETE    (ULONG64)('DxtC')
#define SSP_CREDENTIAL_TAG_ACTIVE (ULONG)('AdrC')
#define SSP_CREDENTIAL_TAG_DELETE (ULONG)('DdrC')
    ULONG64 ContextTag;
    ULONG TickStart; // Used to timeout the context after a period of time.
    LARGE_INTEGER StartTime;
    ULONG Interval;
    ULONG References; // Reference tracking for the context
    ULONG NegotiateFlags; // The Negotiated protocol
    ULONG ContextFlags; // The context requirements
    ULONG ContextAttributes; // Added after NT 5.2
    LARGE_INTEGER ExpirationTime; // Added after NT 5.2
    SSP_CONTEXT_STATE State; // State of the context
    HANDLE TokenHandle; // Token handle of the authenticated user. // Only valid when State == AuthenticatedState
    PSSP_CREDENTIAL Credential; // The credential used to create this context
    UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH]; // The challenge the server sent the client. // Only valid when State == ChallengeSentState
    UCHAR SessionKey[MSV1_0_USER_SESSION_KEY_LENGTH]; // The session key that LSA calculated.
    // Default credentials.
    UNICODE_STRING DomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
    PCREDENTIAL_TARGET_INFORMATIONW TargetInfo; // Optional, marshalled info for credman
    PBYTE pbMarshalledTargetInfo; // Marshalled info for dfs/rdr
    ULONG cbMarshalledTargetInfo;
    ULONG_PTR ServerContextHandle; // Used to validate loopback operations
    ULONG ClientProcessID;
    NTSTATUS LastStatus;
    BOOLEAN Server; // Is this a client or server context?
    BOOLEAN DownLevel; // Context is for a downlevel server?
    BOOLEAN KernelClient; // Was the context granted for a kernel mode client?
    union {
        NTLM_VER_INFO ClientVersion; // Used in server contexts
        NTLM_VER_INFO ServerVersion; // Used in client contexts
    };
    CHAR ContextMagicNumber[MSV1_0_USER_SESSION_KEY_LENGTH];
    // The remainder of the members were added after NT 5.2
    LONG IsLoopbackAllowed;
    LONG CheckForLocal;
    LONG IsPasswordVsmProtected;
    UNICODE_STRING TargetName;
    SecBuffer MappedContexData;
    ULONG Attributes;
    LARGE_INTEGER TimeStamp;
    PUCHAR NegotiateMessage;
    ULONG NegotiateMessageSize;
    PUCHAR ChallengeMessage;
    ULONG ChallengeMessageSize;
    PUCHAR pbMarshalledClientSpecifiedTargetInfo;
    ULONG cbMarshalledClientSpecifiedTargetInfo;
} SSP_CONTEXT, *PSSP_CONTEXT;

/// <summary>
/// The legacy data structure for tracking process options.
/// </summary>
typedef struct _SSP_PROCESSOPTIONS {
    LIST_ENTRY Next;
    ULONG ClientProcessID;
    ULONG ProcessOptions;
} SSP_PROCESSOPTIONS, *PSSP_PROCESSOPTIONS;

/// <summary>
/// The new data structure for tacking process and thread options
/// This structure was likely introduced in NT 6.2 due to it being
/// the first release that allowed software to set thread options.
/// </summary>
typedef struct _SSP_OPTIONS_ENTRY {
    LIST_ENTRY List;
    ULONG ProcessId;
    ULONG ThreadId;
    LONG ProcessWide;
    ULONG EnabledOptions;
    ULONG DisabledOptions;
} SSP_OPTIONS_ENTRY, *PSSP_OPTIONS_ENTRY;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Ntlm {
    // Enumerations
    using MESSAGE_TYPE = NTLM_MESSAGE_TYPE;
    using SignSealOp = _eSignSealOp;
    using SSP_CONTEXT_STATE = ::SSP_CONTEXT_STATE;

    using AUTHENTICATE_MESSAGE = _AUTHENTICATE_MESSAGE;
    using CHALLENGE_MESSAGE = _CHALLENGE_MESSAGE;
    using NEGOTIATE_MESSAGE = _NEGOTIATE_MESSAGE;
    using NTLM_ACCEPT_RESPONSE = _NTLM_ACCEPT_RESPONSE;
    using NTLM_AUTHENTICATE_MESSAGE = _NTLM_AUTHENTICATE_MESSAGE;
    using NTLM_CHALLENGE_MESSAGE = _NTLM_CHALLENGE_MESSAGE;
    using NTLM_CLIENT_CONTEXT = _NTLM_CLIENT_CONTEXT;
    using NTLM_INITIALIZE_RESPONSE = _NTLM_INITIALIZE_RESPONSE;
    using NTLM_PACKED_CONTEXT = _NTLM_PACKED_CONTEXT;
    using NTLM_VER_INFO = _NTLM_VER_INFO;
    using NTLMSSP_MESSAGE_SIGNATURE = _NTLMSSP_MESSAGE_SIGNATURE;
    using NTLMV2_DERIVED_SKEYS = _NTLMV2_DERIVED_SKEYS;
    using OLD_AUTHENTICATE_MESSAGE = _OLD_AUTHENTICATE_MESSAGE;
    using OLD_CHALLENGE_MESSAGE = _OLD_CHALLENGE_MESSAGE;
    using OLD_NEGOTIATE_MESSAGE = _OLD_NEGOTIATE_MESSAGE;
    using OLD_NTLM_CLIENT_CONTEXT = _OLD_NTLM_CLIENT_CONTEXT;
    using OLD_NTLM_PACKED_CONTEXT = _OLD_NTLM_PACKED_CONTEXT;
    using RC4_KEYSTRUCT = ::RC4_KEYSTRUCT;
    using SSP_CONTEXT = _SSP_CONTEXT;
    using SSP_CREDENTIAL = _SSP_CREDENTIAL;
    using SSP_OPTIONS_ENTRY = _SSP_OPTIONS_ENTRY;
    using SSP_PROCESSOPTIONS = _SSP_PROCESSOPTIONS;
}
#endif