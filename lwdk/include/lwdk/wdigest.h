// Copyright (C) 2024 Evan McBroom
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

#include <wdigest.h>
#include <wincrypt.h>

#define VERIFY_DIGEST_MESSAGE          0x1a
#define VERIFY_DIGEST_MESSAGE_RESPONSE 0x0a

#define MD5_HASH_BYTESIZE             16 // MD5 hash size
#define MD5_HASH_HEX_SIZE             (2 * MD5_HASH_BYTESIZE) // BYTES needed to store a Hash as hex Encoded
#define PARAMETER_EXPIRESLEEPINTERVAL 900000 // Garbage collection interval for expired contexts in milliseconds, 15 minutes
#define PARAMETER_LIFETIME            (36000) // Nonce lifetime, 10 hours
#define PARAMETER_MAXCTXTCOUNT        30000
#define WDIGEST_CONTEXT_SIGNATURE     'TSGD'

// Pre-calculated digest hashes stored on a DC as supplimental credentals
// Format: '1' 0 version numhashes 0 0 0 0 0 0 0 0 0 0 0 0
// Hashes 21-29 are fixed realms (FREALM) to STR_DIGEST_DOMAIN
#define NUMPRECALC_HEADERS   29
#define SUPPCREDS_CNTLOC     3
#define SUPPCREDS_VERSION    1
#define SUPPCREDS_VERSIONLOC 2
#define TOTALPRECALC_HEADERS (NUMPRECALC_HEADERS + 1)
// Hash identifiers
#define NAME_HEADER               0
#define NAME_ACCT                 1
#define NAME_ACCT_DOWNCASE        2
#define NAME_ACCT_UPCASE          3
#define NAME_ACCT_DUCASE          4
#define NAME_ACCT_UDCASE          5
#define NAME_ACCT_NUCASE          6
#define NAME_ACCT_NDCASE          7
#define NAME_ACCTDNS              8
#define NAME_ACCTDNS_DOWNCASE     9
#define NAME_ACCTDNS_UPCASE       10
#define NAME_ACCTDNS_DUCASE       11
#define NAME_ACCTDNS_UDCASE       12
#define NAME_ACCTDNS_NUCASE       13
#define NAME_ACCTDNS_NDCASE       14
#define NAME_UPN                  15
#define NAME_UPN_DOWNCASE         16
#define NAME_UPN_UPCASE           17
#define NAME_NT4                  18
#define NAME_NT4_DOWNCASE         19
#define NAME_NT4_UPCASE           20
#define NAME_ACCT_FREALM          21
#define NAME_ACCT_FREALM_DOWNCASE 22
#define NAME_ACCT_FREALM_UPCASE   23
#define NAME_UPN_FREALM           24
#define NAME_UPN_FREALM_DOWNCASE  25
#define NAME_UPN_FREALM_UPCASE    26
#define NAME_NT4_FREALM           27
#define NAME_NT4_FREALM_DOWNCASE  28
#define NAME_NT4_FREALM_UPCASE    29

#ifdef __cplusplus
extern "C" {
#endif

enum _NTDIGEST_STATE;
enum ALGORITHM_TYPE;
enum CHARSET_TYPE;
enum CIPHER_TYPE;
enum DIGEST_TYPE;
enum DIGESTMODE_TYPE;
enum MD5_AUTH_NAME;
enum NAMEFORMAT_TYPE;
enum QOP_TYPE;

struct _DIGEST_BLOB_REQUEST;
struct _DIGEST_BLOB_RESPONSE;
struct _DIGEST_CONTEXT;
struct _DIGEST_CREDENTIAL;
struct _DIGEST_HASHED_DIRS_INFO;
struct _DIGEST_LOGONSESSION;
struct _DIGEST_PACKED_USERCONTEXT;
struct _DIGEST_PARAMETER;
struct _DIGEST_USERCONTEXT;
struct _PLAINTEXTBLOB;
struct _USER_CREDENTIALS;

// Only defined to allow other types to reference a pointer to the class.
typedef struct _SSI_STORE* PSSI_STORE;

typedef enum _NTDIGEST_STATE {
    NtDigestLsaMode = 1,
    NtDigestUserMode = 2,
} NTDIGEST_STATE,
    *PNTDIGEST_STATE;

typedef enum ALGORITHM_TYPE {
    ALGORITHM_UNDEFINED = 0,
    NO_ALGORITHM_SPECIFIED = 1,
    MD5 = 2,
    MD5_SESS = 3,
} ALGORITHM_TYPE,
    *PALGORITHM_TYPE;

typedef enum CHARSET_TYPE {
    CHARSET_UNDEFINED = 0,
    ISO_8859_1 = 1,
    UTF_8 = 2,
    UTF_8_SUBSET = 3,
} CHARSET_TYPE,
    *PCHARSET_TYPE;

typedef enum DIGEST_TYPE {
    DIGEST_UNDEFINED = 0,
    NO_DIGEST_SPECIFIED = 1,
    DIGEST_CLIENT = 2,
    DIGEST_SERVER = 3,
    SASL_SERVER = 4,
    SASL_CLIENT = 5,
} DIGEST_TYPE,
    *PDIGEST_TYPE;

typedef enum DIGESTMODE_TYPE {
    DIGESTMODE_UNDEFINED = 0,
    DIGESTMODE_HTTP = 1,
    DIGESTMODE_SASL = 2,
} DIGESTMODE_TYPE,
    *PDIGESTMODE_TYPE;

typedef enum MD5_AUTH_NAME {
    MD5_AUTH_USERNAME = 0,
    MD5_AUTH_REALM = 1,
    MD5_AUTH_NONCE = 2,
    MD5_AUTH_CNONCE = 3,
    MD5_AUTH_NC = 4,
    MD5_AUTH_ALGORITHM = 5,
    MD5_AUTH_QOP = 6,
    MD5_AUTH_METHOD = 7,
    MD5_AUTH_URI = 8,
    MD5_AUTH_RESPONSE = 9,
    MD5_AUTH_HENTITY = 10,
    MD5_AUTH_AUTHZID = 11,
    MD5_AUTH_DOMAIN = 12,
    MD5_AUTH_STALE = 13,
    MD5_AUTH_OPAQUE = 14,
    MD5_AUTH_MAXBUF = 15,
    MD5_AUTH_CHARSET = 16,
    MD5_AUTH_CIPHER = 17,
    MD5_AUTH_DIGESTURI = 18,
    MD5_AUTH_RSPAUTH = 19,
    MD5_AUTH_NEXTNONCE = 20,
    MD5_AUTH_HASHEDDIRS = 21,
    MD5_AUTH_SERVICENAME = 22,
    MD5_AUTH_CHANNELBINDING = 23,
    MD5_AUTH_LAST = 24,
} MD5_AUTH_NAME,
    *PMD5_AUTH_NAME;

typedef enum NAMEFORMAT_TYPE {
    NAMEFORMAT_UNKNOWN = 0,
    NAMEFORMAT_ACCOUNTNAME = 1,
    NAMEFORMAT_UPN = 2,
    NAMEFORMAT_NETBIOS = 3,
} NAMEFORMAT_TYPE,
    *PNAMEFORMAT_TYPE;

typedef enum QOP_TYPE {
    QOP_UNDEFINED = 0,
    NO_QOP_SPECIFIED = 1,
    AUTH = 2,
    AUTH_INT = 3,
    AUTH_CONF = 4,
} QOP_TYPE,
    *PQOP_TYPE;

/// <summary>
/// Originally called _DIGEST_BLOB_REQUEST.
/// </summary>
typedef struct _DIGEST_BLOB_REQUEST {
    ULONG MessageType;
    USHORT version;
    USHORT cbBlobSize;
    USHORT digest_type;
    USHORT qop_type;
    USHORT alg_type;
    USHORT charset_type;
    USHORT cbCharValues;
    USHORT name_format;
#define FLAG_CRACKNAME_ON_DC         0x00000001 // Name in Username & Realm needs to be processed on DC
#define FLAG_AUTHZID_PROVIDED        0x00000002
#define FLAG_SERVERS_DOMAIN          0x00000004 // Indicate on Server's DC (first hop from server) so expand group membership
#define FLAG_NOBS_DECODE             0x00000008 // if set to one, the wire communication is done without backslash encoding
#define FLAG_BS_ENCODE_CLIENT_BROKEN 0x00000010 // set to TRUE if backslash encoding is possibly boken on client
#define FLAG_QUOTE_QOP               0x00000020 // set according to the context if quote the QOP - client side only
    USHORT usFlags;
    USHORT cbAccountName;
    USHORT cbCrackedDomain;
    USHORT cbWorkstation;
    USHORT ulReserved3;
    ULONG64 pad1;
    CHAR cCharValues; // dummy char to mark start of field-values
} DIGEST_BLOB_REQUEST, *PDIGEST_BLOB_REQUEST;

/// <summary>
/// Originally called _DIGEST_BLOB_RESPONSE.
/// Followed by the authentication data (a PAC) and a NetBIOS name.
/// </summary>
typedef struct _DIGEST_BLOB_RESPONSE {
    ULONG MessageType;
    USHORT version;
    NTSTATUS Status; // If the authentication was successfull
    USHORT SessionKeyMaxLength;
    ULONG ulAuthDataSize;
    USHORT usAcctNameSize; // Size of the NetBIOS name after AuthData
    USHORT ulReserved1;
    ULONG ulBlobSize;
    ULONG ulReserved3;
    BYTE SessionKey[MD5_HASH_HEX_SIZE + 1]; // MD5 asciihexdfs
    ULONG64 pad1;
    CHAR cAuthData; // PAC for the user
    // Place group info here for LogonUser
} DIGEST_BLOB_RESPONSE, *PDIGEST_BLOB_RESPONSE;

typedef struct _DIGEST_CONTEXT {
    LIST_ENTRY Next;
    LONG lReferences; // In NT 5.2 and prior, this member was located immediately after ContextHandle
    ULONG_PTR ContextHandle;
    BOOL bUnlinked;
    ULONG ContextReq;
    ULONG ulFlags;
    DIGEST_TYPE typeDigest;
    QOP_TYPE typeQOP;
    ALGORITHM_TYPE typeAlgorithm;
    CIPHER_TYPE typeCipher;
    CHARSET_TYPE typeCharset;
    STRING strNonce;
    STRING strCNonce;
    ULONG ulNC;
    ULONG ulSendMaxBuf;
    ULONG ulRecvMaxBuf;
    STRING strOpaque;
    STRING strSessionKey;
    STRING strResponseAuth;
    STRING strDirective[MD5_AUTH_LAST];
    HANDLE TokenHandle;
    LUID LoginID;
    ULONG CredentialUseFlags;
    UNICODE_STRING ustrDomain;
    UNICODE_STRING ustrPassword;
    UNICODE_STRING ustrAccountName;
    TimeStamp ExpirationTime;
    // The remaining members where added after NT 5.2
    PSSI_STORE pSsiStore;
    HANDLE hSsiPrincipal;
    ULONG ClientProcessID;
} DIGEST_CONTEXT, *PDIGEST_CONTEXT;

typedef struct _DIGEST_CREDENTIAL {
    LIST_ENTRY Next;
    LONG lReferences;
    BOOL Unlinked;
    ULONG_PTR CredentialHandle;
    ULONG CredentialUseFlags;
    ULONG ulCredentialFlags; // Was added after NT 5.2
    SECURITY_LOGON_TYPE LogonType;
    UNICODE_STRING ustrAccountName;
    LUID LogonId;
    UNICODE_STRING ustrDomainName;
    UNICODE_STRING ustrPassword;
    UNICODE_STRING ustrDomain;
    UNICODE_STRING ustrUpn;
    ULONG ClientProcessID;
    PSSI_STORE pSsiStore; // Was added after NT 5.2
} DIGEST_CREDENTIAL, *PDIGEST_CREDENTIAL;

typedef struct _DIGEST_HASHED_DIRS_INFO {
    ULONG cDir;
    PSTR* ppName;
    PSTRING pValue;
} DIGEST_HASHED_DIRS_INFO, *PDIGEST_HASHED_DIRS_INFO;

typedef struct _DIGEST_LOGONSESSION {
    LIST_ENTRY Next;
    LONG lReferences; // In NT 5.2 and prior, this member was located immediately after LogonSessionHandle
    ULONG_PTR LogonSessionHandle;
    LUID LogonId;
    ULONG Flags; // Was added sometime after NT 5.2. Likely set using SECPKG_CRED_*
    SECURITY_LOGON_TYPE LogonType;
    UNICODE_STRING ustrAccountName;
    UNICODE_STRING ustrDomainName;
    UNICODE_STRING ustrPassword;
    UNICODE_STRING ustrDnsDomainName;
    UNICODE_STRING ustrUpn;
} DIGEST_LOGONSESSION, *PDIGEST_LOGONSESSION;

typedef struct _DIGEST_PACKED_USERCONTEXT {
    ULONG ulFlags;
    TimeStamp ExpirationTime;
    ULONG ContextReq;
    ULONG CredentialUseFlags;
    ULONG typeDigest;
    ULONG typeQOP;
    ULONG typeAlgorithm;
    ULONG typeCipher;
    ULONG typeCharset;
    ULONG ulSendMaxBuf;
    ULONG ulRecvMaxBuf;
    ULONG ClientTokenHandle;
    ULONG uSessionKeyLen;
    ULONG uAccountNameLen;
    ULONG uDigestLen[MD5_AUTH_LAST];
    UCHAR ucData;
} DIGEST_PACKED_USERCONTEXT, *PDIGEST_PACKED_USERCONTEXT;

typedef struct _DIGEST_PARAMETER {
    DIGEST_TYPE typeDigest;
    USHORT usFlags;
    ALGORITHM_TYPE typeAlgorithm;
    QOP_TYPE typeQOP;
    CIPHER_TYPE typeCipher;
    CHARSET_TYPE typeCharset;
    STRING refstrParam[MD5_AUTH_LAST];
    USHORT usDirectiveCnt[MD5_AUTH_LAST];
    UNICODE_STRING ustrRealm;
    UNICODE_STRING ustrUsername;
    NAMEFORMAT_TYPE typeName;
    UNICODE_STRING ustrCrackedAccountName;
    UNICODE_STRING ustrCrackedDomain;
    UNICODE_STRING ustrWorkstation;
    STRING strUsernameEncoded;
    STRING strRealmEncoded;
    STRING strDirective[MD5_AUTH_LAST];
    STRING strSessionKey;
    STRING strResponse;
    ULONG ulTrustDirection;
    ULONG ulTrustType;
    ULONG ulTrustAttributes;
    LPVOID pTrustSid;
    UNICODE_STRING ustrTrustedForest;
    ULONG UserId; // Added after NT 5.2
} DIGEST_PARAMETER, *PDIGEST_PARAMETER;

typedef struct _DIGEST_USERCONTEXT {
    LIST_ENTRY Next;
    LONG lLockedAccess; // Added after NT 5.2
    HANDLE LsaContext;
    TimeStamp ExpirationTime;
    LONG lReferences;
    LONG lReferenceHandles;
    BOOL bUnlinked;
    DIGEST_TYPE typeDigest;
    QOP_TYPE typeQOP;
    ALGORITHM_TYPE typeAlgorithm;
    CIPHER_TYPE typeCipher;
    CHARSET_TYPE typeCharset;
    HANDLE ClientTokenHandle;
    ULONG ContextReq;
    ULONG CredentialUseFlags;
    ULONG ulFlags;
    ULONG ulNC;
    ULONG ulNCHistory; // Added after NT 5.2
    ULONG ulSendMaxBuf;
    ULONG ulRecvMaxBuf;
    DWORD dwSendSeqNum;
    DWORD dwRecvSeqNum;
    BYTE bKcSealHashData[MD5_HASH_BYTESIZE];
    BYTE bKiSignHashData[MD5_HASH_BYTESIZE];
    BYTE bKcUnsealHashData[MD5_HASH_BYTESIZE];
    BYTE bKiVerifyHashData[MD5_HASH_BYTESIZE];
    BYTE bSealKey[MD5_HASH_BYTESIZE];
    BYTE bUnsealKey[MD5_HASH_BYTESIZE];
    HCRYPTKEY hSealCryptKey;
    HCRYPTKEY hUnsealCryptKey;
    STRING strSessionKey;
    BYTE bSessionKey[MD5_HASH_BYTESIZE];
    UNICODE_STRING ustrAccountName;
    STRING strParam[MD5_AUTH_LAST];
} DIGEST_USERCONTEXT, *PDIGEST_USERCONTEXT;

typedef struct _PLAINTEXTBLOB {
    PUBLICKEYSTRUC Blob;
    DWORD dwKeyLen;
    BYTE bKey[MD5_HASH_BYTESIZE];
} PLAINTEXTBLOB, *PPLAINTEXTBLOB;

typedef struct _USER_CREDENTIALS {
    UNICODE_STRING ustrUsername;
    UNICODE_STRING ustrRealm;
    BOOL fIsValidPasswd;
    BOOL fIsValidDigestHash;
    BOOL fIsEncryptedPasswd;
    SHORT wHashSelected;
    SHORT sHashTags[TOTALPRECALC_HEADERS];
    UNICODE_STRING ustrPasswd;
    STRING strDigestHash;
    USHORT usDigestHashCnt;
    // The remaining members were added after NT 5.2
    PTOKEN_GROUPS pGroupMembership;
    LPVOID psidUser;
    LPVOID psidPrimaryGroup;
} USER_CREDENTIALS, *PUSER_CREDENTIALS;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Wdigest {
    // Enumerations
    using ALGORITHM_TYPE = ALGORITHM_TYPE;
    using CHARSET_TYPE = CHARSET_TYPE;
    using CIPHER_TYPE = CIPHER_TYPE;
    using MD5_AUTH_NAME = MD5_AUTH_NAME;
    using MODE_TYPE = DIGESTMODE_TYPE;
    using NAMEFORMAT_TYPE = NAMEFORMAT_TYPE;
    using QOP_TYPE = QOP_TYPE;
    using STATE = _NTDIGEST_STATE;
    using TYPE = DIGEST_TYPE;

    using BLOB_REQUEST = _DIGEST_BLOB_REQUEST;
    using BLOB_RESPONSE = _DIGEST_BLOB_RESPONSE;
    using CONTEXT = _DIGEST_CONTEXT;
    using CREDENTIAL = _DIGEST_CREDENTIAL;
    using HASHED_DIRS_INFO = _DIGEST_HASHED_DIRS_INFO;
    using LOGONSESSION = _DIGEST_LOGONSESSION;
    using PACKED_USERCONTEXT = _DIGEST_PACKED_USERCONTEXT;
    using PARAMETER = _DIGEST_PARAMETER;
    using USERCONTEXT = _DIGEST_USERCONTEXT;
    using PLAINTEXTBLOB = _PLAINTEXTBLOB;
    using USER_CREDENTIALS = _USER_CREDENTIALS;
}
#endif