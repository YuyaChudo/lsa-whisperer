#pragma once
#include <pch.hpp>

#include <kerberos.hpp>

enum _TSPkgCallPackageId : LONG {
  TSPkgCall_GetRemoteCredGuardClient = 0x0000,
  TSPkgCall_Reserved1 = 0x4eacc3c8,
};

struct _TSPkgRemoteCredGuardClientRequest { /* Size=0x14 */
  /* 0x0000 */ public: _TSPkgCallPackageId CallId;
  /* 0x0004 */ public: _LUID LogonId;
  /* 0x000c */ public: _UNICODE_STRING ClientPackageName;
};

struct _TSPkgRemoteCredGuardClientResponse { /* Size=0xc */
  /* 0x0000 */ public: PVOID RedirectedLogonHandle;
  /* 0x0004 */ public: LONG (* OperationCallback)(PVOID, PVOID, ULONG, PVOID*, PULONG);
  /* 0x0008 */ public: VOID (* CleanupCallback)(PVOID);
};


struct _NtlmCredIsoRemoteInput;
struct _NtlmCredIsoRemoteOutput;
struct _KerbCredIsoRemoteInput;
struct _KerbCredIsoRemoteOutput;
struct _KerbCredIsoApi;

enum _RemoteGuardCallId : LONG {
  RemoteCallMinimum = 0x0000,
  RemoteCallGenericMinimum = 0x0000,
  RemoteCallGenericPing = 0x0000,
  RemoteCallGenericMaximum = 0x00ff,
  RemoteCallKerbMinimum = 0x0100,
  RemoteCallKerbBuildAsReqAuthenticator = 0x0100,
  RemoteCallKerbVerifyServiceTicket = 0x0101,
  RemoteCallKerbCreateApReqAuthenticator = 0x0102,
  RemoteCallKerbDecryptApReply = 0x0103,
  RemoteCallKerbUnpackKdcReplyBody = 0x0104,
  RemoteCallKerbComputeTgsChecksum = 0x0105,
  RemoteCallKerbBuildEncryptedAuthData = 0x0106,
  RemoteCallKerbPackApReply = 0x0107,
  RemoteCallKerbHashS4UPreauth = 0x0108,
  RemoteCallKerbSignS4UPreauthData = 0x0109,
  RemoteCallKerbVerifyChecksum = 0x010a,
  RemoteCallKerbBuildTicketArmorKey = 0x010b,
  RemoteCallKerbBuildExplicitArmorKey = 0x010c,
  RemoteCallKerbVerifyFastArmoredTgsReply = 0x010d,
  RemoteCallKerbVerifyEncryptedChallengePaData = 0x010e,
  RemoteCallKerbBuildFastArmoredKdcRequest = 0x010f,
  RemoteCallKerbDecryptFastArmoredKerbError = 0x0110,
  RemoteCallKerbDecryptFastArmoredAsReply = 0x0111,
  RemoteCallKerbDecryptPacCredentials = 0x0112,
  RemoteCallKerbCreateECDHKeyAgreement = 0x0113,
  RemoteCallKerbCreateDHKeyAgreement = 0x0114,
  RemoteCallKerbDestroyKeyAgreement = 0x0115,
  RemoteCallKerbKeyAgreementGenerateNonce = 0x0116,
  RemoteCallKerbFinalizeKeyAgreement = 0x0117,
  RemoteCallKerbMaximum = 0x01ff,
  RemoteCallNtlmMinimum = 0x0200,
  RemoteCallNtlmProtectCredential = 0x0200,
  RemoteCallNtlmLm20GetNtlm3ChallengeResponse = 0x0201,
  RemoteCallNtlmCalculateNtResponse = 0x0202,
  RemoteCallNtlmCalculateUserSessionKeyNt = 0x0203,
  RemoteCallNtlmPasswordValidateInteractive = 0x0204,
  RemoteCallNtlmPasswordValidateNetwork = 0x0205,
  RemoteCallNtlmIsGMSACred = 0x0206,
  RemoteCallNtlmMakeSecretPasswordNT5 = 0x0207,
  RemoteCallNtlmCompareCredentials = 0x0208,
  RemoteCallNtlmMaximum = 0x02ff,
  RemoteCallMaximum = 0x02ff,
  RemoteCallInvalid = 0xffff,
};













struct _unnamed_0x6541 { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* S4UPreauth;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* Key;
  /* 0x0010 */ public: LONG ChecksumType;
};

struct _unnamed_0x6552 { /* Size=0x18 */
  /* 0x0000 */ public: LONG RequestNonce;
  /* 0x0008 */ public: _KERB_ASN1_DATA* InputKerbError;
  /* 0x0010 */ public: _KERB_ENCRYPTION_KEY* ArmorKey;
};

struct _unnamed_0x653b { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* RequestBody;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* Key;
  /* 0x0010 */ public: ULONG ChecksumType;
};

struct _unnamed_0x6556 { /* Size=0x20 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* Key;
  /* 0x0008 */ public: ULONG Version;
  /* 0x000c */ public: ULONG EncryptionType;
  /* 0x0010 */ public: ULONG DataSize;
  /* 0x0018 */ public: PUCHAR Data;
};

struct _unnamed_0x655c { /* Size=0x8 */
  /* 0x0000 */ public: LONGLONG KeyAgreementHandle;
};

struct _unnamed_0x655e { /* Size=0x28 */
  /* 0x0000 */ public: PLONGLONG KeyAgreementHandle;
  /* 0x0008 */ public: ULONG KerbEType;
  /* 0x000c */ public: ULONG RemoteNonceLen;
  /* 0x0010 */ public: PUCHAR RemoteNonce;
  /* 0x0018 */ public: ULONG X509PublicKeyLen;
  /* 0x0020 */ public: PUCHAR X509PublicKey;
};

struct _unnamed_0x654a { /* Size=0x20 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* KdcRequest;
  /* 0x0008 */ public: _KERB_ASN1_DATA* KdcReply;
  /* 0x0010 */ public: _KERB_ENCRYPTION_KEY* ArmorKey;
  /* 0x0018 */ public: _KERB_ENCRYPTION_KEY* ReplyKey;
};

struct _unnamed_0x6545 { /* Size=0x28 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* Key;
  /* 0x0008 */ public: ULONG ChecksumType;
  /* 0x000c */ public: ULONG ExpectedChecksumSize;
  /* 0x0010 */ public: const UCHAR* ExpectedChecksum;
  /* 0x0018 */ public: ULONG DataToCheckSize;
  /* 0x0020 */ public: const UCHAR* DataToCheck;
};

struct _unnamed_0x6543 { /* Size=0x20 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* Key;
  /* 0x0008 */ public: LONG IsRequest;
  /* 0x0010 */ public: _KERB_ASN1_DATA* UserId;
  /* 0x0018 */ public: PLONG ChecksumType;
};

struct _unnamed_0x653f { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* Reply;
  /* 0x0008 */ public: _KERB_ASN1_DATA* ReplyBody;
  /* 0x0010 */ public: _KERB_ENCRYPTION_KEY* SessionKey;
};

struct _unnamed_0x6546 { /* Size=0x8 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* SharedKey;
};

struct _unnamed_0x6550 { /* Size=0x28 */
  /* 0x0000 */ public: LONGLONG KeyAgreementHandle;
  /* 0x0008 */ public: _KERB_ASN1_DATA* KdcRequest;
  /* 0x0010 */ public: _KERB_RPC_PA_DATA* PaTgsReqPaData;
  /* 0x0018 */ public: _KERB_RPC_FAST_ARMOR* FastArmor;
  /* 0x0020 */ public: _KERB_ENCRYPTION_KEY* ArmorKey;
};

struct _unnamed_0x6558 { /* Size=0x4 */
  /* 0x0000 */ public: ULONG KeyBitLen;
};

struct _unnamed_0x6548 { /* Size=0x8 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* TicketSessionKey;
};

struct _unnamed_0x654c { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* ArmorKey;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* UserKey;
  /* 0x0010 */ public: _KERB_RPC_PA_DATA* PaData;
};

struct _unnamed_0x6539 { /* Size=0x20 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* EncryptedData;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* Key;
  /* 0x0010 */ public: _KERB_ENCRYPTION_KEY* StrengthenKey;
  /* 0x0018 */ public: ULONG Pdu;
  /* 0x001c */ public: ULONG KeyUsage;
};

struct _unnamed_0x6537 { /* Size=0x10 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* EncryptedReply;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* Key;
};

struct _unnamed_0x6559 { /* Size=0x1 */
  /* 0x0000 */ public: UCHAR Ignored;
};

struct _unnamed_0x655b { /* Size=0x8 */
  /* 0x0000 */ public: LONGLONG KeyAgreementHandle;
};

struct _unnamed_0x6554 { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* KdcRequest;
  /* 0x0008 */ public: _KERB_ASN1_DATA* KdcReply;
  /* 0x0010 */ public: _KERB_ENCRYPTION_KEY* ArmorKey;
};

struct _unnamed_0x653d { /* Size=0x18 */
  /* 0x0000 */ public: ULONG KeyUsage;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* Key;
  /* 0x0010 */ public: _KERB_ASN1_DATA* PlainAuthData;
};

/// <summary>
/// The input buffer for the remote credential kerberos calls.
/// </summary>
struct _KerbCredIsoRemoteInput {
    _RemoteGuardCallId CallId;
    union {
        // RemoteCallKerbNegotiateVersion
        typedef struct {
            ULONG MaxSupportedVersion;
        } NegotiateVersion;
        // RemoteCallKerbBuildAsReqAuthenticator
        struct {
            _KERB_ENCRYPTION_KEY* EncryptionKey;
            _KERB_ENCRYPTION_KEY* ArmorKey;
            _LARGE_INTEGER* TimeSkew;
        } BuildAsReqAuthenticator;
        struct {
            _KERB_ASN1_DATA* PackedTicket;
            _KERB_ENCRYPTION_KEY* ServiceKey;
            _LARGE_INTEGER* TimeSkew;
        } VerifyServiceTicket;
        struct {
            _KERB_ENCRYPTION_KEY* EncryptionKey;
            ULONG SequenceNumber;
            _KERB_RPC_INTERNAL_NAME* ClientName;
            _UNICODE_STRING* ClientRealm;
            _LARGE_INTEGER* SkewTime;
            _KERB_ENCRYPTION_KEY* SubKey;
            _KERB_ASN1_DATA* AuthData;
            _KERB_ASN1_DATA* GssChecksum;
            ULONG KeyUsage;
        } CreateApReqAuthenticator;
    _unnamed_0x6537 DecryptApReply;
    _unnamed_0x6539 UnpackKdcReplyBody;
    _unnamed_0x653b ComputeTgsChecksum;
    _unnamed_0x653d BuildEncryptedAuthData;
    _unnamed_0x653f PackApReply;
    _unnamed_0x6541 HashS4UPreauth;
    _unnamed_0x6543 SignS4UPreauthData;
    _unnamed_0x6545 VerifyChecksum;
    _unnamed_0x6546 BuildTicketArmorKey;
    _unnamed_0x6548 BuildExplicitArmorKey;
    _unnamed_0x654a VerifyFastArmoredTgsReply;
    _unnamed_0x654c VerifyEncryptedChallengePaData;
    _unnamed_0x6550 BuildFastArmoredKdcRequest;
    _unnamed_0x6552 DecryptFastArmoredKerbError;
    _unnamed_0x6554 DecryptFastArmoredAsReply;
    _unnamed_0x6556 DecryptPacCredentials;
    _unnamed_0x6558 CreateECDHKeyAgreement;
    _unnamed_0x6559 CreateDHKeyAgreement;
    _unnamed_0x655b DestroyKeyAgreement;
    _unnamed_0x655c KeyAgreementGenerateNonce;
    _unnamed_0x655e FinalizeKeyAgreement;
  };
};







===============================================


struct _unnamed_0x3269 { /* Size=0x8 */
  /* 0x0000 */ public: ULONG LowPart;
  /* 0x0004 */ public: LONG HighPart;
};

union _LARGE_INTEGER { /* Size=0x8 */
  struct {
    /* 0x0000 */ public: ULONG LowPart;
    /* 0x0004 */ public: LONG HighPart;
  };
  /* 0x0000 */ public: _unnamed_0x3269 u;
  /* 0x0000 */ public: LONGLONG QuadPart;
};

struct _KERB_RPC_OCTET_STRING { /* Size=0x10 */
  /* 0x0000 */ public: ULONG length;
  /* 0x0008 */ public: PUCHAR value;
};

struct _KERB_ASN1_DATA { /* Size=0x10 */
  /* 0x0000 */ public: ULONG Pdu;
  /* 0x0004 */ public: ULONG Length;
  /* 0x0008 */ public: PUCHAR Asn1Buffer;
};

struct _unnamed_0x64fb { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ASN1_DATA DecryptedTicket;
  /* 0x0010 */ public: LONG KerbProtocolError;
};

struct _unnamed_0x650f { /* Size=0x10 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* SubKey;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* ArmorKey;
};

struct _unnamed_0x64f9 { /* Size=0x18 */
  /* 0x0000 */ public: LONG PreauthDataType;
  /* 0x0008 */ public: _KERB_RPC_OCTET_STRING PreauthData;
};

struct _unnamed_0x6513 { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* NewReplyKey;
  /* 0x0008 */ public: _KERB_ASN1_DATA* ModifiedKdcReply;
  /* 0x0010 */ public: _LARGE_INTEGER* KdcTime;
};

struct _unnamed_0x6519 { /* Size=0x8 */
  /* 0x0000 */ public: _KERB_RPC_PA_DATA* FastPaDataResult;
};

struct _unnamed_0x64f7 { /* Size=0x4 */
  /* 0x0000 */ public: ULONG VersionToUse;
};

struct _unnamed_0x6525 { /* Size=0x38 */
  /* 0x0000 */ public: _KERB_RPC_CRYPTO_API_BLOB* ModulusP;
  /* 0x0008 */ public: _KERB_RPC_CRYPTO_API_BLOB* GeneratorG;
  /* 0x0010 */ public: _KERB_RPC_CRYPTO_API_BLOB* FactorQ;
  /* 0x0018 */ public: PLONGLONG KeyAgreementHandle;
  /* 0x0020 */ public: PLONG KerbErr;
  /* 0x0028 */ public: PULONG LittleEndianPublicKeyLen;
  /* 0x0030 */ public: PUCHAR* LittleEndianPublicKey;
};

struct _unnamed_0x6511 { /* Size=0x20 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* ArmorSubKey;
  /* 0x0008 */ public: _KERB_ENCRYPTION_KEY* ExplicitArmorKey;
  /* 0x0010 */ public: _KERB_ENCRYPTION_KEY* SubKey;
  /* 0x0018 */ public: _KERB_ENCRYPTION_KEY* ArmorKey;
};

struct _unnamed_0x6501 { /* Size=0x18 */
  /* 0x0000 */ public: LONG KerbProtocolError;
  /* 0x0008 */ public: _KERB_ASN1_DATA ReplyBody;
};

struct _unnamed_0x651d { /* Size=0x18 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* StrengthenKey;
  /* 0x0008 */ public: _KERB_ASN1_DATA* ModifiedKdcReply;
  /* 0x0010 */ public: _LARGE_INTEGER* KdcTime;
};

struct _unnamed_0x650d { /* Size=0x4 */
  /* 0x0000 */ public: LONG IsValid;
};

struct _unnamed_0x6521 { /* Size=0x20 */
  /* 0x0000 */ public: PLONGLONG KeyAgreementHandle;
  /* 0x0008 */ public: PLONG KerbErr;
  /* 0x0010 */ public: PULONG EncodedPubKeyLen;
  /* 0x0018 */ public: PUCHAR* EncodedPubKey;
};

struct _unnamed_0x6527 { /* Size=0x1 */
  /* 0x0000 */ public: UCHAR Ignored;
};

struct _unnamed_0x650b { /* Size=0x18 */
  /* 0x0000 */ public: PLONG ChecksumType;
  /* 0x0008 */ public: PULONG ChecksumSize;
  /* 0x0010 */ public: PUCHAR* ChecksumValue;
};

struct _unnamed_0x6507 { /* Size=0x10 */
  /* 0x0000 */ public: ULONG PackedReplySize;
  /* 0x0008 */ public: PUCHAR PackedReply;
};

struct _unnamed_0x6503 { /* Size=0x10 */
  /* 0x0000 */ public: _KERB_ASN1_DATA Checksum;
};

struct _unnamed_0x64ff { /* Size=0x10 */
  /* 0x0000 */ public: _KERB_ASN1_DATA ApReply;
};

struct _unnamed_0x6515 { /* Size=0x8 */
  /* 0x0000 */ public: PUCHAR IsValid;
};

struct _unnamed_0x6505 { /* Size=0x10 */
  /* 0x0000 */ public: _KERB_ASN1_DATA EncryptedAuthData;
};

struct _unnamed_0x651b { /* Size=0x10 */
  /* 0x0000 */ public: _KERB_ASN1_DATA* OutputKerbError;
  /* 0x0008 */ public: _KERB_ASN1_DATA* FastResponse;
};

struct _unnamed_0x6529 { /* Size=0x10 */
  /* 0x0000 */ public: PULONG NonceLen;
  /* 0x0008 */ public: PUCHAR* Nonce;
};

struct _unnamed_0x652b { /* Size=0x8 */
  /* 0x0000 */ public: _KERB_ENCRYPTION_KEY* SharedKey;
};

struct _unnamed_0x651f { /* Size=0x8 */
  /* 0x0000 */ public: _SECPKG_SUPPLEMENTAL_CRED_ARRAY* Credentials;
};

struct _unnamed_0x6509 { /* Size=0x10 */
  /* 0x0000 */ public: PULONG ChecksumSize;
  /* 0x0008 */ public: PUCHAR* ChecksumValue;
};

struct _unnamed_0x64fd { /* Size=0x20 */
  /* 0x0000 */ public: _LARGE_INTEGER AuthenticatorTime;
  /* 0x0008 */ public: _KERB_ASN1_DATA Authenticator;
  /* 0x0018 */ public: LONG KerbProtocolError;
};

struct _KerbCredIsoRemoteOutput { /* Size=0x40 */
  /* 0x0000 */ public: _RemoteGuardCallId CallId;
  /* 0x0004 */ public: LONG Status;
  union {
    /* 0x0008 */ public: _unnamed_0x64f7 NegotiateVersion;
    /* 0x0008 */ public: _unnamed_0x64f9 BuildAsReqAuthenticator;
    /* 0x0008 */ public: _unnamed_0x64fb VerifyServiceTicket;
    /* 0x0008 */ public: _unnamed_0x64fd CreateApReqAuthenticator;
    /* 0x0008 */ public: _unnamed_0x64ff DecryptApReply;
    /* 0x0008 */ public: _unnamed_0x6501 UnpackKdcReplyBody;
    /* 0x0008 */ public: _unnamed_0x6503 ComputeTgsChecksum;
    /* 0x0008 */ public: _unnamed_0x6505 BuildEncryptedAuthData;
    /* 0x0008 */ public: _unnamed_0x6507 PackApReply;
    /* 0x0008 */ public: _unnamed_0x6509 HashS4UPreauth;
    /* 0x0008 */ public: _unnamed_0x650b SignS4UPreauthData;
    /* 0x0008 */ public: _unnamed_0x650d VerifyChecksum;
    /* 0x0008 */ public: _unnamed_0x650f BuildTicketArmorKey;
    /* 0x0008 */ public: _unnamed_0x6511 BuildExplicitArmorKey;
    /* 0x0008 */ public: _unnamed_0x6513 VerifyFastArmoredTgsReply;
    /* 0x0008 */ public: _unnamed_0x6515 VerifyEncryptedChallengePaData;
    /* 0x0008 */ public: _unnamed_0x6519 BuildFastArmoredKdcRequest;
    /* 0x0008 */ public: _unnamed_0x651b DecryptFastArmoredKerbError;
    /* 0x0008 */ public: _unnamed_0x651d DecryptFastArmoredAsReply;
    /* 0x0008 */ public: _unnamed_0x651f DecryptPacCredentials;
    /* 0x0008 */ public: _unnamed_0x6521 CreateECDHKeyAgreement;
    /* 0x0008 */ public: _unnamed_0x6525 CreateDHKeyAgreement;
    /* 0x0008 */ public: _unnamed_0x6527 DestroyKeyAgreement;
    /* 0x0008 */ public: _unnamed_0x6529 KeyAgreementGenerateNonce;
    /* 0x0008 */ public: _unnamed_0x652b FinalizeKeyAgreement;
  };
};











==========================================================



//
// Information extracted with resym v0.4.0
//
// PDB file: C:\Users\emcbroom\Documents\leaks\pivotman319\Mobilecore_symbols\Private_symbols\msv1_0.pdb\A7626EB1EE034CFE84E95C82EDEDF5D91\msv1_0.pdb
// Image architecture: Arm64
//

#include <Windows.h>
#include <array>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

struct _UNICODE_STRING;
struct _CLEAR_BLOCK;
struct _LM_RESPONSE;
struct _MSV1_0_REMOTE_PLAINTEXT_SECRETS;
struct _MSV1_0_REMOTE_ENCRYPTED_SECRETS;

enum _RemoteGuardCallId : LONG {
  RemoteCallMinimum = 0x0000,
  RemoteCallGenericMinimum = 0x0000,
  RemoteCallGenericPing = 0x0000,
  RemoteCallGenericMaximum = 0x00ff,
  RemoteCallKerbMinimum = 0x0100,
  RemoteCallKerbNegotiateVersion = 0x0100,
  RemoteCallKerbBuildAsReqAuthenticator = 0x0101,
  RemoteCallKerbVerifyServiceTicket = 0x0102,
  RemoteCallKerbCreateApReqAuthenticator = 0x0103,
  RemoteCallKerbDecryptApReply = 0x0104,
  RemoteCallKerbUnpackKdcReplyBody = 0x0105,
  RemoteCallKerbComputeTgsChecksum = 0x0106,
  RemoteCallKerbBuildEncryptedAuthData = 0x0107,
  RemoteCallKerbPackApReply = 0x0108,
  RemoteCallKerbHashS4UPreauth = 0x0109,
  RemoteCallKerbSignS4UPreauthData = 0x010a,
  RemoteCallKerbVerifyChecksum = 0x010b,
  RemoteCallKerbBuildTicketArmorKey = 0x010c,
  RemoteCallKerbBuildExplicitArmorKey = 0x010d,
  RemoteCallKerbVerifyFastArmoredTgsReply = 0x010e,
  RemoteCallKerbVerifyEncryptedChallengePaData = 0x010f,
  RemoteCallKerbBuildFastArmoredKdcRequest = 0x0110,
  RemoteCallKerbDecryptFastArmoredKerbError = 0x0111,
  RemoteCallKerbDecryptFastArmoredAsReply = 0x0112,
  RemoteCallKerbDecryptPacCredentials = 0x0113,
  RemoteCallKerbCreateECDHKeyAgreement = 0x0114,
  RemoteCallKerbCreateDHKeyAgreement = 0x0115,
  RemoteCallKerbDestroyKeyAgreement = 0x0116,
  RemoteCallKerbKeyAgreementGenerateNonce = 0x0117,
  RemoteCallKerbFinalizeKeyAgreement = 0x0118,
  RemoteCallKerbMaximum = 0x01ff,
  RemoteCallNtlmMinimum = 0x0200,
  RemoteCallNtlmNegotiateVersion = 0x0200,
  RemoteCallNtlmProtectCredential = 0x0201,
  RemoteCallNtlmLm20GetNtlm3ChallengeResponse = 0x0202,
  RemoteCallNtlmCalculateNtResponse = 0x0203,
  RemoteCallNtlmCalculateUserSessionKeyNt = 0x0204,
  RemoteCallNtlmCompareCredentials = 0x0205,
  RemoteCallNtlmMaximum = 0x02ff,
  RemoteCallMaximum = 0x02ff,
  RemoteCallInvalid = 0xffff,
};

struct _unnamed_0x2157 { /* Size=0x8 */
  /* 0x0000 */ public: _MSV1_0_REMOTE_PLAINTEXT_SECRETS* Credential;
};

struct _unnamed_0x2151 { /* Size=0x10 */
  /* 0x0000 */ public: _CLEAR_BLOCK* NtChallenge;
  /* 0x0008 */ public: _MSV1_0_REMOTE_ENCRYPTED_SECRETS* Credential;
};

struct _unnamed_0x2159 { /* Size=0x4 */
  /* 0x0000 */ public: ULONG MaxSupportedVersion;
};

struct _unnamed_0x214d { /* Size=0x10 */
  /* 0x0000 */ public: _MSV1_0_REMOTE_ENCRYPTED_SECRETS* LhsCredential;
  /* 0x0008 */ public: _MSV1_0_REMOTE_ENCRYPTED_SECRETS* RhsCredential;
};

struct _unnamed_0x214f { /* Size=0x10 */
  /* 0x0000 */ public: _LM_RESPONSE* NtResponse;
  /* 0x0008 */ public: _MSV1_0_REMOTE_ENCRYPTED_SECRETS* Credential;
};

struct _unnamed_0x2153 { /* Size=0x28 */
  /* 0x0000 */ public: _MSV1_0_REMOTE_ENCRYPTED_SECRETS* Credential;
  /* 0x0008 */ public: _UNICODE_STRING* UserName;
  /* 0x0010 */ public: _UNICODE_STRING* LogonDomainName;
  /* 0x0018 */ public: _UNICODE_STRING* ServerName;
  /* 0x0020 */ public: UCHAR ChallengeToClient[8];
};

struct _NtlmCredIsoRemoteInput { /* Size=0x30 */
  /* 0x0000 */ public: _RemoteGuardCallId CallId;
  union {
    /* 0x0008 */ public: _unnamed_0x2159 NegotiateVersion;
    /* 0x0008 */ public: _unnamed_0x2157 ProtectCredential;
    /* 0x0008 */ public: _unnamed_0x2153 Lm20GetNtlm3ChallengeResponse;
    /* 0x0008 */ public: _unnamed_0x2151 CalculateNtResponse;
    /* 0x0008 */ public: _unnamed_0x214f CalculateUserSessionKeyNt;
    /* 0x0008 */ public: _unnamed_0x214d CompareCredentials;
  };
};
















==============================================

//
// Information extracted with resym v0.4.0
//
// PDB file: C:\Users\emcbroom\Documents\leaks\pivotman319\Mobilecore_symbols\Private_symbols\msv1_0.pdb\A7626EB1EE034CFE84E95C82EDEDF5D91\msv1_0.pdb
// Image architecture: Arm64
//

#include <Windows.h>
#include <array>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

enum _MSV1_0_CREDENTIAL_KEY_TYPE : LONG {
  InvalidCredKey = 0x0000,
  DeprecatedIUMCredKey = 0x0001,
  DomainUserCredKey = 0x0002,
  LocalUserCredKey = 0x0003,
  ExternallySuppliedCredKey = 0x0004,
};

struct _CYPHER_BLOCK { /* Size=0x8 */
  /* 0x0000 */ public: CHAR data[8];
};

struct _MSV1_0_CREDENTIAL_KEY { /* Size=0x14 */
  /* 0x0000 */ public: UCHAR Data[20];
};

struct _USER_SESSION_KEY { /* Size=0x10 */
  /* 0x0000 */ public: _CYPHER_BLOCK data[2];
};

struct _LM_RESPONSE { /* Size=0x18 */
  /* 0x0000 */ public: _CYPHER_BLOCK data[3];
};

struct _MSV1_0_REMOTE_ENCRYPTED_SECRETS { /* Size=0x28 */
  /* 0x0000 */ public: UCHAR NtPasswordPresent;
  /* 0x0001 */ public: UCHAR LmPasswordPresent;
  /* 0x0002 */ public: UCHAR ShaPasswordPresent;
  /* 0x0004 */ public: _MSV1_0_CREDENTIAL_KEY_TYPE CredentialKeyType;
  /* 0x0008 */ public: _MSV1_0_CREDENTIAL_KEY CredentialKeySecret;
  /* 0x001c */ public: ULONG EncryptedSize;
  /* 0x0020 */ public: PUCHAR EncryptedSecrets;
};

struct MSV1_0_LM3_RESPONSE { /* Size=0x18 */
  /* 0x0000 */ public: UCHAR Response[16];
  /* 0x0010 */ public: UCHAR ChallengeFromClient[8];
};

struct _CLEAR_BLOCK { /* Size=0x8 */
  /* 0x0000 */ public: CHAR data[8];
};

struct _unnamed_0x2169 { /* Size=0x40 */
  /* 0x0000 */ public: USHORT Ntlm3ResponseLength;
  /* 0x0008 */ public: PUCHAR Ntlm3Response;
  /* 0x0010 */ public: MSV1_0_LM3_RESPONSE Lm3Response;
  /* 0x0028 */ public: _USER_SESSION_KEY UserSessionKey;
  /* 0x0038 */ public: _CLEAR_BLOCK LmSessionKey;
};

struct _unnamed_0x216d { /* Size=0x4 */
  /* 0x0000 */ public: ULONG VersionToUse;
};

struct _unnamed_0x216b { /* Size=0x28 */
  /* 0x0000 */ public: _MSV1_0_REMOTE_ENCRYPTED_SECRETS Credential;
};

struct _unnamed_0x2163 { /* Size=0xc */
  /* 0x0000 */ public: LONG AreNtOwfsEqual;
  /* 0x0004 */ public: LONG AreLmOwfsEqual;
  /* 0x0008 */ public: LONG AreShaOwfsEqual;
};

struct _unnamed_0x2165 { /* Size=0x10 */
  /* 0x0000 */ public: _USER_SESSION_KEY UserSessionKey;
};

struct _unnamed_0x2167 { /* Size=0x18 */
  /* 0x0000 */ public: _LM_RESPONSE NtResponse;
};

struct _NtlmCredIsoRemoteOutput { /* Size=0x48 */
  /* 0x0000 */ public: _RemoteGuardCallId CallId;
  /* 0x0004 */ public: LONG Status;
  union {
    /* 0x0008 */ public: _unnamed_0x216d NegotiateVersion;
    /* 0x0008 */ public: _unnamed_0x216b ProtectCredential;
    /* 0x0008 */ public: _unnamed_0x2169 Lm20GetNtlm3ChallengeResponse;
    /* 0x0008 */ public: _unnamed_0x2167 CalculateNtResponse;
    /* 0x0008 */ public: _unnamed_0x2165 CalculateUserSessionKeyNt;
    /* 0x0008 */ public: _unnamed_0x2163 CompareCredentials;
  };
};
