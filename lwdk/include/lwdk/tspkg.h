// Copyright (C) 2024 Evan McBroom
//
// Terminal services package (tspkg)
//
// Please reference to MS-RDPEAR if detailed information is needed for any type definition:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpear/
//
#pragma once
#include <phnt_windows.h>

#include "kerberos.h"
#include "msv1_0.h"

#define KEY_AGREEMENT_HANDLE_INVALID -1

#ifdef __cplusplus
extern "C" {
#endif

enum _RemoteGuardCallId;
enum _TSPkgCallPackageId;

struct _KerbCredIsoRemoteInput;
struct _KerbCredIsoRemoteOutput;
struct _NtlmCredIsoRemoteInput;
struct _NtlmCredIsoRemoteOutput;
struct _TSPkgRemoteCredGuardClientRequest;
struct _TSPkgRemoteCredGuardClientResponse;

typedef LONG64 KEY_AGREEMENT_HANDLE, *PKEY_AGREEMENT_HANDLE;
typedef LONG KERBERR, *PKERBERR;

/// <summary>
/// The remote credential guard call that should be issued.
/// </summary>
typedef enum _RemoteGuardCallId {
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
    RemoteCallNtlmLm20GetNtlm3ChallengeResponse = 0x0201, // Was RemoteCallNtlmProtectCredential in v160714 but was removed in v210407
    RemoteCallNtlmCalculateNtResponse = 0x0202, // This member and all follow on members were incremented by 1 when RemoteCallNtlmProtectCredential existed
    RemoteCallNtlmCalculateUserSessionKeyNt = 0x0203,
    RemoteCallNtlmCompareCredentials = 0x0204,
    RemoteCallNtlmMaximum = 0x02ff,
    RemoteCallMaximum = 0x02ff,
    RemoteCallInvalid = 0xffff,
} RemoteGuardCallId,
    *PRemoteGuardCallId;

typedef enum _TSPkgCallPackageId {
    TSPkgCall_GetRemoteCredGuardClient = 0,
    TSPkgCall_Reserved1 = 0x4eacc3c8,
} TSPkgCallPackageId,
    *PTSPkgCallPackageId;

/// <summary>
/// The input buffer for remote credential kerberos calls.
/// </summary>
typedef struct _KerbCredIsoRemoteInput {
    RemoteGuardCallId CallId;
    union {
        typedef struct {
            ULONG MaxSupportedVersion;
        } NegotiateVersion;
        typedef struct {
            PKERB_ENCRYPTION_KEY EncryptionKey;
            PKERB_ENCRYPTION_KEY ArmorKey;
            PLARGE_INTEGER TimeSkew;
        } BuildAsReqAuthenticator;
        typedef struct {
            PKERB_ASN1_DATA PackedTicket;
            PKERB_ENCRYPTION_KEY ServiceKey;
            PLARGE_INTEGER TimeSkew;
        } VerifyServiceTicket;
        typedef struct {
            PKERB_ENCRYPTION_KEY EncryptionKey;
            ULONG SequenceNumber;
            PKERB_RPC_INTERNAL_NAME ClientName;
            PUNICODE_STRING ClientRealm;
            PLARGE_INTEGER SkewTime;
            PKERB_ENCRYPTION_KEY SubKey;
            PKERB_ASN1_DATA AuthData;
            PKERB_ASN1_DATA GssChecksum;
            ULONG KeyUsage;
        } CreateApReqAuthenticator;
        typedef struct {
            PKERB_ASN1_DATA EncryptedReply;
            PKERB_ENCRYPTION_KEY Key;
        } DecryptApReply;
        typedef struct {
            PKERB_ASN1_DATA EncryptedData;
            PKERB_ENCRYPTION_KEY Key;
            PKERB_ENCRYPTION_KEY StrengthenKey;
            ULONG Pdu;
            ULONG KeyUsage;
        } UnpackKdcReplyBody;
        typedef struct {
            PKERB_ASN1_DATA RequestBody;
            PKERB_ENCRYPTION_KEY Key;
            ULONG ChecksumType;
        } ComputeTgsChecksum;
        typedef struct {
            ULONG KeyUsage;
            PKERB_ENCRYPTION_KEY Key;
            PKERB_ASN1_DATA PlainAuthData;
        } BuildEncryptedAuthData;
        typedef struct {
            PKERB_ASN1_DATA Reply;
            PKERB_ASN1_DATA ReplyBody;
            PKERB_ENCRYPTION_KEY SessionKey;
        } PackApReply;
        typedef struct {
            PKERB_ASN1_DATA S4UPreauth;
            PKERB_ENCRYPTION_KEY Key;
            LONG ChecksumType;
        } HashS4UPreauth;
        typedef struct {
            PKERB_ENCRYPTION_KEY Key;
            LONG IsRequest;
            PKERB_ASN1_DATA UserId;
            PLONG ChecksumType;
        } SignS4UPreauthData;
        typedef struct {
            PKERB_ENCRYPTION_KEY Key;
            ULONG ChecksumType;
            ULONG ExpectedChecksumSize;
            const UCHAR* ExpectedChecksum;
            ULONG DataToCheckSize;
            const UCHAR* DataToCheck;
        } VerifyChecksum;
        typedef struct {
            PKERB_ENCRYPTION_KEY SharedKey;
        } BuildTicketArmorKey;
        typedef struct {
            PKERB_ENCRYPTION_KEY TicketSessionKey;
        } BuildExplicitArmorKey;
        typedef struct {
            PKERB_ASN1_DATA KdcRequest;
            PKERB_ASN1_DATA KdcReply;
            PKERB_ENCRYPTION_KEY ArmorKey;
            PKERB_ENCRYPTION_KEY ReplyKey;
        } VerifyFastArmoredTgsReply;
        typedef struct {
            PKERB_ENCRYPTION_KEY ArmorKey;
            PKERB_ENCRYPTION_KEY UserKey;
            PKERB_RPC_PA_DATA PaData;
        } VerifyEncryptedChallengePaData;
        typedef struct {
            KEY_AGREEMENT_HANDLE KeyAgreementHandle;
            PKERB_ASN1_DATA KdcRequest;
            PKERB_RPC_PA_DATA PaTgsReqPaData;
            PKERB_RPC_FAST_ARMOR FastArmor;
            PKERB_ENCRYPTION_KEY ArmorKey;
        } BuildFastArmoredKdcRequest;
        typedef struct {
            LONG RequestNonce;
            PKERB_ASN1_DATA InputKerbError;
            PKERB_ENCRYPTION_KEY ArmorKey;
        } DecryptFastArmoredKerbError;
        typedef struct {
            PKERB_ASN1_DATA KdcRequest;
            PKERB_ASN1_DATA KdcReply;
            PKERB_ENCRYPTION_KEY ArmorKey;
        } DecryptFastArmoredAsReply;
        typedef struct {
            PKERB_ENCRYPTION_KEY Key;
            ULONG Version;
            ULONG EncryptionType;
            ULONG DataSize;
            PUCHAR Data;
        } DecryptPacCredentials;
        typedef struct {
            ULONG KeyBitLen;
        } CreateECDHKeyAgreement;
        typedef struct {
            UCHAR Ignored;
        } CreateDHKeyAgreement;
        typedef struct {
            KEY_AGREEMENT_HANDLE KeyAgreementHandle;
        } DestroyKeyAgreement;
        typedef struct {
            LONGLONG KeyAgreementHandle;
        } KEY_AGREEMENT_HANDLE;
        typedef struct {
            PKEY_AGREEMENT_HANDLE KeyAgreementHandle;
            ULONG KerbEType;
            ULONG RemoteNonceLen;
            PBYTE RemoteNonce;
            ULONG X509PublicKeyLen;
            PBYTE X509PublicKey;
        } FinalizeKeyAgreement;
    };
} KerbCredIsoRemoteInput, *PKerbCredIsoRemoteInput;

/// <summary>
/// The output buffer for remote credential kerberos calls.
/// </summary>
typedef struct _KerbCredIsoRemoteOutput {
    RemoteGuardCallId CallId;
    LONG Status;
    union {
        typedef struct {
            ULONG VersionToUse;
        } NegotiateVersion;
        typedef struct {
            LONG PreauthDataType;
            KERB_RPC_OCTET_STRING PreauthData;
        } BuildAsReqAuthenticator;
        typedef struct {
            KERB_ASN1_DATA DecryptedTicket;
            LONG KerbProtocolError;
        } VerifyServiceTicket;
        typedef struct {
            TimeStamp AuthenticatorTime;
            KERB_ASN1_DATA Authenticator;
            LONG KerbProtocolError;
        } CreateApReqAuthenticator;
        typedef struct {
            KERB_ASN1_DATA ApReply;
        } DecryptApReply;
        typedef struct {
            LONG KerbProtocolError;
            KERB_ASN1_DATA ReplyBody;
        } UnpackKdcReplyBody;
        typedef struct {
            KERB_ASN1_DATA Checksum;
        } ComputeTgsChecksum;
        typedef struct {
            KERB_ASN1_DATA EncryptedAuthData;
        } BuildEncryptedAuthData;
        typedef struct {
            ULONG PackedReplySize;
            PUCHAR PackedReply;
        } PackApReply;
        typedef struct {
            PULONG ChecksumSize;
            PUCHAR* ChecksumValue;
        } HashS4UPreauth;
        typedef struct {
            PLONG ChecksumType;
            PULONG ChecksumSize;
            PUCHAR* ChecksumValue;
        } SignS4UPreauthData;
        typedef struct {
            BOOL IsValid;
        } VerifyChecksum;
        typedef struct {
            PKERB_ENCRYPTION_KEY SubKey;
            PKERB_ENCRYPTION_KEY ArmorKey;
        } BuildTicketArmorKey;
        typedef struct {
            PKERB_ENCRYPTION_KEY ArmorSubKey;
            PKERB_ENCRYPTION_KEY ExplicitArmorKey;
            PKERB_ENCRYPTION_KEY SubKey;
            PKERB_ENCRYPTION_KEY ArmorKey;
        } BuildExplicitArmorKey;
        typedef struct {
            PKERB_ENCRYPTION_KEY NewReplyKey;
            PKERB_ASN1_DATA ModifiedKdcReply;
            PTimeStamp KdcTime;
        } VerifyFastArmoredTgsReply;
        typedef struct {
            BOOL IsValid;
        } VerifyEncryptedChallengePaData;
        typedef struct {
            PKERB_RPC_PA_DATA FastPaDataResult;
        } BuildFastArmoredKdcRequest;
        typedef struct {
            PKERB_ASN1_DATA OutputKerbError;
            PKERB_ASN1_DATA FastResponse;
        } DecryptFastArmoredKerbError;
        typedef struct {
            PKERB_ENCRYPTION_KEY StrengthenKey;
            PKERB_ASN1_DATA ModifiedKdcReply;
            PTimeStamp KdcTime;
        } DecryptFastArmoredAsReply;
        typedef struct {
            PSECPKG_SUPPLEMENTAL_CRED_ARRAY Credentials;
        } DecryptPacCredentials;
        typedef struct {
            PKEY_AGREEMENT_HANDLE KeyAgreementHandle;
            PKERBERR KerbErr;
            PULONG EncodedPubKeyLen;
            PBYTE* EncodedPubKey;
        } CreateECDHKeyAgreement;
        typedef struct {
            PKERB_RPC_CRYPTO_API_BLOB ModulusP;
            PKERB_RPC_CRYPTO_API_BLOB GeneratorG;
            PKERB_RPC_CRYPTO_API_BLOB FactorQ;
            PKEY_AGREEMENT_HANDLE KeyAgreementHandle;
            PKERBERR KerbErr;
            PULONG LittleEndianPublicKeyLen;
            PBYTE* LittleEndianPublicKey;
        } CreateDHKeyAgreement;
        typedef struct {
            UCHAR Ignored;
        } DestroyKeyAgreement;
        typedef struct {
            PULONG NonceLen;
            PBYTE* Nonce;
        } KeyAgreementGenerateNonce;
        typedef struct {
            PKERB_ENCRYPTION_KEY SharedKey;
        } FinalizeKeyAgreement;
    };
} KerbCredIsoRemoteOutput, *PKerbCredIsoRemoteOutput;

/// <summary>
/// The input buffer for remote credential ntlm calls.
/// </summary>
typedef struct _NtlmCredIsoRemoteInput {
    RemoteGuardCallId CallId;
    union {
        typedef struct {
            ULONG MaxSupportedVersion;
        } NegotiateVersion;
        typedef struct {
            PMSV1_0_REMOTE_PLAINTEXT_SECRETS Credential;
        } ProtectCredential;
        typedef struct {
            PMSV1_0_REMOTE_ENCRYPTED_SECRETS* Credential;
            PUNICODE_STRING UserName;
            PUNICODE_STRING LogonDomainName;
            PUNICODE_STRING ServerName;
            UCHAR ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
        } Lm20GetNtlm3ChallengeResponse;
        typedef struct {
            PNT_CHALLENGE NtChallenge;
            PMSV1_0_REMOTE_ENCRYPTED_SECRETS Credential;
        } CalculateNtResponse;
        typedef struct {
            PNT_RESPONSE NtResponse;
            PMSV1_0_REMOTE_ENCRYPTED_SECRETS Credential;
        } CalculateUserSessionKeyNt;
        typedef struct {
            PMSV1_0_REMOTE_ENCRYPTED_SECRETS LhsCredential;
            PMSV1_0_REMOTE_ENCRYPTED_SECRETS RhsCredential;
        } CompareCredentials;
    };
} NtlmCredIsoRemoteInput, *PNtlmCredIsoRemoteInput;

/// <summary>
/// The output buffer for remote credential ntlm calls.
/// </summary>
typedef struct _NtlmCredIsoRemoteOutput {
    RemoteGuardCallId CallId;
    LONG Status;
    union {
        typedef struct {
            ULONG VersionToUse;
        } NegotiateVersion;
        typedef struct {
            MSV1_0_REMOTE_ENCRYPTED_SECRETS Credential;
        } ProtectCredential;
        typedef struct {
            USHORT Ntlm3ResponseLength;
            PBYTE Ntlm3Response;
            MSV1_0_LM3_RESPONSE Lm3Response;
            USER_SESSION_KEY UserSessionKey;
            LM_SESSION_KEY LmSessionKey;
        } Lm20GetNtlm3ChallengeResponse;
        typedef struct {
            NT_RESPONSE NtResponse;
        } CalculateNtResponse;
        typedef struct {
            USER_SESSION_KEY UserSessionKey;
        } CalculateUserSessionKeyNt;
        typedef struct {
            BOOL AreNtOwfsEqual;
            BOOL AreLmOwfsEqual;
            BOOL AreShaOwfsEqual;
        } CompareCredentials;
    };
} NtlmCredIsoRemoteOutput, *PNtlmCredIsoRemoteOutput;

typedef struct _TSPkgRemoteCredGuardClientRequest {
    TSPkgCallPackageId CallId;
    LUID LogonId;
    UNICODE_STRING ClientPackageName;
} TSPkgRemoteCredGuardClientRequest, *PTSPkgRemoteCredGuardClientRequest;

typedef struct _TSPkgRemoteCredGuardClientResponse {
    LPVOID RedirectedLogonHandle;
    // clang-format off
    LONG(*OperationCallback)(PVOID, PVOID, ULONG, PVOID*, PULONG);
    VOID(*CleanupCallback)(PVOID);
    // clang-format on
} TSPkgRemoteCredGuardClientResponse, *PTSPkgRemoteCredGuardClientResponse;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Tspkg {
    // Enumerations
    using RemoteGuardCallId = _RemoteGuardCallId;
    using TSPkgCallPackageId = _TSPkgCallPackageId;

    using KerbCredIsoRemoteInput = _KerbCredIsoRemoteInput;
    using KerbCredIsoRemoteOutput = _KerbCredIsoRemoteOutput;
    using NtlmCredIsoRemoteInput = _NtlmCredIsoRemoteInput;
    using NtlmCredIsoRemoteOutput = _NtlmCredIsoRemoteOutput;
    using TSPkgRemoteCredGuardClientRequest = _TSPkgRemoteCredGuardClientRequest;
    using TSPkgRemoteCredGuardClientResponse = _TSPkgRemoteCredGuardClientResponse;
}
#endif