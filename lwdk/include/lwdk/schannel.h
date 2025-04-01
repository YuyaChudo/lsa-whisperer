// Copyright (C) 2024 Evan McBroom
//
// Secure channel (schannel)
//
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format ofn

#define SCHANNEL_USE_BLACKLISTS // Needed to get the full schannel header
#include "cpdk/ncrypt_provider.h"
#include "cpdk/sslprovider.h"
#include <schannel.h>

#define SSL_PURGE_CLIENT_ENTRIES                  0x00000001
#define SSL_PURGE_SERVER_ENTRIES                  0x00000002
#define SSL_PURGE_CLIENT_ALL_ENTRIES              0x00010000 // test use only
#define SSL_PURGE_SERVER_ALL_ENTRIES              0x00020000 // test use only
#define SSL_PURGE_SERVER_ENTRIES_DISCARD_LOCATORS 0x00040000 // test use only
#define SSL_RETRIEVE_CLIENT_ENTRIES               0x00000001
#define SSL_RETRIEVE_SERVER_ENTRIES               0x00000002

// Magic constants
#define MAGIC_DH1         (((DWORD)'D' << 8) + ((DWORD)'H' << 16) + ((DWORD)'1' << 24))
#define MAGIC_DSS1        ((DWORD)'D' + ((DWORD)'S' << 8) + ((DWORD)'S' << 16) + ((DWORD)'1' << 24))
#define MAGIC_DSS2        ((DWORD)'D' + ((DWORD)'S' << 8) + ((DWORD)'S' << 16) + ((DWORD)'2' << 24))
#define MAGIC_DSS3        ((DWORD)'D' + ((DWORD)'S' << 8) + ((DWORD)'S' << 16) + ((DWORD)'3' << 24))
#define PCT_CRED_MAGIC    *(DWORD*)"CtcP"
#define PCT_INVALID_MAGIC *(DWORD*)"eerF"
#define RSA1              ((DWORD)'R' + ((DWORD)'S' << 8) + ((DWORD)'A' << 16) + ((DWORD)'1' << 24))
#define RSA2              ((DWORD)'R' + ((DWORD)'S' << 8) + ((DWORD)'A' << 16) + ((DWORD)'2' << 24))
#define SP_CACHE_MAGIC    0xCACE
#define SP_CONTEXT_MAGIC  *(DWORD*)"!Tcp"

#ifdef __cplusplus
extern "C" {
#endif

enum eCacheItemType;
enum eCipherSuiteState;
enum eClientAuthTrustMode;
enum eDefClientCred;
enum eDtlsReorderState;
enum efAlgFlags;
enum efCredCertFlags;
enum efCredFlags;
enum efCredRevocationFlags;
enum eOptFlags;
enum eOptInEnableDisableRegVal;
enum eSniNameType;
enum eSslCipherSuite;
enum eSslErrorState;
enum eSslState;
enum eTlsCertificateType;
enum eTlsExtensionLoggingType;
enum eTlsExtensions;
enum eTlsHandshakeType;
enum eTlsHashIndex;
enum eTlsKeyExchangeMessageFlowStyle;
enum eTlsRecordType;
enum eTlsSignatureIndex;
enum eTlsSignatureStyle;

struct _CRED_THUMBPRINT;
struct _LSA_SCHANNEL_CRED;
struct _LSA_SCHANNEL_SUB_CRED;
struct _SCHANNEL_CIPHERSUFFIX_TO_CURVE;
struct _SSL_CERT_LOGON_REQ;
struct _SSL_CERT_LOGON_RESP;
struct _SSL_CERT_NAME_INFO;
struct _SSL_CIPHER_ENTRY;
struct _SSL_CIPHER_REGISTRY;
struct _SSL_CIPHER_SUITE;
struct _SSL_CIPHER_SUITE_REGISTRY;
struct _SSL_ENCODED_CERT_LOGON_REQ;
struct _SSL_ENCODED_CERT_LOGON_RESP;
struct _SSL_EPHEMERAL_KEY;
struct _SSL_EXTERNAL_CERT_LOGON_REQ;
struct _SSL_EXTERNAL_CERT_LOGON_RESP;
struct _SSL_KEY;
struct _SSL_KEYPAIR;
struct _SSL_MASTER_KEY;
struct _SSL_OBJECT;
struct _SSL_OPAQUE_BLOB;
struct _SSL_PACKED_CONTEXT;
struct _SSL_PERFMON_INFO_REQUEST;
struct _SSL_PERFMON_INFO_RESPONSE;
struct _SSL_PRE_MASTER_KEY;
struct _SSL_HASH;
struct _SSL_HASH_ENTRY;
struct _SSL_PROVIDER;
struct _SSL_PURGE_SESSION_CACHE_REQUEST;
struct _SSL_SESSION_CACHE_INFO_REQUEST;
struct _SSL_SESSION_CACHE_INFO_RESPONSE;
struct _SSL_STREAM_SIZES_REQ;
struct _SSL_STREAM_SIZES_RESP;

typedef enum eCacheItemType {
    CacheItem_Unknown = 0,
    CacheItem_Client = 1,
    CacheItem_Server = 2,
} eCacheItemType;

typedef enum eCipherSuiteState {
    efNotInitialized = 0,
    efPending = 1,
    efReadInit = 2,
    efWriteInit = 4,
    efComplete = 8,
} eCipherSuiteState;

typedef enum eClientAuthTrustMode {
    eMachineTrust = 0,
    eExclusiveRootTrust = 1,
    eExclusiveCATrust = 2,
    eLastClientAuthMode = 3,
} eClientAuthTrustMode;

typedef enum eDefClientCred {
    efSearchedNothing = 0,
    efSearchedCredMan = 1,
    efSearchedFind1 = 2,
    efSearchedFind2 = 3,
    efSearchedFind3 = 4,
    efSearchedFind4 = 5,
} eDefClientCred;

typedef enum eDtlsReorderState {
    DtlsState_Start = 0,
    DtlsState_Handshake = 1,
    DtlsState_Ccs = 2,
    DtlsState_Finished = 3,
    DtlsState_Connected = 4,
} eDtlsReorderState;

typedef enum efAlgFlags {
    afAlgFlags_Empty = 0,
    afAlgFlags_UserSignatureSpecified = 1,
    afAlgFlags_UserHashSpecified = 2,
    afAlgFlags_UserKeyXSpecified = 4,
    afAlgFlags_UserEncryptSpecified = 8,
} efAlgFlags;

typedef enum efCredCertFlags {
    afCredCert_Renewed = 1,
    afCredCert_FromMemoryStore = 2,
    afCredCert_ChainCacheOnlyUrlRetrieval = 4,
    afCredCert_SerializeCertRoot = 8,
    afCredCert_DisableOcsp = 16,
    afCredCert_LocalMachineMyStore = 32,
} efCredCertFlags;

typedef enum efCredFlags {
    afCredFlags_Empty = 0,
    afCredFlags_NoSystemMapper = 1,
    afCredFlags_NoServernameCheck = 2,
    afCredFlags_ManualCredValidation = 4,
    afCredFlags_NoDefaultCreds = 8,
    afCredFlags_UpdateIssuerList = 16,
    afCredFlags_DisableReconnects = 32,
    afCredFlags_CheckForRenewal = 64,
    afCredFlags_SendRootCert = 128,
    afCredFlags_AcknowledgeSni = 256,
    afCredFlags_DisableOcsp = 512,
    afCredFlags_SendAuxRecord = 1024,
    afCredFlags_UseStrongCrypto = 2048,
    afCredFlags_UsePresharedKeyOnly = 4096,
} efCredFlags;

typedef enum efCredRevocationFlags {
    afRevFlags_Empty = 0,
    afRevFlags_RevcheckEndCert = 256,
    afRevFlags_RevcheckChain = 512,
    afRevFlags_RevcheckChainExcludeRoot = 1024,
    afRevFlags_IgnoreNoRevocationCheck = 2048,
    afRevFlags_IgnoreRevocationOffline = 4096,
    afRevFlags_CacheOnlyUrlRetrieval = 8192,
    afRevFlags_RevocationCheckCacheOnly = 16384,
} efCredRevocationFlags;

typedef enum eOptFlags {
    eOptFlags_None = 0,
    eOptFlags_ContextLookaside = 1,
    eOptFlags_ContextDataLookaside = 2,
    eOptFlags_CacheLookaside = 4,
} eOptFlags;

typedef enum eOptInEnableDisableRegVal {
    eRegVal_OptIn = 0,
    eRegVal_EnableForAll = 1,
    eRegVal_DisableForAll = 2,
} eOptInEnableDisableRegVal;

typedef enum eSniNameType {
    TlsExt_Sni_NameType_HostName = 0,
} eSniNameType;

typedef enum eSslCipherSuite {
    CS_TLS_RSA_WITH_NULL_MD5 = 1,
    CS_TLS_RSA_WITH_NULL_SHA = 2,
    CS_TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 3,
    CS_TLS_RSA_WITH_RC4_128_MD5 = 4,
    CS_TLS_RSA_WITH_RC4_128_SHA = 5,
    CS_TLS_RSA_WITH_DES_CBC_SHA = 9,
    CS_TLS_RSA_WITH_3DES_EDE_CBC_SHA = 10,
    CS_TLS_DHE_DSS_WITH_DES_CBC_SHA = 18,
    CS_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 19,
    CS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 22,
    CS_TLS_RSA_WITH_AES_128_CBC_SHA = 47,
    CS_TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 50,
    CS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 51,
    CS_TLS_RSA_WITH_AES_256_CBC_SHA = 53,
    CS_TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 56,
    CS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 57,
    CS_TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA = 98,
    CS_TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA = 99,
    CS_TLS_RSA_EXPORT1024_WITH_RC4_56_SHA = 100,
    CS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xffffc009,
    CS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xffffc013,
    CS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xffffc00a,
    CS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xffffc014,
    CS_SSL_CK_RC4_128_WITH_MD5 = 0x10080,
    CS_SSL_CK_RC4_128_EXPORT40_WITH_MD5 = 0x20080,
    CS_SSL_CK_RC2_128_CBC_WITH_MD5 = 0x30080,
    CS_SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x40080,
    CS_SSL_CK_IDEA_128_CBC_WITH_MD5 = 0x50080,
    CS_SSL_CK_DES_64_CBC_WITH_MD5 = 0x60040,
    CS_SSL_CK_DES_192_EDE3_CBC_WITH_MD5 = 0x700c0,
    CS_TLS_PSK_WITH_AES_128_GCM_SHA256 = 168,
    CS_TLS_PSK_WITH_AES_256_GCM_SHA384 = 169,
    CS_TLS_PSK_WITH_AES_128_CBC_SHA256 = 174,
    CS_TLS_PSK_WITH_AES_256_CBC_SHA384 = 175,
    CS_TLS_PSK_WITH_NULL_SHA256 = 176,
    CS_TLS_PSK_WITH_NULL_SHA384 = 177,
    CS_TLS_RSA_WITH_NULL_SHA256 = 59,
    CS_TLS_RSA_WITH_AES_128_CBC_SHA256 = 60,
    CS_TLS_RSA_WITH_AES_256_CBC_SHA256 = 61,
    CS_TLS_RSA_WITH_AES_128_GCM_SHA256 = 156,
    CS_TLS_RSA_WITH_AES_256_GCM_SHA384 = 157,
    CS_TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 64,
    CS_TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 106,
    CS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 158,
    CS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 159,
    CS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xffffc023,
    CS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xffffc024,
    CS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xffffc02b,
    CS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xffffc02c,
    CS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xffffc027,
    CS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xffffc028,
    CS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xffffc02f,
    CS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xffffc030,
} eSslCipherSuite;

typedef enum eSslErrorState {
    ErrorState_None = 0,
    Parse_BadContentType = 10,
    Parse_BadProtoVersion = 11,
    Parse_BadHsHeader = 12,
    Parse_InsufficientMsg = 13,
    Alert_Tls1_1PlusClientDowngrade = 14,
    ServerHelloVerifyReq_Invalid = 90,
    ServerHello_Invalid = 100,
    ServerHello_InvalidAlg = 102,
    ServerHello_InvalidSessionId = 103,
    ServerHello_InvalidCompressField = 104,
    ServerHello_InvalidVersion = 105,
    ServerHello_ExtInvalid = 106,
    ServerHello_SetServerCipher = 107,
    ServerHello_InvalidRenegoInfo = 108,
    SrvHelloRsp_ChainTooLarge = 150,
    SrvHelloRsp_UserMapping = 151,
    SrvHelloRsp_GenCcsFin = 152,
    CertStatus_Unexpected = 200,
    CertStatus_Invalid = 201,
    RemoteCert_Invalid = 250,
    RemoteCert_PublicKey = 251,
    RemoteCert_SigAlg = 252,
    GenVerify_ComputeHash = 300,
    GenVerify_SignHash = 301,
    GenVerify_InvalidDeferred = 302,
    GenVerify_InvalidTLS1_2 = 303,
    GenVerify_SigAlg = 304,
    DigestCertReq_Invalid = 400,
    DigestCertReq_IssuerFormatting = 401,
    DigestCertReq_SigAlg = 402,
    ClientPreparse_Invalid = 500,
    ServerCert_Load = 550,
    ServerCert_GetChain = 551,
    ServerCert_VerifyChain = 552,
    ServerCert_WrongPrincipal = 553,
    MakeSessKey_GenKey = 600,
    MakeSessKey_GenParameterList = 601,
    MakeSessKey_GenMasterKey = 602,
    MakeEphemKey_CredFailure = 603,
    MakeSessKey_GenSessionHash = 604,
    MasterKey_Rsa_Invalid = 700,
    MasterKey_Rsa_Import = 701,
    MasterKey_Ecc_Invalid = 702,
    MasterKey_Ecc_Import = 703,
    MasterKey_Dh_Invalid = 704,
    MasterKey_Dh_Import = 705,
    MasterKey_Rsa_Gen = 706,
    MasterKey_Rsa_GenParameterList = 707,
    PreMasterKey_Rsa_Gen = 708,
    ClientCke_Invalid = 800,
    ClientCke_InvalidCurve = 801,
    ClientCke_RsaVerify = 802,
    ClientCke_EcdsaVerify = 803,
    ClientCke_Import = 804,
    ClientCke_GetEphemKey = 805,
    ClientCke_GetEphemKeyBlob = 806,
    ClientCke_Dh_Invalid = 807,
    ClientCke_Dh_GetEphemKey = 808,
    ClientCke_Dh_GetEphemKeyBlob = 809,
    ClientCke_Dh_Import = 810,
    ClientCke_Rsa_Invalid = 811,
    ClientCke_Rsa_NoPublicKey = 812,
    ClientCke_Rsa_Crypto = 813,
    ClientCke_Rsa_GenerateCke = 814,
    ClientCke_Rsa_ComputeHash = 815,
    ClientCke_Rsa_Verify = 816,
    ClientCke_Rsa_Import = 817,
    ClientCke_Rsa_GetEphem = 818,
    ClientCke_Rsa_GetEphemBlob = 819,
    ClientCke_Rsa_SignHash = 820,
    ClientCke_Ecdsa_SigAlg = 821,
    ClientCke_Dh_SigAlg = 822,
    ClientCke_DsaVerify = 823,
    ClientCke_Unexpected_Ske = 824,
    ClientCke_Ecdsa_NoPublicKey = 825,
    ClientCke_Ecdsa_GenerateCke = 826,
    ClientCke_Psk_Invalid = 827,
    Finished_MacMismatch = 900,
    Finished_GenHashFailure = 901,
    Finished_DigestHashFailure = 902,
    Finished_Invalid = 903,
    Ccs_Illegal = 904,
    CcsFinished_Wrap = 950,
    SrvHelloRspAlert_Wrap = 951,
    SrvHelloRsp_Wrap = 952,
    HelloReq_Wrap = 953,
    SrvReconnect_Wrap = 954,
    CliHelloRsp_Wrap_Final = 955,
    CliHelloRsp_Wrap_1stRecord = 957,
    CliHelloRsp_Wrap_2ndRecord = 958,
    Unwrap_Illegal = 959,
    Unwrap_DecryptFailure = 960,
    Unwrap_RemoteUserKey = 961,
    Unwrap_Tls1_1PlusClientDowngrade = 962,
    Unwrap_Invalid_Sequence_Number = 963,
    NewSessionTicket_Wrap = 964,
    Finished_UpdateHash = 1000,
    SrvHelloRsp_UpdateHash = 1001,
    SrvHelloRsp_UpdateHash_ClientCert = 1002,
    SrvHelloRsp_UpdateHash_Cke = 1003,
    SrvHelloRsp_UpdateHash_CertVerify = 1004,
    SrvReconnect_UpdateHash_CliHello = 1005,
    SrvReconnect_UpdateHash_SrvHello = 1006,
    CliHelloRsp_UpdateHash_CliHello = 1007,
    CliHelloRsp_UpdateHashFinal = 1008,
    CliHelloRsp_UpdateHash1stRecord = 1009,
    CliHelloRsp_UpdateHash2ndRecord = 1010,
    NewSessionTicket_UpdateHash = 1011,
    NextProtocol_UpdateHash = 1012,
    ServerSke_GetEphem = 1050,
    ServerSke_GetSigLen = 1051,
    SignRsa_ComputeHash = 1100,
    SignRsa_SignHash = 1101,
    SignEcdsa_ComputeHash = 1102,
    SignEcdsa_SignHash = 1103,
    SignEcdsa_Encode = 1104,
    VerifyRsa_ComputeHash = 1105,
    VerifyRsa_Verify = 1106,
    VerifyEcdsa_Crypto = 1107,
    VerifyEcdsa_Decode = 1108,
    VerifyEcdsa_ComputeHash = 1109,
    VerifyEcdsa_Verify = 1110,
    SignDss_ComputeHash = 1111,
    SignDss_SignHash = 1112,
    SignDss_Encode = 1113,
    VerifyDss_Decode = 1114,
    VerifyDss_ComputeHash = 1115,
    VerifyDss_Verify = 1116,
    VerifyDss_PublicKey = 1117,
    SrvCliHello_Invalid = 1200,
    SrvCliHello_ProtoInvalid = 1201,
    SrvCliHello_ExtInvalid = 1202,
    SrvCliUniHello_Invalid = 1203,
    SrvCliUniHello_MismatchAlg = 1204,
    SrvCliHello_MismatchAlg = 1205,
    SrvCliHello_MismatchSigAlg = 1206,
    SrvCliHello_InvalidRenegoInfo = 1207,
    SrvCliHello_NoAppProtocol = 1208,
    SrvCliResp_SkeFailed = 1250,
    SrvCliResp_CertReq = 1251,
    ValidateCertVerify_Illegal = 1300,
    ValidateCertVerify_KeyLen = 1301,
    ValidateCertVerify_Illegal_Alg = 1302,
    ValidateCertVerify_ComputeHash = 1303,
    ValidateCertVerify_ConvertBcrypt = 1304,
    ValidateCertVerify_Decode = 1305,
    ValidateCertVerify_Sig = 1306,
    ValidateCertVerify_SigAlg = 1307,
    SessionTicket_Cli_InvalidSize = 1400,
    SessionTicket_Cli_MismatchedSize = 1401,
    SessionTicket_Cli_Unexpected = 1402,
    NextProtocol_Unexpected = 1500,
    NextProtocol_InvalidSize = 1501,
    NextProtocol_InvalidPadding = 1502,
    Cred_BadCspTypeForRsaProvider = 10000,
    Cred_GetServerPrivateKeyFailed = 10001,
    Cred_OpenKeyUsingCngFailed = 10002,
    Cred_RemoteOpenClientKeyFailed = 10003,
    Cred_CertDuplicateFailed = 10004,
    Cred_CertGetPublicKeyFailed = 10005,
    Cred_CertGetPublicKeyLenFailed = 10006,
    Cred_CertSerializationFailed = 10007,
    Cred_CertTooLarge = 10008,
    Cred_FillCertInfoFailed = 10009,
    Cred_InitMinMaxStrengthsFailed = 10010,
    Cred_BuildUserAlgsFailed = 10011,
    Cred_RootStoreChangeFailed = 10012,
    Cred_InitEnabledProtocolsFailed = 10013,
    Cred_OpenKeyUsingCapiFailed = 10014,
    Cred_GetCertEndpointBindingsFailed = 10015,
    ErrorState_Max = 0xffffffff,
} eSslErrorState;

typedef enum eSslState {
    SslState_None = 0,
    SslState_Error = 1,
    SslState_ShutdownPending = 2,
    SslState_Shutdown = 3,
    SslState_Connected = 4,
    SslState_ReceivedUniHello = 20,
    SslState_TlsCli_ClientHello = 40,
    SslState_TlsCli_ServerCert = 41,
    SslState_TlsCli_CertStatus = 42,
    SslState_TlsCli_ServerKeyX = 43,
    SslState_TlsCli_ServerCertReq = 44,
    SslState_TlsCli_ClientCcs = 45,
    SslState_TlsCli_ClientFinish = 46,
    SslState_TlsCli_ReconnectClientCcs = 47,
    SslState_TlsCli_ReconnectServerFinish = 48,
    SslState_TlsCli_DeferredSignature = 49,
    SslState_TlsCli_NewSessionTicket = 50,
    SslState_TlsCli_FalseStart = 51,
    SslState_TlsCli_RenewSessionTicket = 52,
    SslState_TlsSrv_ClientCertificate = 60,
    SslState_TlsSrv_ClientKeyX = 61,
    SslState_TlsSrv_CertVerify = 62,
    SslState_TlsSrv_ServerCcs = 63,
    SslState_TlsSrv_ReconnectServerHello = 64,
    SslState_TlsSrv_ReconnectServerCcs = 65,
    SslState_TlsSrv_NextProtocol = 66,
    SslState_TlsSrv_ReconnectNextProtocol = 67,
    SslState_TlsServerHello = 70,
    SslState_TlsNoCertificateAlert = 75,
    SslState_TlsRenegotiate = 76,
    SslState_TlsRetrieveUserData = 77,
    SslState_TlsGenerateStart = 90,
    SslState_TlsGenServerHelloResponse = 91,
    SslState_TlsGenClientFinishReconnect = 92,
    SslState_TlsGenServerHello = 93,
    SslState_TlsGenServerHelloReconnect = 94,
    SslState_TlsGenServerFinish = 95,
    SslState_TlsError = 96,
    SslState_DTlsHelloVerify = 97,
    SslState_TlsGenerateEnd = 98,
    SslState_Max = 255,
} eSslState;

typedef enum eTlsCertificateType {
    TlsCerttype_Undefined = 0,
    TlsCerttype_RsaSign = 1,
    TlsCerttype_DssSign = 2,
    TlsCerttype_RsaFixedDh = 3,
    TlsCerttype_DssFixedDh = 4,
    TlsCerttype_RsaEphemeralDh = 5,
    TlsCerttype_DssEphemeralDh = 6,
    TlsCerttype_FortezzaKea = 20,
    TlsCerttype_EcdsaSign = 64,
} eTlsCertificateType;

typedef enum eTlsExtensionLoggingType {
    Sent = 0,
    Received = 1,
} eTlsExtensionLoggingType;

typedef enum eTlsExtensions {
    TlsExt_ServerName = 0,
    TlsExt_MaxFragmentLen = 1,
    TlsExt_ClientCertUrl = 2,
    TlsExt_TrustedCaKeys = 3,
    TlsExt_TruncatedHmac = 4,
    TlsExt_StatusRequest = 5,
    TlsExt_UsermapData = 6,
    TlsExt_EllipticCurve = 10,
    TlsExt_EccPointsFormat = 11,
    TlsExt_SignatureAlgorithms = 13,
    TlsExt_UseSrtp = 14,
    TlsExt_AppProtocolNegotiation = 16,
    TlsExt_ExtendedMasterSecret = 23,
    TlsExt_SessionTicket = 35,
    TlsExt_NextProtocolNegotiation = 13172,
    TlsExt_TokenBinding = 21760,
    TlsExt_RenegotiationInfo = 0xffffff01,
} eTlsExtensions;

typedef enum eTlsHandshakeType {
    TlsHandshake_HelloRequest = 0,
    TlsHandshake_ClientHello = 1,
    TlsHandshake_ServerHello = 2,
    TlsHandshake_HelloVerifyRequest = 3,
    TlsHandshake_NewSessionTicket = 4,
    TlsHandshake_Certificate = 11,
    TlsHandshake_ServerKeyX = 12,
    TlsHandshake_CertificateRequest = 13,
    TlsHandshake_ServerHelloDone = 14,
    TlsHandshake_CertificateVerify = 15,
    TlsHandshake_ClientKeyX = 16,
    TlsHandshake_Finished = 20,
    TlsHandshake_CertStatus = 22,
    TlsHandshake_SupplementalData = 23,
    TlsHandshake_NextProtocol = 67,
} eTlsHandshakeType;

typedef enum eTlsHashIndex {
    TlsHashIndex_None = 0,
    TlsHashIndex_Md5 = 1,
    TlsHashIndex_First = 1,
    TlsHashIndex_Sha1 = 2,
    TlsHashIndex_Sha224 = 3,
    TlsHashIndex_Sha256 = 4,
    TlsHashIndex_FirstPRF = 4,
    TlsHashIndex_Sha384 = 5,
    TlsHashIndex_Sha512 = 6,
} eTlsHashIndex;

typedef enum eTlsKeyExchangeMessageFlowStyle {
    TlsKeyExchangeMessageFlowStyle_Unknown = 0,
    TlsKeyExchangeMessageFlowStyle_Rsa = 1,
    TlsKeyExchangeMessageFlowStyle_Dh = 2,
    TlsKeyExchangeMessageFlowStyle_Ecdh = 3,
    TlsKeyExchangeMessageFlowStyle_Psk = 4,
} eTlsKeyExchangeMessageFlowStyle;

typedef enum eTlsRecordType {
    TlsRecord_ChangeCipherSpec = 20,
    TlsRecord_Alert = 21,
    TlsRecord_Handshake = 22,
    TlsRecord_ApplicationData = 23,
} eTlsRecordType;

typedef enum eTlsSignatureIndex {
    TlsSignatureIndex_Anonymous = 0,
    TlsSignatureIndex_Rsa = 1,
    TlsSignatureIndex_First = 1,
    TlsSignatureIndex_Dsa = 2,
    TlsSignatureIndex_Ecdsa = 3,
} eTlsSignatureIndex;

typedef enum eTlsSignatureStyle {
    TlsSignatureStyle_Unknown = 0,
    TlsSignatureStyle_Anonymous = 1,
    TlsSignatureStyle_Rsa = 2,
    TlsSignatureStyle_Dsa = 3,
    TlsSignatureStyle_Ecdsa = 4,
} eTlsSignatureStyle;

typedef struct _CRED_THUMBPRINT {
    DWORD LowPart;
    DWORD HighPart;
} CRED_THUMBPRINT, *PCRED_THUMBPRINT;

typedef struct _LSA_SCHANNEL_SUB_CRED {
    PCCERT_CONTEXT pCert;
    LPWSTR pszPin;
    HCRYPTPROV hRemoteProv;
    LPVOID pPrivateKey;
    DWORD cbPrivateKey;
    LPSTR pszPassword;
} LSA_SCHANNEL_SUB_CRED, *PLSA_SCHANNEL_SUB_CRED;

typedef struct _LSA_SCHANNEL_CRED {
    DWORD dwVersion;
    DWORD cSubCreds;
    PLSA_SCHANNEL_SUB_CRED paSubCred;
    HCERTSTORE hRootStore;
    DWORD cMappers;
    struct _HMAPPER** aphMappers; // Defined in Microsoft sources in certmap.h
    DWORD cSupportedAlgs;
    ALG_ID* palgSupportedAlgs;
    DWORD grbitEnabledProtocols;
    DWORD dwMinimumCipherStrength;
    DWORD dwMaximumCipherStrength;
    DWORD dwSessionLifespan;
    DWORD dwFlags;
    DWORD reserved;
} LSA_SCHANNEL_CRED, *PLSA_SCHANNEL_CRED;

typedef struct _SCHANNEL_CIPHERSUFFIX_TO_CURVE {
    LPWSTR pwszCipherSuffix;
    NCRYPT_SSL_ECC_CURVE SslEccCurve;
} SCHANNEL_CIPHERSUFFIX_TO_CURVE, *PSCHANNEL_CIPHERSUFFIX_TO_CURVE;

/// <summary>Asn.1 encoded name.</summary>
typedef struct _SSL_CERT_NAME_INFO {
    ULONG IssuerOffset;
    ULONG IssuerLength;
} SSL_CERT_NAME_INFO, *PSSL_CERT_NAME_INFO;

typedef struct _SSL_CERT_LOGON_REQ {
    ULONG MessageType;
    ULONG Length;
    ULONG OffsetCertificate;
    ULONG CertLength;
    ULONG Flags;
    ULONG CertCount;
    SSL_CERT_NAME_INFO NameInfo[ANYSIZE_ARRAY];
} SSL_CERT_LOGON_REQ, *PSSL_CERT_LOGON_REQ;

typedef struct _SSL_CERT_LOGON_RESP {
    ULONG MessageType;
    ULONG Length;
    ULONG OffsetAuthData;
    ULONG AuthDataLength;
    ULONG Flags;
    ULONG OffsetDomain;
    ULONG DomainLength;
    ULONG Align;
} SSL_CERT_LOGON_RESP, *PSSL_CERT_LOGON_RESP;

typedef struct _SSL_CIPHER_ENTRY {
    HANDLE hProvider;
    ULONG cbObject;
    BOOL fLoaded;
} SSL_CIPHER_ENTRY, *PSSL_CIPHER_ENTRY;

typedef struct _SSL_CIPHER_REGISTRY {
    LPWSTR wszCipher[NCRYPT_SSL_MAX_NAME_SIZE];
    LPWSTR wszCipherMode[NCRYPT_SSL_MAX_NAME_SIZE];
} SSL_CIPHER_REGISTRY, *PSSL_CIPHER_REGISTRY;

typedef struct _SSL_CIPHER_SUITE {
    DWORD dwProtocols;
    DWORD dwCipherSuite;
    LPWSTR pszCipherSuite;
    LPWSTR pszCipher;
    ULONG aiCipher;
    DWORD dwCipherBits;
    DWORD dwCipherBytes;
    DWORD dwBlockLen;
    DWORD dwCipherIndex;
    LPWSTR pszCipherMode;
    LPWSTR pszHash;
    ULONG aiHash;
    DWORD dwHashLen;
    DWORD dwHashIndex;
    LPWSTR pszExchange;
    ULONG aiExchange;
    DWORD dwMinExchangeLen;
    DWORD dwMaxExchangeLen;
    eTlsKeyExchangeMessageFlowStyle MessageFlowStyle;
    LPWSTR pszKDF;
    DWORD dwPaddingFlags;
    LPWSTR pszCertificate;
    BOOL fExport;
    LPWSTR pszPRFHash;
} SSL_CIPHER_SUITE, *PSSL_CIPHER_SUITE;

typedef struct _SSL_CIPHER_SUITE_REGISTRY {
    DWORD dwVersion;
    DWORD dwProtocols;
    DWORD dwCipherSuite;
    WCHAR wszCipherSuiteName[NCRYPT_SSL_MAX_NAME_SIZE];
    WCHAR wszHash[NCRYPT_SSL_MAX_NAME_SIZE];
    WCHAR wszCipher[NCRYPT_SSL_MAX_NAME_SIZE];
    DWORD dwCipherBits;
    DWORD dwCipherBytes;
    WCHAR wszCipherMode[NCRYPT_SSL_MAX_NAME_SIZE];
    WCHAR wszKeyExchange[NCRYPT_SSL_MAX_NAME_SIZE];
    DWORD dwMinExchangeLen;
    DWORD dwMaxExchangeLen;
    WCHAR wszSignature[NCRYPT_SSL_MAX_NAME_SIZE];
    WCHAR wszKDF[NCRYPT_SSL_MAX_NAME_SIZE];
    WCHAR wszPRFHash[NCRYPT_SSL_MAX_NAME_SIZE];
    DWORD dwPaddingFlags;
} SSL_CIPHER_SUITE_REGISTRY, *PSSL_CIPHER_SUITE_REGISTRY;

typedef struct _SSL_ENCODED_CERT_LOGON_REQ {
    ULONG MessageType;
    ULONG Length;
    ULONG CredentialType;
    ULONG CertEncodingType;
    ULONG CertEncodedLength;
    LPVOID CertEncoded;
    ULONG Flags;
} SSL_ENCODED_CERT_LOGON_REQ, *PSSL_ENCODED_CERT_LOGON_REQ;

typedef struct _SSL_ENCODED_CERT_LOGON_RESP {
    ULONG MessageType;
    ULONG Length;
    LPVOID UserToken;
    DWORD Flags;
} SSL_ENCODED_CERT_LOGON_RESP, *PSSL_ENCODED_CERT_LOGON_RESP;

typedef struct _SSL_EPHEMERAL_KEY {
    ULONG cbLength;
    DWORD dwMagic;
    ULONG aiAlgorithm;
    HANDLE hProvider;
    HANDLE hSubKey;
    DWORD dwKeyType;
} SSL_EPHEMERAL_KEY, *PSSL_EPHEMERAL_KEY;

typedef struct _SSL_EXTERNAL_CERT_LOGON_REQ {
    ULONG MessageType;
    ULONG Length;
    ULONG CredentialType;
    LPVOID Credential;
    ULONG Flags;
} SSL_EXTERNAL_CERT_LOGON_REQ, *PSSL_EXTERNAL_CERT_LOGON_REQ;

typedef struct _SSL_EXTERNAL_CERT_LOGON_RESP {
    ULONG MessageType;
    ULONG Length;
    LPVOID UserToken;
    ULONG Flags;
} SSL_EXTERNAL_CERT_LOGON_RESP, *PSSL_EXTERNAL_CERT_LOGON_RESP;

/// <summary>Data referenced by NCRYPT_KEY_HANDLE. Used as the SSL session key.</summary>
typedef struct _SSL_KEY {
    ULONG cbLength;
    DWORD dwMagic;
    DWORD dwProtocol;
    const PSSL_CIPHER_SUITE pCipherSuite;
    BOOL fReadKey;
    HANDLE hKey;
    PBYTE pbIVRandom;
    ULONG cbIVRandom;
    DWORD dwIVRandomOffset;
    union {
        BYTE rgbMac[48];
        BYTE rgbAeadNonceImplicit[4];
    };
    union {
        ULONG cbMac;
        ULONG cbAeadNonceImplicit;
    };
} SSL_KEY, *PSSL_KEY;

typedef struct _SSL_KEYPAIR {
    ULONG cbLength;
    DWORD dwMagic;
    ULONG aiAlgorithm;
    HANDLE hProvider;
    HANDLE hSubKey;
} SSL_KEYPAIR, *PSSL_KEYPAIR;

typedef struct _SSL_MASTER_KEY {
    ULONG cbLength;
    DWORD dwMagic;
    DWORD dwProtocol;
    const PSSL_CIPHER_SUITE pCipherSuite;
    BOOL fClient;
    BYTE rgbMasterKey[48];
    ULONG cbMasterKey;
} SSL_MASTER_KEY, *PSSL_MASTER_KEY;

typedef struct _SSL_OBJECT {
    ULONG cbLength;
    DWORD dwMagic;
} SSL_OBJECT, *PSSL_OBJECT;

/// <summary>Used to store blobs with a magic of SSL3.</summary>
typedef struct _SSL_OPAQUE_BLOB {
    ULONG cbLength;
    DWORD dwMagic;
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    union {
        BOOL fReadKey;
        BOOL fClient;
    };
    ULONG cbKeyBlob;
    union {
        ULONG cbMac;
        ULONG cbAeadNonceImplicit;
        ULONG cbMasterKey;
    };
    union {
        BYTE rgbMac[48];
        BYTE rgbAeadNonceImplicit[4];
        BYTE rgbMasterKey[48];
    };
} SSL_OPAQUE_BLOB, *PSSL_OPAQUE_BLOB;

/// <summary>Defined for its use in _SSL_PACKED_CONTEXT.</summary>
typedef struct _CC_POLICY_RESULT {
    HRESULT hrPolicyResult;
} CC_POLICY_RESULT, *PCC_POLICY_RESULT;

typedef struct _SSL_PACKED_CONTEXT {
    ULONG State;
    ULONG Flags;
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    DWORD dwKeyType;
    DWORD dwExchStrength;
    DWORD dwCipherHeaderLen;
    DWORD dwAuxRecordLen;
    DWORD dwLocalCertKeySize;
    ULONGLONG ReadCounter;
    ULONGLONG WriteCounter;
    ULARGE_INTEGER hLocator;
    ULONG LocatorStatus;
    LARGE_INTEGER Wow64LsaHandle;
    ULONG cbSessionID;
    BYTE SessionID[32];
    ULONG cbSessionKey;
    BYTE SessionKey[16];
    CC_POLICY_RESULT PolicyResults;
    DWORD dwRecordLayerHeaderLen;
    ULONGLONG CurrentRecordWindow;
    ULONGLONG StartValidWindow;
    LONG DtlsReadLatestEpoch;
    USHORT PMTU;
    USHORT maxPayload;
    DWORD dwNextHsSeqNum;
} SSL_PACKED_CONTEXT, *PSSL_PACKED_CONTEXT;

typedef struct _SSL_PERFMON_INFO_REQUEST {
    ULONG MessageType;
    DWORD Flags;
} SSL_PERFMON_INFO_REQUEST, *PSSL_PERFMON_INFO_REQUEST;

typedef struct _SSL_PERFMON_INFO_RESPONSE {
    DWORD ClientCacheEntries;
    DWORD ServerCacheEntries;
    DWORD ClientActiveEntries;
    DWORD ServerActiveEntries;
    DWORD ClientHandshakesPerSecond;
    DWORD ServerHandshakesPerSecond;
    DWORD ClientReconnectsPerSecond;
    DWORD ServerReconnectsPerSecond;
} SSL_PERFMON_INFO_RESPONSE, *PSSL_PERFMON_INFO_RESPONSE;

typedef struct _SSL_PRE_MASTER_KEY {
    ULONG cbLength;
    DWORD dwMagic;
    DWORD dwProtocol;
    BYTE rgbPreMasterKey[48];
} SSL_PRE_MASTER_KEY, *PSSL_PRE_MASTER_KEY;

typedef struct _SSL_HASH {
    ULONG cbLength;
    DWORD dwMagic;
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    HANDLE hHash;
    ULONG cbHashObject;
    DWORD dwHashLen;
    HANDLE hMd5Hash;
    ULONG cbMd5HashObject;
} SSL_HASH, *PSSL_HASH;

/// <summary>Data referenced by NCRYPT_HASH_HANDLE.</summary>
typedef struct _SSL_HASH_ENTRY {
    HANDLE hProvider;
    HANDLE hHmacProvider;
    ULONG cbObject;
    ULONG cbHmacObject;
    DWORD dwHashLen;
    BOOL fLoaded;
} SSL_HASH_ENTRY, *PSSL_HASH_ENTRY;

/// <summary>Data referenced by NCRYPT_PROV_HANDLE.</summary>
typedef struct _SSL_PROVIDER {
    ULONG cbLength;
    DWORD dwMagic;
    ULONG RefCount;
    ULONG AlgorithmFlags;
    SSL_CIPHER_ENTRY Ciphers[16];
    SSL_HASH_ENTRY Hashes[16];
} SSL_PROVIDER, *PSSL_PROVIDER;

typedef struct _SSL_PURGE_SESSION_CACHE_REQUEST {
    ULONG MessageType;
    LUID LogonId;
    UNICODE_STRING ServerName;
    ULONG Flags;
} SSL_PURGE_SESSION_CACHE_REQUEST, *PSSL_PURGE_SESSION_CACHE_REQUEST;

typedef struct _SSL_SESSION_CACHE_INFO_REQUEST {
    ULONG MessageType;
    LUID LogonId;
    UNICODE_STRING ServerName;
    ULONG Flags;
} SSL_SESSION_CACHE_INFO_REQUEST, *PSSL_SESSION_CACHE_INFO_REQUEST;

typedef struct _SSL_SESSION_CACHE_INFO_RESPONSE {
    ULONG CacheSize;
    ULONG Entries;
    ULONG ActiveEntries;
    ULONG Zombies;
    ULONG ExpiredZombies;
    ULONG AbortedZombies;
    ULONG DeletedZombies;
} SSL_SESSION_CACHE_INFO_RESPONSE, *PSSL_SESSION_CACHE_INFO_RESPONSE;

typedef struct _SSL_STREAM_SIZES_REQ {
    ULONG MessageType;
} SSL_STREAM_SIZES_REQ, *PSSL_STREAM_SIZES_REQ;

typedef struct _SSL_STREAM_SIZES_RESP {
    ULONG MessageType;
    ULONG Length;
    ULONG cbHeader;
    ULONG cbTrailer;
} SSL_STREAM_SIZES_RESP, *PSSL_STREAM_SIZES_RESP;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Schannel {
    // Enumerations
    using AlgFlags = efAlgFlags;
    using CacheItemType = eCacheItemType;
    using CipherSuiteState = eCipherSuiteState;
    using ClientAuthTrustMode = eClientAuthTrustMode;
    using CredCertFlags = efCredCertFlags;
    using CredFlags = efCredFlags;
    using CredRevocationFlags = efCredRevocationFlags;
    using DefClientCred = eDefClientCred;
    using DtlsReorderState = eDtlsReorderState;
    using OptFlags = eOptFlags;
    using OptInEnableDisableRegVal = eOptInEnableDisableRegVal;
    using SchGetExtensionsOptions = _SchGetExtensionsOptions;
    using SniNameType = eSniNameType;
    using SslCipherSuite = eSslCipherSuite;
    using SslErrorState = eSslErrorState;
    using SslState = eSslState;
    using TlsAlgorithmUsage = _eTlsAlgorithmUsage;
    using TlsCertificateType = eTlsCertificateType;
    using TlsExtensionLoggingType = eTlsExtensionLoggingType;
    using TlsExtensions = eTlsExtensions;
    using TlsHandshakeType = eTlsHandshakeType;
    using TlsHashAlgorithm = _eTlsHashAlgorithm;
    using TlsHashIndex = eTlsHashIndex;
    using TlsKeyExchangeMessageFlowStyle = eTlsKeyExchangeMessageFlowStyle;
    using TlsRecordType = eTlsRecordType;
    using TlsSignatureAlgorithm = _eTlsSignatureAlgorithm;
    using TlsSignatureIndex = eTlsSignatureIndex;
    using TlsSignatureStyle = eTlsSignatureStyle;

    using LSA_SCHANNEL_CRED = _LSA_SCHANNEL_CRED;
    using LSA_SCHANNEL_SUB_CRED = _LSA_SCHANNEL_SUB_CRED;

    using SCH_CRED = _SCH_CRED;
    using SCH_CRED_PUBLIC_CERTCHAIN = _SCH_CRED_PUBLIC_CERTCHAIN;
    using SCH_CRED_SECRET_CAPI = _SCH_CRED_SECRET_CAPI;
    using SCH_CRED_SECRET_PRIVKEY = _SCH_CRED_SECRET_PRIVKEY;
    using SCH_CREDENTIALS = _SCH_CREDENTIALS;
    using SCH_EXTENSION_DATA = _SCH_EXTENSION_DATA;

    using SCHANNEL_ALERT_TOKEN = _SCHANNEL_ALERT_TOKEN;
    using SCHANNEL_ALG = _SCHANNEL_ALG;
    using SCHANNEL_CERT_HASH = _SCHANNEL_CERT_HASH;
    using SCHANNEL_CERT_HASH_STORE = _SCHANNEL_CERT_HASH_STORE;
    using SCHANNEL_CIPHERSUFFIX_TO_CURVE = _SCHANNEL_CIPHERSUFFIX_TO_CURVE;
    using SCHANNEL_CLIENT_SIGNATURE = _SCHANNEL_CLIENT_SIGNATURE;
    using SCHANNEL_CRED = _SCHANNEL_CRED;
    using SCHANNEL_SESSION_TOKEN = _SCHANNEL_SESSION_TOKEN;

    using SSL_CERT_LOGON_REQ = _SSL_CERT_LOGON_REQ;
    using SSL_CERT_LOGON_RESP = _SSL_CERT_LOGON_RESP;
    using SSL_CERT_NAME_INFO = _SSL_CERT_NAME_INFO;
    using SSL_CIPHER_ENTRY = _SSL_CIPHER_ENTRY;
    using SSL_CIPHER_REGISTRY = _SSL_CIPHER_REGISTRY;
    using SSL_CIPHER_SUITE = _SSL_CIPHER_SUITE;
    using SSL_CIPHER_SUITE_REGISTRY = _SSL_CIPHER_SUITE_REGISTRY;
    using SSL_CREDENTIAL_CERTIFICATE = _SSL_CREDENTIAL_CERTIFICATE;
    using SSL_ECCKEY_BLOB = _SSL_ECCKEY_BLOB;
    using SSL_ENCODED_CERT_LOGON_REQ = _SSL_ENCODED_CERT_LOGON_REQ;
    using SSL_ENCODED_CERT_LOGON_RESP = _SSL_ENCODED_CERT_LOGON_RESP;
    using SSL_EPHEMERAL_KEY = _SSL_EPHEMERAL_KEY;
    using SSL_EXTERNAL_CERT_LOGON_REQ = _SSL_EXTERNAL_CERT_LOGON_REQ;
    using SSL_EXTERNAL_CERT_LOGON_RESP = _SSL_EXTERNAL_CERT_LOGON_RESP;
    using SSL_HASH = _SSL_HASH;
    using SSL_HASH_ENTRY = _SSL_HASH_ENTRY;
    using SSL_KEY = _SSL_KEY;
    using SSL_KEYPAIR = _SSL_KEYPAIR;
    using SSL_MASTER_KEY = _SSL_MASTER_KEY;
    using SSL_OBJECT = _SSL_OBJECT;
    using SSL_OPAQUE_BLOB = _SSL_OPAQUE_BLOB;
    using SSL_PACKED_CONTEXT = _SSL_PACKED_CONTEXT;
    using SSL_PERFMON_INFO_REQUEST = _SSL_PERFMON_INFO_REQUEST;
    using SSL_PERFMON_INFO_RESPONSE = _SSL_PERFMON_INFO_RESPONSE;
    using SSL_PRE_MASTER_KEY = _SSL_PRE_MASTER_KEY;
    using SSL_PROVIDER = _SSL_PROVIDER;
    using SSL_PURGE_SESSION_CACHE_REQUEST = _SSL_PURGE_SESSION_CACHE_REQUEST;
    using SSL_SESSION_CACHE_INFO_REQUEST = _SSL_SESSION_CACHE_INFO_REQUEST;
    using SSL_SESSION_CACHE_INFO_RESPONSE = _SSL_SESSION_CACHE_INFO_RESPONSE;
    using SSL_STREAM_SIZES_REQ = _SSL_STREAM_SIZES_REQ;
    using SSL_STREAM_SIZES_RESP = _SSL_STREAM_SIZES_RESP;

    // Miscellaneous
    using CRED_THUMBPRINT = _CRED_THUMBPRINT;
    using CRYPTO_SETTINGS = _CRYPTO_SETTINGS;
    using PctPublicKey = _PctPublicKey;
    using SEND_GENERIC_TLS_EXTENSION = _SEND_GENERIC_TLS_EXTENSION;
    using SUBSCRIBE_GENERIC_TLS_EXTENSION = _SUBSCRIBE_GENERIC_TLS_EXTENSION;
    using TLS_EXTENSION_SUBSCRIPTION = _TLS_EXTENSION_SUBSCRIPTION;
    using TLS_PARAMETERS = _TLS_PARAMETERS;
    using X509Certificate = _X509Certificate;
}
#endif