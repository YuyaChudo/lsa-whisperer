// Copyright (C) 2024 Evan McBroom
//
// Cloud authentication package (cloudap) which includes plugins for
// - Entra id, formally known as azure ad (aad)
// - Microsoft account (msa), formally known as live accounts
//
// These types were accurate at the time they were audited but they will
// likely experience significant changes. Microsoft's internal types for
// cloud technologies have shown to be less stable than type collections
// for other Windows technologies.
//
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

#include "cloudap_m.h"
#include "native.h"
#include <lmcons.h>
#include <lmjoin.h>
#include <sspi.h>

#define CLOUDAP_NAME_A "cloudap"

#ifdef __cplusplus
extern "C" {
#endif

enum _DSR_INSTANCE;
enum AadCredentialType;
enum AadTracingEventType;
struct _AAD_CREDUI_CREDS;
struct _AAD_LOGON_CRED;
struct _AadApPluginEnterpriseSTSInfo;
struct _AadApPluginHandle;
struct _AadApPluginKeyInfo;
struct _AadApPluginTokenInfo;
struct _AadApPluginTokenUpdateInfo;
struct _AadApPluginUserRealmInfo;
struct _AadNetworkConfig;
struct _AP_BLOB;
struct _APPLUGIN_PWD_EXPIRY_INFO;
struct _APPLUGIN_SECPKG_FUNCTION_TABLE_NETWORK_CALLS_OK;
struct _APPLUGIN_SECPKG_FUNCTION_TABLE_NO_NETWORK_CALLS;
struct _APPLUGIN_SECPKG_FUNCTION_TABLE;
struct _APPLUGIN_SSO_USER_INFO;
struct _APPLUGIN_USER_INFO;
struct _ApPluginPkg;
struct _ApPluginSubPkg;
struct _CLOUD_COMMAND;
struct _CLOUD_DATA_TRANSFER;
struct _CLOUD_PROPERTY_BLOB_CONTEXT;
struct _CLOUD_PROVIDER_GET_EXTERNAL_INFO;
struct _CLOUD_PROVIDER_MESSAGE;
struct _CLOUD_PROVIDER_SET_EXTERNAL_INFO;
struct _CLOUDAP_SECPKG_FUNCTION_TABLE;
struct _DPAPI_DECODED_AUTH_DATA;
struct _tagCloudAPGenericCallPkgInput;
struct _tagCloudAPGetAuthenticatingProviderInput;
struct _tagCloudAPGetTokenInput;
struct _tagCloudAPProfileDeletedInput;
struct _tagCloudAPPwdExpiryInfoOutput;
struct _tagCloudAPRefreshTokenInput;
struct _tagCloudAPReinitPluginsInput;
struct _tagCloudAPRenameAccountInput;
struct _tagCloudAPSetIdCacheFlushParasInput;
struct _tagSCLock;
struct AadCredBagIndex;
struct AADTB_REQUEST;

typedef enum _DSR_INSTANCE {
    DSR_INSTANCE_ADRS = 0,
    DSR_INSTANCE_ENTDRS = 1,
} DSR_INSTANCE,
    *PDSR_INSTANCE;

typedef enum AadCredentialType {
    unknown = 0,
    password = 1,
    ngc = 2,
    x509 = 3,
    token = 4,
} AadCredentialType,
    *PAadCredentialType;

typedef enum AadTracingEventType {
    core = 0,
    authbuffer = 1,
    credman = 2,
} AadTracingEventType,
    *PAadTracingEventType;

typedef struct _AAD_CREDUI_CREDS {
    USHORT cbHeaderLength;
    USHORT cbStructureLength;
    SEC_WINNT_AUTH_BYTE_VECTOR AuthInfo;
    ULONG RequestFlags;
} AAD_CREDUI_CREDS, *PAAD_CREDUI_CREDS;

typedef struct _AAD_LOGON_CRED {
    UNICODE_STRING UserName;
    AadCredentialType CredType;
    UNICODE_STRING CredValue;
    ULONG RequestFlags;
} AAD_LOGON_CRED, *PAAD_LOGON_CRED;

typedef struct _AP_BLOB {
    ULONG cb;
    PBYTE pb;
} AP_BLOB, *PAP_BLOB;

typedef struct _AadApPluginKeyInfo {
    DWORD dwVersion;
    LPWSTR pwszKeyType;
    LPWSTR pwszAlgorithm;
    AP_BLOB keyValue;
} AadApPluginKeyInfo, *PAadApPluginKeyInfo;

typedef struct _AadApPluginTokenUpdateInfo {
    DWORD dwVersion;
    AP_BLOB primaryRefreshToken;
    TimeStamp primaryRefreshTokenExpiryTime;
    AadApPluginKeyInfo proofOfPossesionKey;
    LPWSTR authorityUri;
} AadApPluginTokenUpdateInfo, *PAadApPluginTokenUpdateInfo;

typedef struct _AadApPluginEnterpriseSTSInfo {
    DWORD dwVersion;
    LPWSTR authorityUri;
    LPWSTR tokenEndpointUri;
    LPWSTR authorizationEndpointUri;
    LPWSTR issuer;
    LPWSTR subject;
    BOOL prtSupported;
    TimeStamp lastTriedTime;
    AadApPluginTokenUpdateInfo refreshTokenInfo;
} AadApPluginEnterpriseSTSInfo, *PAadApPluginEnterpriseSTSInfo;

typedef struct _AadNetworkConfig {
    ULONG resolveTimeout;
    ULONG connectTimeout;
    ULONG sendTimeout;
    ULONG receiveTimeout;
    UNICODE_STRING federationProviderName;
    ULONG prtRefreshTimeout;
    GUID providerGuid;
} AadNetworkConfig, *PAadNetworkConfig;

typedef struct _AadApPluginHandle {
    UNICODE_STRING authorityUri;
    UNICODE_STRING instanceName;
    UNICODE_STRING tenantId;
    UNICODE_STRING deviceId;
    UNICODE_STRING deviceCertificateThumbprint;
    AadNetworkConfig networkConfig;
    ULONG pluginCaps;
    PSID singleUserSid;
    BOOL adrsJoined;
    HANDLE certificateUpdateThread;
    HANDLE certificateUpdateEvent;
    ULONG certificateUpdateThreadId;
    ULONG certificateUpdateThreadStop;
    RTL_CRITICAL_SECTION pluginSync;
    BOOL syncInitialized;
    BOOL wsaInitialized;
    UNICODE_STRING ssoCookie;
    UNICODE_STRING ssoUserId;
} AadApPluginHandle, *PAadApPluginHandle;

typedef struct _APPLUGIN_SSO_USER_INFO {
    LPWSTR pwszUserDownlevelName;
    LPWSTR pwszUserDomainNetBiosName;
    LPWSTR pwszUserDomainDNSName;
} APPLUGIN_SSO_USER_INFO, *PAPPLUGIN_SSO_USER_INFO;

typedef struct _APPLUGIN_PWD_EXPIRY_INFO {
    LPWSTR pwszPwdChangeURL;
    FILETIME ftExpiryTime;
} APPLUGIN_PWD_EXPIRY_INFO, *PAPPLUGIN_PWD_EXPIRY_INFO;

typedef struct _APPLUGIN_USER_INFO {
    DWORD dwVersion;
    LPWSTR pwszUniqueId;
    PSID pPrimarySID;
    ULONG cGroupSIDs;
    PSID* ppGroupSIDs;
    LPWSTR pwszDisplayName;
    LPWSTR pwszFirstName;
    LPWSTR pwszLastName;
    APPLUGIN_SSO_USER_INFO ssoUserInfo;
    APPLUGIN_PWD_EXPIRY_INFO pwdExpiryInfo;
} APPLUGIN_USER_INFO, *PAPPLUGIN_USER_INFO;

typedef struct _AadApPluginTokenInfo {
    DWORD dwVersion;
    APPLUGIN_USER_INFO userInfo;
    AP_BLOB primaryRefreshToken;
    TimeStamp primaryRefreshTokenReceivedTime;
    TimeStamp primaryRefreshTokenExpiryTime;
    AadApPluginKeyInfo proofOfPossesionKey;
    LPWSTR tenantId;
    LPWSTR userName;
    LPWSTR subject;
    LPWSTR authorityUri;
    LPWSTR deviceId;
    LPWSTR deviceCertificateThumbprint;
    AadApPluginEnterpriseSTSInfo enterpriseSTSInfo;
    DSR_INSTANCE dsrInstance;
    BOOL adfsPasswordChangeInfo;
} AadApPluginTokenInfo, *PAadApPluginTokenInfo;

typedef struct _AadApPluginUserRealmInfo {
    ULONG accountType;
    ULONG federationProtocol;
    UNICODE_STRING federationMetadataUrl;
    UNICODE_STRING federationAuthUrl;
    UNICODE_STRING userNamePasswordUrl;
    UNICODE_STRING certificateUrl;
    UNICODE_STRING domainName;
    ULONG userNamePasswordUrlProtocolVersion;
    ULONG certificateUrlProtocolVersion;
} AadApPluginUserRealmInfo, *PAadApPluginUserRealmInfo;

typedef struct _APPLUGIN_SECPKG_FUNCTION_TABLE_NETWORK_CALLS_OK {
    LPVOID GetToken;
    LPVOID RefreshToken;
    LPVOID GetKeys;
    LPVOID LookupSIDFromIdentityName;
    LPVOID LookupIdentityNameFromSID;
    LPVOID UserProfileLoaded;
    LPVOID ConnectIdentity;
    LPVOID DisconnectIdentity;
    LPVOID RenewCertificate;
    LPVOID GetCertificateFromCred;
    LPVOID GenericCallPkg;
    LPVOID PostLogonProcessing; // Was added later
} APPLUGIN_SECPKG_FUNCTION_TABLE_NETWORK_CALLS_OK, *PAPPLUGIN_SECPKG_FUNCTION_TABLE_NETWORK_CALLS_OK;

typedef struct _APPLUGIN_SECPKG_FUNCTION_TABLE_NO_NETWORK_CALLS {
    LPVOID Uninitialize;
    LPVOID ValidateUserInfo;
    LPVOID GetUnlockKey;
    LPVOID PersistSSOTokens;
    LPVOID GetDefCredentialComplexity;
    LPVOID IsConnected;
    LPVOID AcceptPeerCertificate;
    LPVOID AssembleOpaqueData;
    LPVOID DisassembleOpaqueData;
} APPLUGIN_SECPKG_FUNCTION_TABLE_NO_NETWORK_CALLS, *PAPPLUGIN_SECPKG_FUNCTION_TABLE_NO_NETWORK_CALLS;

typedef struct _APPLUGIN_SECPKG_FUNCTION_TABLE {
    DWORD dwVersion;
    APPLUGIN_SECPKG_FUNCTION_TABLE_NO_NETWORK_CALLS pFnTableNoNetworkCalls;
    APPLUGIN_SECPKG_FUNCTION_TABLE_NETWORK_CALLS_OK pFnTableNetworkCallsOk;
} APPLUGIN_SECPKG_FUNCTION_TABLE, *PAPPLUGIN_SECPKG_FUNCTION_TABLE;

typedef struct _tagSCLock {
    RTL_RESOURCE Resource;
    volatile LONG lNoExclusiveAcquires;
} SCLock, *PSCLock;

struct _ApPluginPkg {
    HINSTANCE hMod;
    PVOID hPlugin;
    PVOID LsaIdProvHandle;
    WCHAR awchProviderName[21];
    GUID ProviderGuid;
    UCHAR abProviderSid[68];
    PVOID pTokenBrokerPkgSid;
    ULONG ulCaps;
    APPLUGIN_SECPKG_FUNCTION_TABLE FnTable;
    PWCHAR pwszCacheDir;
    HKEY hKeyCacheRoot;
    PSCLock pSubPkgLock;
    LONG bSubPkgLockInitialized;
    RTL_AVL_TREE SubProvAvlTree;
    RTL_AVL_TREE SubProvDnsAvlTree;
};

struct _ApPluginSubPkg {
    RTL_BALANCED_NODE AvlLink;
    RTL_BALANCED_NODE AvlDnsLink;
    WCHAR awchProviderName[16];
    WCHAR awchProviderDnsName[256];
    HKEY hKeyCacheRoot;
};

typedef struct _CLOUD_COMMAND {
    ULONG Version;
    ULONG CommandCode;
    union {
        struct {
            LARGE_INTEGER RecallOffset;
            LARGE_INTEGER RecallLength;
        } InitiateRecall;
        struct {
            LARGE_INTEGER DeflateOffset;
            LARGE_INTEGER DeflateLength;
        } Deflate;
        struct {
            LARGE_INTEGER NewServerFileSize;
            ULONG FileIdentityOffset;
            ULONG FileIdentityLength;
        } UpdatePlaceholderIdentity;
        struct {
            union {
                LPVOID ServiceIdentity;
                LONGLONG Alignment;
            } u;
            ULONG Length;
            ULONG Flags;
        } CreateServiceIdentity;
        struct {
            union {
                LPVOID ServiceIdentity;
                LONGLONG Alignment;
            } u;
            ULONG Length;
            ULONG Flags;
        } ConnectServiceIdentity;
        struct {
            union {
                LPVOID ServiceIdentity;
                LONGLONG Alignment;
            } u;
            ULONG Length;
            ULONG Flags;
        } DeleteServiceIdentity;
        struct {
            ULONG FirstBlobContextOffset;
            ULONG BlobCount;
            LARGE_INTEGER Timeout;
            ULONG Flags;
        } PropertyOperation;
    };
} CLOUD_COMMAND, *PCLOUD_COMMAND;

typedef struct _CLOUD_DATA_TRANSFER {
    FILE_ID_128 TargetFileId;
    LARGE_INTEGER RequiredOffset;
    LARGE_INTEGER ByteOffset;
    ULONG RequiredLength;
    ULONG Length;
    ULONG Flags;
    NTSTATUS ServiceStatus; // NTSTATUS is assumed based on the member name
} CLOUD_DATA_TRANSFER, *PCLOUD_DATA_TRANSFER;

typedef struct _CLOUD_PROPERTY_BLOB_CONTEXT {
    ULONG BlobType;
    ULONG BufferLength;
    union {
        LPVOID Buffer;
        LONGLONG Alignment;
    };
    ULONG BlobLength;
    NTSTATUS Status; // NTSTATUS is assumed based on the member name
} CLOUD_PROPERTY_BLOB_CONTEXT, *PCLOUD_PROPERTY_BLOB_CONTEXT;

typedef struct _CLOUD_PROVIDER_GET_EXTERNAL_INFO {
    ULONG Version;
    ULONG Flags;
    LARGE_INTEGER BytesLocallyPresent;
    LARGE_INTEGER BytesMetadata;
    ULONG ServiceIdentityOffset;
    ULONG ServiceIdentityLength;
    ULONG FileIdentityOffset;
    ULONG FileIdentityLength;
} CLOUD_PROVIDER_GET_EXTERNAL_INFO, *PCLOUD_PROVIDER_GET_EXTERNAL_INFO;

typedef struct _CLOUD_PROVIDER_MESSAGE {
    ULONG Version;
    ULONG MessageCode;
    struct {
        FILE_ID_128 FileId;
        LARGE_INTEGER ContainingOffset;
        LARGE_INTEGER ContainingLength;
        LARGE_INTEGER RequiredOffset;
        ULONG RequiredLength;
        ULONG Flags;
        ULONG Alignment;
        ULONG FileIdentityOffset;
        ULONG FileIdentityLength;
        ULONG ServiceIdentityOffset;
        ULONG ServiceIdentityLength;
    } FetchData;
} CLOUD_PROVIDER_MESSAGE, *PCLOUD_PROVIDER_MESSAGE;

typedef struct _CLOUD_PROVIDER_SET_EXTERNAL_INFO {
    ULONG Version;
    ULONG Flags;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER ModifiedTime;
    LARGE_INTEGER AccessedTime;
    ULONG FileAttributes;
    ULONG Reserved;
    ULONG FileIdentityOffset;
    ULONG FileIdentityLength;
} CLOUD_PROVIDER_SET_EXTERNAL_INFO, *PCLOUD_PROVIDER_SET_EXTERNAL_INFO;

typedef struct _CLOUDAP_SECPKG_FUNCTION_TABLE {
    LPVOID ImpersonateClient;
    LPVOID LsaProtectMemory;
    LPVOID LsaUnprotectMemory;
    LPVOID OpenTokenByLogonId;
    LPVOID AllocateLsaHeap;
    LPVOID FreeLsaHeap;
    LPVOID AllocateUserInfo;
    LPVOID FreeUserInfo;
    LPVOID CrediRead;
    LPVOID CrediFreeCredentials;
    LPVOID CrediWrite;
    LPVOID SignMessageWithNgc;
} CLOUDAP_SECPKG_FUNCTION_TABLE, *PCLOUDAP_SECPKG_FUNCTION_TABLE;

typedef struct _DPAPI_DECODED_AUTH_DATA {
    ULONG dwCredType;
    ULONG cbCredBuff;
    PUCHAR pbCredBuff;
} DPAPI_DECODED_AUTH_DATA, *PDPAPI_DECODED_AUTH_DATA;

typedef struct _tagCloudAPGenericCallPkgInput {
    ULONG ulMessageType;
    GUID ProviderGuid;
    ULONG ulInputSize;
    BYTE abInput[ANYSIZE_ARRAY];
} CloudAPGenericCallPkgInput, *PCloudAPGenericCallPkgInput;

typedef struct _tagCloudAPGetAuthenticatingProviderInput {
    ULONG ulMessageType;
    LUID LogonId;
} CloudAPGetAuthenticatingProviderInput, *PCloudAPGetAuthenticatingProviderInput;

typedef struct _tagCloudAPGetTokenInput {
    ULONG ulMessageType;
    LUID LogonId;
} CloudAPGetTokenInput, *PCloudAPGetTokenInput;

typedef struct _tagCloudAPProfileDeletedInput {
    ULONG ulMessageType;
    ULONG ulUserSidOffset; // Offset to PSID pointer within structure
    ULONG ulUserSidSize;
    ULONG ulInputSize;
    BYTE abInput[ANYSIZE_ARRAY]; // SID
} CloudAPProfileDeletedInput, *PCloudAPProfileDeletedInput;

typedef struct _tagCloudAPPwdExpiryInfoOutput {
    FILETIME ftExpiryTime;
    WCHAR awchPwdResetUrl[ANYSIZE_ARRAY];
} CloudAPPwdExpiryInfoOutput, *PCloudAPPwdExpiryInfoOutput;

typedef struct _tagCloudAPRefreshTokenInput {
    ULONG ulMessageType;
    LUID LogonId;
    ULONG ulTokenSize;
    BYTE abToken[ANYSIZE_ARRAY];
} CloudAPRefreshTokenInput, *PCloudAPRefreshTokenInput;

typedef struct _tagCloudAPReinitPluginsInput {
    ULONG ulMessageType;
} CloudAPReinitPluginsInput, *PCloudAPReinitPluginsInput;

typedef struct _tagCloudAPRenameAccountInput {
    ULONG ulMessageType;
    GUID ProviderGuid;
    ULONG ulSerializedPropertiesSize;
    BYTE abSerializedProperties[ANYSIZE_ARRAY];
} CloudAPRenameAccountInput, *PCloudAPRenameAccountInput;

/// <summary>
/// Although originally intended for just setting the id cache
/// flush parameter, this is now used to generically set test
/// parameters via the SetTestParas call and bFlushSync is used
/// in-practice as a generic DWORD. The macro names for these
/// parameters have been determined through manual audits.
/// </summary>
typedef struct _tagCloudAPSetIdCacheFlushParasInput {
    ULONG ulMessageType;
#define ENABLE_ID_CACHE_FLUSHES 1
#define ENABLE_PRE_RS2_SUPPORT  2
    BOOL bFlushSync;
} CloudAPSetIdCacheFlushParasInput, *PCloudAPSetIdCacheFlushParasInput;

typedef struct AadCredBagIndex {
    const ULONG ArrayLength;
} AadCredBagIndex, *PAadCredBagIndex;

struct AADTB_REQUEST {
    ULONG cbSize;
    LPCWSTR RT;
    LPCWSTR UPN;
    LPCWSTR TenantId;
    LPCWSTR Resource;
    LPCWSTR Authority;
    LPCWSTR ClientId;
};

#ifdef __cplusplus
} // Closes extern "C" above
namespace Cloudap {
    // Enumerations
    using AadCredentialAttribute = _AadCredentialAttribute;
    using AadCredentialsType = _AadCredentialsType;
    using AadCredentialType = AadCredentialType;
    using AadTracingEventType = AadTracingEventType;
    using DSR_INSTANCE = _DSR_INSTANCE;

    using AAD_CREDUI_CREDS = ::_AAD_CREDUI_CREDS;
    using AAD_LOGON_CRED = ::_AAD_LOGON_CRED;
    using AadApPluginEnterpriseSTSInfo = ::_AadApPluginEnterpriseSTSInfo;
    using AadApPluginHandle = ::_AadApPluginHandle;
    using AadApPluginKeyInfo = ::_AadApPluginKeyInfo;
    using AadApPluginTokenInfo = ::_AadApPluginTokenInfo;
    using AadApPluginTokenUpdateInfo = ::_AadApPluginTokenUpdateInfo;
    using AadApPluginUserRealmInfo = ::_AadApPluginUserRealmInfo;
    using AadCredBagIndex = ::AadCredBagIndex;
    using AadCredential = ::_AadCredential;
    using AadCredentialBag = ::_AadCredentialBag;
    using AadCredentialString = ::_AadCredentialString;
    using AadNetworkConfig = ::_AadNetworkConfig;
    using AADTB_REQUEST = ::AADTB_REQUEST;
    using AP_BLOB = ::_AP_BLOB;
    using APPLUGIN_PWD_EXPIRY_INFO = ::_APPLUGIN_PWD_EXPIRY_INFO;
    using APPLUGIN_SECPKG_FUNCTION_TABLE = ::_APPLUGIN_SECPKG_FUNCTION_TABLE;
    using APPLUGIN_SECPKG_FUNCTION_TABLE_NETWORK_CALLS_OK = ::_APPLUGIN_SECPKG_FUNCTION_TABLE_NETWORK_CALLS_OK;
    using APPLUGIN_SECPKG_FUNCTION_TABLE_NO_NETWORK_CALLS = ::_APPLUGIN_SECPKG_FUNCTION_TABLE_NO_NETWORK_CALLS;
    using APPLUGIN_SSO_USER_INFO = ::_APPLUGIN_SSO_USER_INFO;
    using APPLUGIN_USER_INFO = ::_APPLUGIN_USER_INFO;
    using ApPluginPkg = ::_ApPluginPkg;
    using ApPluginSubPkg = ::_ApPluginSubPkg;
    using CLOUD_COMMAND = ::_CLOUD_COMMAND;
    using CLOUD_DATA_TRANSFER = ::_CLOUD_DATA_TRANSFER;
    using CLOUD_PROPERTY_BLOB_CONTEXT = ::_CLOUD_PROPERTY_BLOB_CONTEXT;
    using CLOUD_PROVIDER_GET_EXTERNAL_INFO = ::_CLOUD_PROVIDER_GET_EXTERNAL_INFO;
    using CLOUD_PROVIDER_MESSAGE = ::_CLOUD_PROVIDER_MESSAGE;
    using CLOUD_PROVIDER_SET_EXTERNAL_INFO = ::_CLOUD_PROVIDER_SET_EXTERNAL_INFO;
    using CLOUDAP_SECPKG_FUNCTION_TABLE = ::_CLOUDAP_SECPKG_FUNCTION_TABLE;
    using CloudAPCache = ::_CloudAPCache;
    using CloudAPCacheNode = ::_CloudAPCacheNode;
    using CloudAPCacheNodeData = ::_CloudAPCacheNodeData;
    using CloudAPCacheNodeData2 = ::_CloudAPCacheNodeData2;
    using CloudAPGenericCallPkgInput = ::_tagCloudAPGenericCallPkgInput;
    using CloudAPGetAuthenticatingProviderInput = ::_tagCloudAPGetAuthenticatingProviderInput;
    using CloudAPGetTokenInput = ::_tagCloudAPGetTokenInput;
    using CloudAPProfileDeletedInput = ::_tagCloudAPProfileDeletedInput;
    using CloudAPPwdExpiryInfoOutput = ::_tagCloudAPPwdExpiryInfoOutput;
    using CloudAPRefreshTokenInput = ::_tagCloudAPRefreshTokenInput;
    using CloudAPReinitPluginsInput = ::_tagCloudAPReinitPluginsInput;
    using CloudAPRenameAccountInput = ::_tagCloudAPRenameAccountInput;
    using CloudAPSetIdCacheFlushParasInput = ::_tagCloudAPSetIdCacheFlushParasInput;
    using CloudKeyNode = ::_CloudKeyNode;
    using DPAPI_DECODED_AUTH_DATA = ::_DPAPI_DECODED_AUTH_DATA;
    using DPAPICloudKeyCache = ::_DPAPICloudKeyCache;
    using DPAPICloudKeyVersionMapping = ::_DPAPICloudKeyVersionMapping;
    using DPAPICloudKeyVersionPair = ::_DPAPICloudKeyVersionPair;
    using SCLock = _tagSCLock;
}
#endif