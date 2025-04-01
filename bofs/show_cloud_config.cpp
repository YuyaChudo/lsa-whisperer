// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"
#include "sspi.hpp"

enum _AADPLUGIN_AUTHORITY_TYPE;

struct _AADPLUGIN_PRT_INFO;
struct _DSREG_JOIN_INFO_1;
struct _REGISTRATION_DATA;

typedef void DSREG_JOIN_INFO_ALL, *PDSREG_JOIN_INFO_ALL;

typedef enum _AADPLUGIN_AUTHORITY_TYPE {
    AADPLUGIN_AUTHORITY_CLOUD = 1,
    AADPLUGIN_AUTHORITY_ENTERPRISE = 2
} AADPLUGIN_AUTHORITY_TYPE;

typedef struct _AADPLUGIN_PRT_INFO {
    LPWSTR unknown1;
    LPWSTR unknown2;
    LPWSTR unknown3;
    LPWSTR unknown4;
    LPWSTR unknown5;
} AADPLUGIN_PRT_INFO, *PAADPLUGIN_PRT_INFO;

typedef struct _DSREG_JOIN_INFO_1 {
    ULONG level;
    DSREG_JOIN_TYPE joinType;
    PCCERT_CONTEXT pJoinCertificate;
    PWCHAR pszDeviceId;
    PWCHAR pszIdpDomain;
    PWCHAR pszTenantId;
    PWCHAR pszJoinUserEmail;
    PWCHAR pszTenantDisplayName;
    PWCHAR pszMdmEnrollmentUrl;
    PWCHAR pszMdmTermsOfUseUrl;
    PWCHAR pszMdmComplianceUrl;
    PWCHAR pszUserSettingSyncUrl;
    PWCHAR pszRegistrationServiceVersion;
    PWCHAR pszRegistrationEndpointReference;
    PWCHAR pszRegistrationResourceId;
    PWCHAR pszAuthCodeUrl;
    PWCHAR pszAccessTokenUrl;
    PWCHAR pszDeviceJoinServiceVersion;
    PWCHAR pszDeviceJoinEndpointReference;
    PWCHAR pszDeviceJoinResourceId;
    PWCHAR pszKeyProvisioningServiceVersion;
    PWCHAR pszKeyProvisioningEndpointReference;
    PWCHAR pszKeyProvisioningResourceId;
    PDSREG_USER_INFO pUserInfo;
    DSR_INSTANCE dwDsrInstance;
} DSREG_JOIN_INFO_1, *PDSREG_JOIN_INFO_1;

typedef struct _REGISTRATION_DATA {
    PUCHAR pbPublicKey;
    ULONG dwPublicKeyLen;
    PWCHAR pszComputerObjectGuid;
    PWCHAR pszComputerObjectSid;
    PWCHAR pszAadTenantName;
    PWCHAR pszAadTenantId;
    PWCHAR pszTargetDomainController;
    PWCHAR pszEnterpriseDrsName;
    DSR_INSTANCE dwDsrInstance;
} REGISTRATION_DATA, *PREGISTRATION_DATA;

[[maybe_unused]] decltype(NetFreeAadJoinInformation) DsrFreeJoinInfo;
[[maybe_unused]] void NET_API_FUNCTION DsrFreeJoinInfoEx(PDSREG_JOIN_INFO_ALL pJoinInfo);
[[maybe_unused]] HRESULT NET_API_FUNCTION DsrGetDomainRegistrationData(LPCWSTR pcszServerName, PREGISTRATION_DATA ppRegistrationData);
[[maybe_unused]] decltype(NetGetAadJoinInformation) DsrGetJoinInfo;
[[maybe_unused]] HRESULT NET_API_FUNCTION DsrGetJoinInfoEx(DWORD level, LPCWSTR pInputArg, PDSREG_JOIN_INFO_ALL ppJoinInfo);
[[maybe_unused]] HRESULT NET_API_FUNCTION DsrGetPrtAuthorityInfo(AADPLUGIN_AUTHORITY_TYPE authorityType, PAADPLUGIN_PRT_INFO ppPrtAuthorityInfo);

GUID AadGlobalIdProviderGuid = { 0xB16898C6, 0xA148, 0x4967, 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20 };

void ShowCloudApInfo() {
    // GetUnlockKeyType
    auto request1 = reinterpret_cast<Cloudap::PGET_UNLOCK_KEY_TYPE_REQUEST>(Libc::malloc(sizeof(Cloudap::GET_UNLOCK_KEY_TYPE_REQUEST)));
    Libc::memset(&request1, '\0', sizeof(*request1));
    request1->MessageType = Cloudap::PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType;
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(*request1);
    submitBuffer.data = reinterpret_cast<char*>(request1);
    PIC_STRING(cloudap, ClOUDAP_NAME_A);
    Libc::CHAR_SPAN returnBuffer;
    PIC_WSTRING(sspicli, L"SSPICLI.DLL");
    LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
    if (LsaApi::CallPackage(cloudap, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<Cloudap::GET_UNLOCK_KEY_TYPE_RESPONSE*>(returnBuffer.data);
        PIC_STRING(message1, "CloudAP logon session config\n");
        BeaconPrintf(CallbackType::OUTPUT, message1);
        PIC_STRING(message2, "    Unlock key type : %d\n");
        BeaconPrintf(CallbackType::OUTPUT, message2, response->Type);
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    }
    // GetAuthenticatingProvider
    auto request2 = reinterpret_cast<PCloudAPGetTokenInput>(Libc::malloc(sizeof(CloudAPGetTokenInput)));
    Libc::memset(&request2, '\0', sizeof(*request2));
    request2->ulMessageType = static_cast<ULONG>(Cloudap::PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider);
    submitBuffer.count = sizeof(*request2);
    submitBuffer.data = reinterpret_cast<char*>(request2);
    Libc::memset(&returnBuffer, '\0', sizeof(returnBuffer));
    if (LsaApi::CallPackage(cloudap, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<Cloudap::GET_AUTHENTICATION_PROVIDER_RESPONSE*>(returnBuffer.data);
        PIC_WSTRING(rpcrt4, L"RPCRT4.DLL");
        LAZY_LOAD_PROC(rpcrt4, UuidToStringA);
        RPC_CSTR providerString;
        if (LazyUuidToStringA(&response->provider, &providerString) == RPC_S_OK) {
            PIC_STRING(message, "    CloudAP plugin  : %s\n");
            BeaconPrintf(CallbackType::OUTPUT, message, providerString);
            LAZY_LOAD_PROC(rpcrt4, RpcStringFreeA);
            LazyRpcStringFreeA(&providerString);
        }
        // GetPrtAuthority
        if (!Libc::memcmp(&response->provider, &AadGlobalIdProviderGuid, sizeof(GUID))) {
            for (size_t authority = 1; authority <= 2; authority++) {
                PIC_STRING(json, "{\"call\":3,\"authoritytype\":%d}");
                PIC_WSTRING(ntdll, L"NTDLL.DLL");
                LAZY_LOAD_PROC(ntdll, sprintf);
                submitBuffer.count = Lazysprintf(nullptr, 0, json, authority) + 1;
                submitBuffer.data = reinterpret_cast<char*>(Libc::malloc(submitBuffer.count));
                (void)Lazysprintf(submitBuffer.data, json, authority);
                Libc::memset(&returnBuffer, '\0', sizeof(returnBuffer));
                if (LsaApi::CallCloudapPlugin(&AadGlobalIdProviderGuid, &submitBuffer, &returnBuffer)) {
                    PIC_STRING(message, "    Authority %d info: %s\n");
                    BeaconPrintf(CallbackType::OUTPUT, message, authority, reinterpret_cast<char*>(returnBuffer.data));
                    LazyLsaFreeReturnBuffer(returnBuffer.data);
                }
                Libc::free(submitBuffer.data);
            }
        }
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    }
    // GetDpApiCredKeyDecryptStatus
    auto request3 = reinterpret_cast<Cloudap::PGET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST>(Libc::malloc(sizeof(Cloudap::GET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST)));
    Libc::memset(&request3, '\0', sizeof(*request3));
    request3->MessageType = Cloudap::PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus;
    submitBuffer.count = sizeof(*request3);
    submitBuffer.data = reinterpret_cast<char*>(request3);
    Libc::memset(&returnBuffer, '\0', sizeof(returnBuffer));
    if (LsaApi::CallPackage(cloudap, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<Cloudap::GET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE*>(returnBuffer.data);
        if (response->IsDecrypted) {
            PIC_STRING(message, "    DpApiCredKey    : Decrypted\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        } else {
            PIC_STRING(message, "    DpApiCredKey    : Not decrypted\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    }
    // IsCloudToOnPremTgtPresentInCache
    auto request5 = reinterpret_cast<Cloudap::PIS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST>(Libc::malloc(sizeof(Cloudap::IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST)));
    Libc::memset(&request5, '\0', sizeof(*request5));
    request5->MessageType = Cloudap::PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache;
    submitBuffer.count = sizeof(*request5);
    submitBuffer.data = reinterpret_cast<char*>(request5);
    Libc::memset(&returnBuffer, '\0', sizeof(returnBuffer));
    if (LsaApi::CallPackage(cloudap, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<Cloudap::IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE*>(returnBuffer.data);
        if (response->IsPresent) {
            PIC_STRING(message, "    CloudToOnPremTgt: Present\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        } else {
            PIC_STRING(message, "    CloudToOnPremTgt: Not present\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    }
}

void ShowCloudKerberosInfo() {
    auto request = reinterpret_cast<PKERB_CLOUD_KERBEROS_DEBUG_REQUEST>(Libc::malloc(sizeof(KERB_CLOUD_KERBEROS_DEBUG_REQUEST)));
    Libc::memset(&request, '\0', sizeof(*request));
    request->MessageType = KERB_PROTOCOL_MESSAGE_TYPE::KerbPrintCloudKerberosDebugMessage;
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(*request);
    submitBuffer.data = reinterpret_cast<char*>(request);
    PIC_STRING(kerberos, MICROSOFT_KERBEROS_NAME_A);
    Libc::CHAR_SPAN returnBuffer;
    if (LsaApi::CallPackage(kerberos, &submitBuffer, &returnBuffer)) {
        PIC_STRING(message01, "Cloud kerberos logon session config\n");
        BeaconPrintf(CallbackType::OUTPUT, message01);
        auto response = reinterpret_cast<PKERB_CLOUD_KERBEROS_DEBUG_RESPONSE>(returnBuffer.data);
        auto debugDataV0 = reinterpret_cast<PKERB_CLOUD_KERBEROS_DEBUG_DATA_V0>(&response->Data);
        PIC_STRING(message02, "    EnabledByPolicy          : %d\n");
        BeaconPrintf(CallbackType::OUTPUT, message02, debugDataV0->EnabledByPolicy);
        PIC_STRING(message03, "    AsRepCallbackPresent     : %d\n");
        BeaconPrintf(CallbackType::OUTPUT, message03, debugDataV0->AsRepCallbackPresent);
        PIC_STRING(message04, "    AsRepCallbackUsed        : %d\n");
        BeaconPrintf(CallbackType::OUTPUT, message04, debugDataV0->AsRepCallbackUsed);
        PIC_STRING(message05, "    CloudReferralTgtAvailable: %d\n");
        BeaconPrintf(CallbackType::OUTPUT, message05, debugDataV0->CloudReferralTgtAvailable);
        PIC_STRING(message06, "    SpnOracleConfigured      : %d\n");
        BeaconPrintf(CallbackType::OUTPUT, message06, debugDataV0->SpnOracleConfigured);
        PIC_STRING(message07, "    KdcProxyPresent          : %d\n");
        BeaconPrintf(CallbackType::OUTPUT, message07, debugDataV0->KdcProxyPresent);
        if (response->Version >= 1) {
            auto debugDataV1 = reinterpret_cast<PKERB_CLOUD_KERBEROS_DEBUG_DATA>(&response->Data);
            PIC_STRING(message08, "    PublicKeyCredsPresent    : %d\n");
            BeaconPrintf(CallbackType::OUTPUT, message08, debugDataV1->PublicKeyCredsPresent);
            PIC_STRING(message09, "    PasswordKeysPresent      : %d\n");
            BeaconPrintf(CallbackType::OUTPUT, message09, debugDataV1->PasswordKeysPresent);
            PIC_STRING(message10, "    PasswordPresent          : %d\n");
            BeaconPrintf(CallbackType::OUTPUT, message10, debugDataV1->PasswordPresent);
            PIC_STRING(message11, "    AsRepSourceCred          : %d\n");
            BeaconPrintf(CallbackType::OUTPUT, message11, debugDataV1->AsRepSourceCred);
        }
        PIC_WSTRING(sspicli, L"SSPICLI.DLL");
        LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    }
}

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    PIC_WSTRING(dsreg, L"DSREG.DLL");
    LAZY_LOAD_PROC(dsreg, DsrGetJoinInfoEx);
    PDSREG_JOIN_INFO_1 joinInfo;
    auto aa = LazyDsrGetJoinInfoEx(1, nullptr, &joinInfo);
    if (aa == S_OK) {
        switch (joinInfo->joinType) {
        case DSREG_UNKNOWN_JOIN:
            BeaconPrintf(CallbackType::OUTPUT, "Join type        : Unknown");
            break;
        case DSREG_DEVICE_JOIN:
            BeaconPrintf(CallbackType::OUTPUT, "Join type        : Device");
            break;
        case DSREG_WORKPLACE_JOIN:
            BeaconPrintf(CallbackType::OUTPUT, "Join type        : Workplace");
            break;
        }
        if (joinInfo->pszDeviceId) {
            BeaconPrintf(CallbackType::OUTPUT, "Device id        : %S", joinInfo->pszDeviceId);
        }
        if (joinInfo->pszIdpDomain) {
            BeaconPrintf(CallbackType::OUTPUT, "Idp domain       : %S", joinInfo->pszIdpDomain);
        }
        if (joinInfo->pszTenantId) {
            BeaconPrintf(CallbackType::OUTPUT, "Tenant id        : %S", joinInfo->pszTenantId);
        }
        if (joinInfo->pszJoinUserEmail) {
            BeaconPrintf(CallbackType::OUTPUT, "Join email       : %S", joinInfo->pszJoinUserEmail);
        }
        if (joinInfo->pszTenantDisplayName) {
            BeaconPrintf(CallbackType::OUTPUT, "Tenant name      : %S", joinInfo->pszTenantDisplayName);
        }
        if (joinInfo->pszMdmEnrollmentUrl && joinInfo->pszMdmTermsOfUseUrl && joinInfo->pszMdmComplianceUrl) {
            BeaconPrintf(CallbackType::OUTPUT, "Mdm");
            BeaconPrintf(CallbackType::OUTPUT, "    Enrollment url  : %S", joinInfo->pszMdmEnrollmentUrl);
            BeaconPrintf(CallbackType::OUTPUT, "    Terms of use url: %S", joinInfo->pszMdmTermsOfUseUrl);
            BeaconPrintf(CallbackType::OUTPUT, "    Compliance url  : %S", joinInfo->pszMdmComplianceUrl);
        }
        if (joinInfo->pszUserSettingSyncUrl) {
            BeaconPrintf(CallbackType::OUTPUT, "User settings url: %S", joinInfo->pszUserSettingSyncUrl);
        }
        if (joinInfo->pszAuthCodeUrl) {
            BeaconPrintf(CallbackType::OUTPUT, "Auth code url    : %S", joinInfo->pszAuthCodeUrl);
        }
        if (joinInfo->pszAccessTokenUrl) {
            BeaconPrintf(CallbackType::OUTPUT, "Access token url : %S", joinInfo->pszAccessTokenUrl);
        }
        if (joinInfo->pszRegistrationServiceVersion && joinInfo->pszRegistrationEndpointReference && joinInfo->pszRegistrationResourceId) {
            BeaconPrintf(CallbackType::OUTPUT, "Registration service");
            BeaconPrintf(CallbackType::OUTPUT, "    Version           : %S", joinInfo->pszRegistrationServiceVersion);
            BeaconPrintf(CallbackType::OUTPUT, "    Endpoint reference: %S", joinInfo->pszRegistrationEndpointReference);
            BeaconPrintf(CallbackType::OUTPUT, "    Resource id       : %S", joinInfo->pszRegistrationResourceId);
        }
        if (joinInfo->pszDeviceJoinServiceVersion && joinInfo->pszDeviceJoinEndpointReference && joinInfo->pszDeviceJoinResourceId) {
            BeaconPrintf(CallbackType::OUTPUT, "Device join service");
            BeaconPrintf(CallbackType::OUTPUT, "    Version           : %S", joinInfo->pszDeviceJoinServiceVersion);
            BeaconPrintf(CallbackType::OUTPUT, "    Endpoint reference: %S", joinInfo->pszDeviceJoinEndpointReference);
            BeaconPrintf(CallbackType::OUTPUT, "    Resource id       : %S", joinInfo->pszDeviceJoinResourceId);
        }
        if (joinInfo->pszKeyProvisioningServiceVersion && joinInfo->pszKeyProvisioningEndpointReference && joinInfo->pszKeyProvisioningResourceId) {
            BeaconPrintf(CallbackType::OUTPUT, "Key provisioning service");
            BeaconPrintf(CallbackType::OUTPUT, "    Version           : %S", joinInfo->pszKeyProvisioningServiceVersion);
            BeaconPrintf(CallbackType::OUTPUT, "    Endpoint reference: %S", joinInfo->pszKeyProvisioningEndpointReference);
            BeaconPrintf(CallbackType::OUTPUT, "    Resource id       : %S", joinInfo->pszKeyProvisioningResourceId);
        }
        if (joinInfo->pUserInfo) {
            BeaconPrintf(CallbackType::OUTPUT, "User info");
            auto userInfo{ joinInfo->pUserInfo };
            if (userInfo->pszUserEmail) {
                BeaconPrintf(CallbackType::OUTPUT, "    Email   : %S", userInfo->pszUserEmail);
            }
            if (userInfo->pszUserKeyId) {
                BeaconPrintf(CallbackType::OUTPUT, "    Key id  : %S", userInfo->pszUserKeyId);
            }
            if (userInfo->pszUserKeyName) {
                BeaconPrintf(CallbackType::OUTPUT, "    Key name: %S", userInfo->pszUserKeyName);
            }
        }
        switch (joinInfo->dwDsrInstance) {
        case DSR_INSTANCE_ADRS:
            BeaconPrintf(CallbackType::OUTPUT, "Dsr instance     : ADRS");
            break;
        case DSR_INSTANCE_ENTDRS:
            BeaconPrintf(CallbackType::OUTPUT, "Dsr instance     : ENTDRS");
            break;
        }
        LAZY_LOAD_PROC(dsreg, DsrFreeJoinInfoEx);
        LazyDsrFreeJoinInfoEx(joinInfo);
    }
    ShowCloudApInfo();
    ShowCloudKerberosInfo();
}