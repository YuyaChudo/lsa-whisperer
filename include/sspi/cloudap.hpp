// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"
#include <memory>
#include <string>

namespace Cloudap {
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        ReinitPlugin = 0,
        GetTokenBlob,
        CallPluginGeneric,
        ProfileDeleted,
        GetAuthenticatingProvider,
        RenameAccount,
        RefreshTokenBlob,
        GenARSOPwd,
        SetTestParas,
        TransferCreds,
        ProvisionNGCNode,
        GetPwdExpiryInfo,
        DisableOptimizedLogon,
        GetUnlockKeyType,
        GetPublicCachedInfo,
        GetAccountInfo,
        GetDpApiCredKeyDecryptStatus,
        IsCloudToOnPremTgtPresentInCache
    };

    typedef struct _DISABLE_OPTIMIZED_LOGON_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::DisableOptimizedLogon };
        LUID LogonId{ 0 };
    } DISABLE_OPTIMIZED_LOGON_REQUEST, *PDISABLE_OPTIMIZED_LOGON_REQUEST;

    typedef struct _GEN_ARSO_PASSWORD_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GenARSOPwd };
        LUID LogonId{ 0 };
        ULONG BufferLength;
        CHAR Buffer[0];
    } GEN_ARSO_PASSWORD_REQUEST, *PGEN_ARSO_PASSWORD_REQUEST;

    typedef struct _GET_ACCOUNT_INFO_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GenARSOPwd };
        GUID PackageGuid{ 0 };
        PSID Sid;
        // Pad of 0x3C
    } GET_ACCOUNT_INFO_REQUEST, *PGET_ACCOUNT_INFO_REQUEST;

    typedef struct _GET_AUTHENTICATION_PROVIDER_RESPONSE {
        GUID provider;
    } GET_AUTHENTICATION_PROVIDER_RESPONSE, *PGET_AUTHENTICATION_PROVIDER_RESPONSE;

    typedef struct _GET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetDpApiCredKeyDecryptStatus };
        LUID LogonId{ 0 };
    } GET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST, *PGET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST;

    typedef struct _GET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE {
        DWORD IsDecrypted;
    } GET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE, *PGET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE;

    typedef struct _GET_PUBLIC_CACHED_INFO_REQUEST { // wip
        // code + package guid + uint 6 + (uint + uint) + (uint + uint).
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GenARSOPwd };
        GUID PackageGuid{ 0 };
        ULONG StringLength{ 6 }; // Length must be 6
        ULONG StringMaximumLength;
        PWSTR StringBuffer;
    } GET_PUBLIC_CACHED_INFO_REQUEST, *PGET_PUBLIC_CACHED_INFO_REQUEST;

    typedef struct _GET_PWD_EXPIRY_INFO_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetPwdExpiryInfo };
        LUID LogonId{ 0 };
    } GET_PWD_EXPIRY_INFO_REQUEST, *PGET_PWD_EXPIRY_INFO_REQUEST;

    typedef struct _GET_UNLOCK_KEY_TYPE_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::GetUnlockKeyType };
        LUID LogonId{ 0 };
    } GET_UNLOCK_KEY_TYPE_REQUEST, *PGET_UNLOCK_KEY_TYPE_REQUEST;

    typedef struct _GET_UNLOCK_KEY_TYPE_RESPONSE {
        DWORD Type;
    } GET_UNLOCK_KEY_TYPE_RESPONSE, *PGET_UNLOCK_KEY_TYPE_RESPONSE;

    typedef struct _IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::IsCloudToOnPremTgtPresentInCache };
        LUID LogonId{ 0 };
    } IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST, *PIS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST;

    typedef struct _IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE {
        DWORD IsPresent;
    } IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE, *PIS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE;

    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        // Supported functions in cloudAP!PluginFunctionTable
        bool CallPluginGeneric(const GUID* plugin, const std::string& json, void** returnBuffer, size_t* returnBufferLength) const;
        bool DisableOptimizedLogon(PLUID luid) const;
        bool GenARSOPwd(PLUID luid, const std::string& data) const;
        bool GetAccountInfo() const;
        bool GetAuthenticatingProvider(PLUID luid) const;
        bool GetDpApiCredKeyDecryptStatus(PLUID luid) const;
        bool GetPublicCachedInfo() const;
        bool GetPwdExpiryInfo(PLUID luid) const;
        bool GetTokenBlob(PLUID luid) const;
        bool GetUnlockKeyType(PLUID luid) const;
        bool IsCloudToOnPremTgtPresentInCache(PLUID luid) const;
        bool ProfileDeleted() const;
        bool ProvisionNGCNode() const;
        bool RefreshTokenBlob() const;
        bool ReinitPlugin() const;
        bool RenameAccount() const;
        bool SetTestParas(ULONG TestFlags) const;
        bool TransferCreds(PLUID sourceLuid, PLUID destinationLuid) const;

    protected:
        std::shared_ptr<Lsa::Api> lsa;

        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;

        bool CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const;

        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer, size_t* returnBufferLength) const;
    };

    // The AzureAD plugin (AAD), implemented in aadcloudap.dll
    namespace Aad {
        typedef enum _AUTHORITY_TYPE {
            AzureAd = 1,
            Enterprise = 2,
        } AUTHORITY_TYPE;

        enum class CALL : ULONG {
            SignPayload = 1,
            CreateSSOCookie,
            GetPrtAuthority,
            CheckDeviceKeysHealth,
            DeviceAuth,
            RefreshP2PCACert,
            DeviceValidityCheck,
            CreateDeviceSSOCookie,
            CreateNonce,
            ValidateRdpAssertionRequest,
            RefreshP2PCerts,
            CreateBindingKey,
            GenerateBindingClaims,
            CreateEnterpriseSSOCookie = 0xf,
        };

        // {B16898C6-A148-4967-9171-64D755DA8520}
        extern GUID AadGlobalIdProviderGuid;

        class Api : public Cloudap::Api {
        public:
            Api(const std::shared_ptr<Lsa::Api>& lsa);

            bool CheckDeviceKeysHealth() const;
            bool CreateBindingKey() const;
            bool CreateDeviceSSOCookie(const std::string& server, const std::string& nonce) const;
            bool CreateEnterpriseSSOCookie(const std::string& server, const std::string& nonce) const;
            bool CreateNonce() const;
            bool CreateSSOCookie(const std::string& server, const std::string& nonce) const;
            bool DeviceAuth() const;
            bool DeviceValidityCheck() const;
            bool GenerateBindingClaims() const;
            bool GetPrtAuthority(AUTHORITY_TYPE authority) const;
            bool RefreshP2PCACert() const;
            bool RefreshP2PCerts() const;
            bool SignPayload() const;
            bool ValidateRdpAssertionRequest(const std::string& authenticationRequest) const;
        };
    }

    // The MicrosoftAccount plugin (MSA), implemented in MicrosoftAccountCloudAP.dll
    namespace Msa {
        // {D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F}
        extern GUID WLIDProviderGuid;

        enum class CALL : ULONG {
            GetSignedProofOfPossessionTokens,
        };

        class Api : public Cloudap::Api {
        public:
            Api(const std::shared_ptr<Lsa::Api>& lsa);

            bool GetSignedProofOfPossessionTokens(const std::wstring& email) const;
        };
    }
}