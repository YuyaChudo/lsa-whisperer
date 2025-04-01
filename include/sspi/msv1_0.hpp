// Copyright (C) 2025 Evan McBroom
#pragma once
#include "crypt.hpp"
#include "sspi/lsa.hpp"
#include <memory>
#include <string>
#include <vector>

namespace Msv1_0 {
    typedef struct _DELETE_TBAL_SECRETS_REQUEST {
        PROTOCOL_MESSAGE_TYPE MessageType{ PROTOCOL_MESSAGE_TYPE::MsV1_0DeleteTbalSecrets };
    } DELETE_TBAL_SECRETS_REQUEST, *PDELETE_TBAL_SECRETS_REQUEST;

    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        // A subset of the supported functions in msv1_0
        bool CacheLogon(void* logonInfo, void* validationInfo, const std::vector<byte>& supplementalCacheData, ULONG flags) const;
        bool CacheLookupEx(const std::wstring username, const std::wstring domain, ULONG type, const std::string credential) const;
        bool ChangePassword() const;
        bool ChangeCachedPassword(const std::wstring& domainName, const std::wstring& accountName, const std::wstring& newPassword) const;
        bool ClearCachedCredentials() const;
        bool DecryptDpapiMasterKey() const;
        bool DeleteTbalSecrets() const;
        bool DeriveCredential(PLUID luid, ULONG type, const std::vector<byte>& mixingBits) const;
        bool EnumerateUsers() const;
        bool GenericPassthrough(const std::wstring& domainName, const std::wstring& packageName, std::vector<byte>& data) const;
        bool GetCredentialKey(PLUID luid) const;
        bool GetStrongCredentialKey(PLUID luid, bool isProtectedUser) const;
        bool GetUserInfo(PLUID luid) const;
        bool Lm20ChallengeRequest() const;
        bool Lm20GetChallengeResponse(ULONG flags, PLUID luid, const std::vector<byte>& challenge) const;
        bool ProvisionTbal(PLUID luid) const;
        bool SetProcessOption(ULONG options, bool disable) const;

    protected:
        std::shared_ptr<Lsa::Api> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;
        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
        template<typename _Request, typename _Response>
        bool CallPackage(_Request* submitBuffer, size_t submitBufferLength, _Response** returnBuffer) const;
    };
}