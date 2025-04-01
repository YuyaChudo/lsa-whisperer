// Copyright (C) 2025 Evan McBroom
#include "sspi/cloudap.hpp"
#include <iostream>
#include <sstream>
#include <string>

namespace {
    std::string CorrelationId() {
        UUID uuid;
        (void)UuidCreate(&uuid);
        RPC_CSTR uuidString;
        if (UuidToStringA(&uuid, &uuidString) == RPC_S_OK) {
            std::string correlationId{ reinterpret_cast<char*>(uuidString) };
            RpcStringFreeA(&uuidString);
            return correlationId;
        }
        return "";
    }

    void SehTranslator(UINT code, _EXCEPTION_POINTERS* pointers) {
        throw std::exception();
    }
}

namespace Cloudap {
    GUID Aad::AadGlobalIdProviderGuid = { 0xB16898C6, 0xA148, 0x4967, 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20 };
    GUID Msa::WLIDProviderGuid = { 0xD7F9888F, 0xE3FC, 0x49b0, 0x9E, 0xA6, 0xA8, 0x5B, 0x5F, 0x39, 0x2A, 0x4F };

    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::CallPluginGeneric(const GUID* plugin, const std::string& json, void** returnBuffer, size_t* returnBufferLength) const {
        if (json[0] == '{') {
            lsa->out << "InputJson: " << json << std::endl;
        }
        size_t requestLength{ sizeof(CloudAPGenericCallPkgInput) + json.size() + 1 };
        std::string requestBytes(requestLength, '\0');
        auto request{ reinterpret_cast<PCloudAPGenericCallPkgInput>(requestBytes.data()) };
        std::memset(request, 0, requestLength);
        request->ulMessageType = static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::CallPluginGeneric);
        std::memcpy(&request->ProviderGuid, plugin, sizeof(GUID));
        request->ulInputSize = json.size() + 1;
        std::memcpy(request->abInput, json.data(), json.length());
        request->abInput[json.length()] = '\0';
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(request), requestLength);
            *returnBufferLength = 0;
            auto result{ lsa->CallPackage(CLOUDAP_NAME_A, stringSubmitBuffer, returnBuffer, returnBufferLength) };
            if (*returnBufferLength) {
                std::string output{ reinterpret_cast<char*>(*returnBuffer), reinterpret_cast<char*>(*returnBuffer) + *returnBufferLength };
                if (output[0] == '{') {
                    lsa->out << "OutputJson: " << output << std::endl;
                }
            }
            return result;
        }
        return false;
    }

    bool Api::DisableOptimizedLogon(PLUID luid) const {
        DISABLE_OPTIMIZED_LOGON_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::GenARSOPwd(PLUID luid, const std::string& data) const {
        auto requestSize{ sizeof(GEN_ARSO_PASSWORD_REQUEST) + data.length() };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PGEN_ARSO_PASSWORD_REQUEST>(requestBytes.data()) };
        request->MessageType = PROTOCOL_MESSAGE_TYPE::GenARSOPwd;
        request->LogonId.LowPart = luid->LowPart;
        request->LogonId.HighPart = luid->HighPart;
        request->BufferLength = data.length();

        auto ptr{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptr, data.data(), data.length());

        void* response;
        auto result{ CallPackage(requestBytes, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetAccountInfo() const { // xxx
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetAccountInfo);
    }

    bool Api::GetAuthenticatingProvider(PLUID luid) const {
        CloudAPGetTokenInput request = { static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::GetAuthenticatingProvider) };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        GET_AUTHENTICATION_PROVIDER_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            RPC_WSTR providerString;
            (void)UuidToStringW(&response->provider, &providerString);
            lsa->out << "Provider: " << providerString << std::endl;
            RpcStringFreeW(&providerString);
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetDpApiCredKeyDecryptStatus(PLUID luid) const {
        GET_DP_API_CRED_KEY_DECRYPT_STATUS_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        GET_DP_API_CRED_KEY_DECRYPT_STATUS_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "IsDecrypted: " << response->IsDecrypted << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetPublicCachedInfo() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::GetPublicCachedInfo);
    }

    bool Api::GetPwdExpiryInfo(PLUID luid) const {
        GET_PWD_EXPIRY_INFO_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PCloudAPPwdExpiryInfoOutput response;
        size_t returnLength;
        auto result{ CallPackage(request, &response, &returnLength) };
        if (result) {
            FILETIME forever{ 0xd5969fff, 0x7fffff36 };
            if (response->ftExpiryTime.dwHighDateTime == forever.dwHighDateTime && response->ftExpiryTime.dwLowDateTime == forever.dwLowDateTime) {
                std::wcout << "PwdExpirationTime: Never" << std::endl;
            } else {
                SYSTEMTIME systemTime = { 0 };
                FileTimeToSystemTime(&response->ftExpiryTime, &systemTime);
                auto size{ GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &systemTime, nullptr, nullptr, 0) };
                std::vector<wchar_t> formattedTime(size, 0);
                if (GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, &systemTime, nullptr, formattedTime.data(), formattedTime.size())) {
                    std::wcout << "PwdExpirationTime: " << std::wstring(formattedTime.data()) << std::endl;
                }
            }
            std::wcout << "PwdResetUrl: " << std::wstring(response->awchPwdResetUrl) << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetTokenBlob(PLUID luid) const {
        CloudAPGetTokenInput request = { static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::GetTokenBlob) };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        char* response;
        size_t returnBufferLength;
        auto result{ CallPackage(request, &response, &returnBufferLength) };
        if (result) {
            OutputHex(lsa->out, "TokenBlob", std::string(response, returnBufferLength));
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetUnlockKeyType(PLUID luid) const {
        GET_UNLOCK_KEY_TYPE_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        GET_UNLOCK_KEY_TYPE_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "Type: " << response->Type << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::IsCloudToOnPremTgtPresentInCache(PLUID luid) const {
        IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_REQUEST request;
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        IS_CLOUD_TO_ON_PREM_TGT_PRESENT_IN_CACHE_RESPONSE* response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            lsa->out << "IsPresent: " << response->IsPresent << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::ProfileDeleted() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ProfileDeleted);
    }

    bool Api::ProvisionNGCNode() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ProvisionNGCNode);
    }

    bool Api::RefreshTokenBlob() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::RefreshTokenBlob);
    }

    bool Api::ReinitPlugin() const {
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::ReinitPlugin);
    }

    bool Api::RenameAccount() const { // xxx
        return this->CallPackage(PROTOCOL_MESSAGE_TYPE::RenameAccount);
    }

    bool Api::SetTestParas(ULONG TestFlags) const {
        CloudAPSetIdCacheFlushParasInput request = { static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::SetTestParas) };
        request.bFlushSync = TestFlags;
        void* response{ nullptr };
        auto status{ CallPackage(&request, &response) };
        return status;
    }

    bool Api::TransferCreds(PLUID sourceLuid, PLUID destinationLuid) const {
        SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST request = { static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::TransferCreds) };
        request.OriginLogonId.LowPart = sourceLuid->LowPart;
        request.OriginLogonId.HighPart = sourceLuid->HighPart;
        request.DestinationLogonId.LowPart = destinationLuid->LowPart;
        request.DestinationLogonId.HighPart = destinationLuid->HighPart;
        request.Flags = 0; // Ignored by cloudap
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(CLOUDAP_NAME_A, submitBuffer, returnBuffer);
        }
        return false;
    }

    bool Api::CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const {
        auto request{ static_cast<ULONG>(MessageType) };
        void* response{ nullptr };
        return this->CallPackage(request, &response);
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        size_t returnBufferLength;
        return CallPackage(submitBuffer, returnBuffer, &returnBufferLength);
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer, size_t* returnBufferLength) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(CLOUDAP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}

namespace Cloudap::Aad {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : Cloudap::Api(lsa) {
    }

    bool Api::CheckDeviceKeysHealth() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":4}", &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::CreateBindingKey() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":12}", &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::CreateDeviceSSOCookie(const std::string& server, const std::string& nonce) const {
        std::stringstream stream;
        stream << "{\"call\":8,\"payload\":\"https://" << server << "/?sso_nonce=" << nonce << "\", \"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::CreateEnterpriseSSOCookie(const std::string& server, const std::string& nonce) const {
        std::stringstream stream;
        stream << "{\"call\":15,\"payload\":\"https://" << server << "/?sso_nonce=" << nonce << "\", \"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::CreateNonce() const {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/74b5513f-08d4-4807-b899-5e03dc9c8d6e
        std::stringstream stream;
        stream << "{\"call\":9,\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::CreateSSOCookie(const std::string& server, const std::string& nonce) const {
        std::stringstream stream;
        stream << "{\"call\":2,\"payload\":\"https://" << server << "/?sso_nonce=" << nonce << "\", \"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::DeviceAuth() const {
        std::stringstream stream;
        stream << "{\"call\":5,\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Api::DeviceValidityCheck() const {
        std::stringstream stream;
        stream << "{\"call\":7,\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength);
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::GenerateBindingClaims() const {
        return false;
    }

    bool Api::GetPrtAuthority(AUTHORITY_TYPE authority) const {
        std::stringstream stream;
        stream << "{\"call\":3,\"authoritytype\":" << authority << "}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result{ CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength) };
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::RefreshP2PCACert() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":6}", &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Api::RefreshP2PCerts() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":11}", &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Api::SignPayload() const {
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result = CallPluginGeneric(&AadGlobalIdProviderGuid, "{\"call\":1}", &returnBuffer, &returnBufferLength);
        std::cout << returnBuffer << std::endl;
        return result;
    }

    bool Api::ValidateRdpAssertionRequest(const std::string& authenticationRequest) const {
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/25861219-8546-4780-a9c3-1f709daf4dde
        std::stringstream stream;
        stream << "{\"call\":10,\"payload\":\"" << authenticationRequest << "\",\"correlationId\":\"" << CorrelationId() << "\"}";
        void* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result{ CallPluginGeneric(&AadGlobalIdProviderGuid, stream.str(), &returnBuffer, &returnBufferLength) };
        if (result) {
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }
}

namespace Cloudap::Msa {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : Cloudap::Api(lsa) {
    }

#pragma warning(push)
#pragma warning(disable : 6011; disable : 6387) // Assume all allocations succeed for brevity
    bool Api::GetSignedProofOfPossessionTokens(const std::wstring& email) const {
        bool result{ false };
        if (lsa->Connected()) {
            auto previousSehTranslator{ _set_se_translator(SehTranslator) };
            try {
                char* inputBuffer{ nullptr };
                unsigned long inputBufferSize;
                handle_t encodingHandle;
                if (MesEncodeDynBufferHandleCreate(&inputBuffer, &inputBufferSize, &encodingHandle) == RPC_S_OK) {
                    WlidPropertyBag wlidPropertyBag = { 0 };
                    try {
                        wlidPropertyBag.propertyCount = 3;
                        auto propertyArraySize{ sizeof(WlidProperty) * wlidPropertyBag.propertyCount };
                        wlidPropertyBag.pPropertyArray = reinterpret_cast<PWlidProperty>(std::malloc(propertyArraySize));
                        auto pPropertyArray{ wlidPropertyBag.pPropertyArray };
                        std::memset(reinterpret_cast<char*>(pPropertyArray), '\0', propertyArraySize);
                        // The meaning of the 1st property is unknown but its value is verified
                        // by MicrosoftAccountCloudAP!ValidateSerializedProtocolBuffer
                        pPropertyArray[0].dataSize = sizeof(int);
                        pPropertyArray[0].pData = reinterpret_cast<PBYTE>(std::malloc(pPropertyArray[0].dataSize));
                        *reinterpret_cast<int*>(pPropertyArray[0].pData) = 2;
                        // The 2nd property is used by MicrosoftAccountCloudAP!HandleGenericCallPkg
                        // to set the value of "MicrosoftAccount:target=SSO_POP_User:user="
                        pPropertyArray[1].dataSize = (email.size() + 1) * sizeof(wchar_t);
                        pPropertyArray[1].pData = reinterpret_cast<PUCHAR>(std::malloc(pPropertyArray[1].dataSize));
                        std::memset(pPropertyArray[1].pData, '\0', pPropertyArray[1].dataSize);
                        std::memcpy(pPropertyArray[1].pData, email.data(), email.size() * sizeof(wchar_t));
                        auto marshelSize{ WlidPropertyBag_AlignSize(encodingHandle, &wlidPropertyBag) };
                        inputBuffer = reinterpret_cast<char*>(std::malloc(marshelSize));
                        std::memset(inputBuffer, '\0', marshelSize);
                        if (MesBufferHandleReset(encodingHandle, MES_FIXED_BUFFER_HANDLE, MES_ENCODE, &inputBuffer, marshelSize, &inputBufferSize) == RPC_S_OK) {
                            WlidPropertyBag_Encode(encodingHandle, &wlidPropertyBag);
                            std::string inputBuffer(inputBuffer, inputBufferSize);
                            char* returnBuffer{ nullptr };
                            size_t returnBufferLength{ 0 };
                            if (CallPluginGeneric(&WLIDProviderGuid, inputBuffer, reinterpret_cast<void**>(&returnBuffer), &returnBufferLength)) {
                                handle_t decodingHandle;
                                if (MesDecodeBufferHandleCreate(returnBuffer, returnBufferLength, &decodingHandle) == RPC_S_OK) {
                                    ProofOfPossessionTokenBag popTokenBag = { 0 };
                                    try {
                                        ProofOfPossessionTokenBag_Decode(decodingHandle, &popTokenBag);
                                        for (size_t index{ 0 }; index < popTokenBag.tokenCount; index++) {
                                            auto& popTokenData{ popTokenBag.pTokenArray[index] };
                                            lsa->out << "Pop token " << index << std::endl;
                                            lsa->out << "    Name     : " << popTokenData.pName << std::endl;
                                            lsa->out << "    Url      : " << popTokenData.pUrl << std::endl;
                                            lsa->out << "    P3pHeader: " << popTokenData.pP3pHeader << std::endl;
                                            lsa->out << "    TokenData: " << popTokenData.pTokenData << std::endl;
                                            lsa->out << "    Flags    : " << popTokenData.flags << std::endl;
                                            lsa->out << "    Type     : " << ((popTokenData.tokenType == UserToken) ? "UserToken" : "DeviceToken") << std::endl;
                                        }

                                    } catch (...) {
                                    }
                                    ProofOfPossessionTokenBag_Free(decodingHandle, &popTokenBag);
                                    MesHandleFree(decodingHandle);
                                }
                                LsaFreeReturnBuffer(returnBuffer);
                            }
                        }
                    } catch (...) {
                    }
                    if (inputBuffer) {
                        std::free(inputBuffer);
                    }
                    if (wlidPropertyBag.pPropertyArray) {
                        if (wlidPropertyBag.pPropertyArray[0].pData) {
                            std::free(wlidPropertyBag.pPropertyArray[0].pData);
                        }
                        if (wlidPropertyBag.pPropertyArray[1].pData) {
                            std::free(wlidPropertyBag.pPropertyArray[1].pData);
                        }
                        std::free(wlidPropertyBag.pPropertyArray);
                    }
                    MesHandleFree(encodingHandle);
                }
            } catch (...) {
            }
            (void)_set_se_translator(previousSehTranslator);
        }
        return result;
    }
#pragma warning(pop)
}