// Copyright (C) 2025 Evan McBroom
#include "sspi/livessp.hpp"
#include "sspi/crypt.hpp"
#include <codecvt>
#include <iomanip>
#include <iostream>
#include <locale>
#include <string>

namespace {
    void SehTranslator(UINT code, _EXCEPTION_POINTERS* pointers) {
        throw std::exception();
    }
}

namespace Live {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::GetSignedProofOfPossessionToken() const {
        auto request{ static_cast<ULONG>(PROTOCOL_MESSAGE_TYPE::GetSignedProofOfPossessionToken) };
        char* returnBuffer{ nullptr };
        size_t returnBufferLength{ 0 };
        auto result{ CallPackage(request, reinterpret_cast<void**>(&returnBuffer), &returnBufferLength) };
        if (result) {
            handle_t decodingHandle;
            auto bufferPos{ returnBuffer };
            if (MesDecodeBufferHandleCreate(returnBuffer, returnBufferLength, &decodingHandle) == RPC_S_OK) {
                auto previousSehTranslator{ _set_se_translator(SehTranslator) };
                ProofOfPossessionTokenBagOld popTokenBag = { 0 };
                try {
                    ProofOfPossessionTokenBagOld_Decode(decodingHandle, &popTokenBag);
                    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
                    for (size_t index{ 0 }; index < popTokenBag.tokenCount; index++) {
                        auto& popTokenData{ popTokenBag.pTokenArray[index] };
                        lsa->out << "Pop token " << index << std::endl;
                        lsa->out << "    Name     : " << converter.to_bytes(popTokenData.pName) << std::endl;
                        lsa->out << "    Url      : " << converter.to_bytes(popTokenData.pUrl) << std::endl;
                        lsa->out << "    P3pHeader: " << converter.to_bytes(popTokenData.pP3pHeader) << std::endl;
                        lsa->out << "    TokenData: " << converter.to_bytes(popTokenData.pTokenData) << std::endl;
                        lsa->out << "    Flags    : " << popTokenData.flags << std::endl;
                        lsa->out << "    Type     : " << ((popTokenData.tokenType == UserToken) ? "UserToken" : "DeviceToken") << std::endl;
                    }

                } catch (...) {
                }
                ProofOfPossessionTokenBagOld_Free(decodingHandle, &popTokenBag);
                MesHandleFree(decodingHandle);
                (void)_set_se_translator(previousSehTranslator);
            }
            LsaFreeReturnBuffer(returnBuffer);
        }
        return result;
    }

    bool Api::CallPackage(PROTOCOL_MESSAGE_TYPE MessageType) const {
        auto request{ static_cast<ULONG>(MessageType) };
        void* response{ nullptr };
        size_t responseLength;
        return this->CallPackage(request, &response, &responseLength);
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer, size_t* returnBufferLength) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(LIVE_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer), returnBufferLength);
        }
        return false;
    }
}