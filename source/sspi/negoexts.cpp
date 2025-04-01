// Copyright (C) 2025 Evan McBroom
#include "sspi/negoexts.hpp"
#include "sspi/crypt.hpp"
#include <string>

namespace NegoExts {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::FlushContext(ULONGLONG contextHandle) const {
        NEGOTIATE_FLUSH_CONTEXT_REQUEST request = { NegFlushContext, sizeof(NEGOTIATE_FLUSH_CONTEXT_REQUEST) };
        request.ContextHandle = contextHandle;
        void* response;
        return CallPackage(request, &response);
    }

    bool Api::GetCredUIContext(ULONGLONG contextHandle, GUID& credType, LUID& logonSession) const {
        NEGOTIATE_GET_CREDUI_CONTEXT_REQUEST request{ NegGetCredUIContext, sizeof(NEGOTIATE_GET_CREDUI_CONTEXT_REQUEST) };
        request.ContextHandle = contextHandle;
        request.CredType = credType;
        request.LogonId.HighPart = logonSession.HighPart;
        request.LogonId.LowPart = logonSession.LowPart;
        PNEGOTIATE_GET_CREDUI_CONTEXT_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::LookupContext(const std::wstring& target) const {
        auto requestSize{ sizeof(NEGOTIATE_LOOKUP_CONTEXT_REQUEST) + ((target.length() + 1) * sizeof(wchar_t)) };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PNEGOTIATE_LOOKUP_CONTEXT_REQUEST>(requestBytes.data()) };
        request->MessageType = NegLookupContext;
        request->cbHeaderLength = sizeof(NEGOTIATE_LOOKUP_CONTEXT_REQUEST);

        auto ptrTarget{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrTarget, target.data(), target.size() * sizeof(wchar_t));
        request->TargetNameOffset = sizeof(NEGOTIATE_LOOKUP_CONTEXT_REQUEST);
        request->TargetNameLengthInCharacters = target.size() * sizeof(wchar_t);

        PNEGOTIATE_LOOKUP_CONTEXT_RESPONSE response{ nullptr };
        auto result{ this->CallPackage(requestBytes, reinterpret_cast<void**>(&response)) };
        if (result) {
            lsa->out << "ContextHandle: " << response->ContextHandle << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::UpdateCredentials(ULONGLONG contextHandle, GUID& credType, const std::string& data) const {
        auto requestSize{ sizeof(NEGOTIATE_UPDATE_CREDENTIALS_REQUEST) + data.length() };
        std::string requestBytes(requestSize, '\0');
        auto request{ reinterpret_cast<PNEGOTIATE_UPDATE_CREDENTIALS_REQUEST>(requestBytes.data()) };
        request->MessageType = NegUpdateCredentials;
        request->cbHeaderLength = sizeof(NEGOTIATE_UPDATE_CREDENTIALS_REQUEST);

        request->ContextHandle = contextHandle;
        request->CredType = credType;

        auto ptrData{ reinterpret_cast<std::byte*>(request + 1) };
        std::memcpy(ptrData, data.data(), data.size());
        request->FlatCredUIContextOffset = sizeof(NEGOTIATE_UPDATE_CREDENTIALS_REQUEST);
        request->FlatCredUIContextLength = data.length();

        void* response;
        return this->CallPackage(requestBytes, &response);
    }

    bool Api::CallPackage(const std::string& submitBuffer, void** returnBuffer) const {
        if (lsa->Connected()) {
            return lsa->CallPackage(NEGOEX_NAME_A, submitBuffer, returnBuffer);
        }
        return false;
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(NEGOEX_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}