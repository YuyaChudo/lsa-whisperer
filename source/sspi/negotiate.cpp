// Copyright (C) 2025 Evan McBroom
#include "sspi/negotiate.hpp"
#include "sspi/crypt.hpp"
#include <string>

namespace Negotiate {
    Api::Api(const std::shared_ptr<Lsa::Api>& lsa)
        : lsa(lsa) {
    }

    bool Api::EnumPackagePrefixes() const {
        PNEGOTIATE_PACKAGE_PREFIXES response;
        auto result{ this->CallPackage(NegEnumPackagePrefixes, &response) };
        if (result) {
            lsa->out << "PrefixCount: " << response->PrefixCount << std::endl;
            auto offset{ reinterpret_cast<byte*>(response) + response->Offset };
            for (size_t count{ response->PrefixCount }; count > 0; count--) {
                auto packagePrefix{ reinterpret_cast<PNEGOTIATE_PACKAGE_PREFIX>(offset) };
                lsa->out << std::to_string(packagePrefix->PackageId) + " Prefix[0x" << packagePrefix->PrefixLen << "]: ";
                OutputHex(lsa->out, std::string(reinterpret_cast<char*>(packagePrefix->Prefix), packagePrefix->PrefixLen));
                lsa->out << std::endl
                         << "         Leak: ";
                OutputHex(lsa->out, std::string(reinterpret_cast<char*>(packagePrefix->Prefix) + packagePrefix->PrefixLen, NEGOTIATE_MAX_PREFIX - packagePrefix->PrefixLen));
                lsa->out << std::endl;
                offset += sizeof(PACKAGE_PREFIX);
            }
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::GetCallerName(PLUID luid) const {
        NEGOTIATE_CALLER_NAME_REQUEST request = { NegGetCallerName };
        request.LogonId.LowPart = luid->LowPart;
        request.LogonId.HighPart = luid->HighPart;
        PNEGOTIATE_CALLER_NAME_RESPONSE response;
        auto result{ CallPackage(request, &response) };
        if (result) {
            std::wcout << "CallerName [" << response->CallerName << "]: " << std::wstring{ reinterpret_cast<PWSTR>(response + 1) } << std::endl;
            LsaFreeReturnBuffer(response);
        }
        return result;
    }

    bool Api::TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const {
        SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST request = { NegTransferCredentials };
        request.OriginLogonId.LowPart = sourceLuid->LowPart;
        request.OriginLogonId.HighPart = sourceLuid->HighPart;
        request.DestinationLogonId.LowPart = destinationLuid->LowPart;
        request.DestinationLogonId.HighPart = destinationLuid->HighPart;
        request.Flags = flags;
        void* response;
        return CallPackage(request, &response);
    }

    template<typename _Request, typename _Response>
    bool Api::CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const {
        if (lsa->Connected()) {
            std::string stringSubmitBuffer(reinterpret_cast<const char*>(&submitBuffer), sizeof(decltype(submitBuffer)));
            return lsa->CallPackage(NEGOSSP_NAME_A, stringSubmitBuffer, reinterpret_cast<void**>(returnBuffer));
        }
        return false;
    }
}