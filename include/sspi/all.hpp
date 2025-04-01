// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"

namespace AllPackages {
    // Actually starts at 1024, but magic_enum appears to have a bug and can't process enums with explicit values
    // The enum is only declared for to use with magic_enum though for processing user input so we allow it to start at 0
    enum class PROTOCOL_MESSAGE_TYPE : ULONG {
        PinDc,
        UnpinAllDcs,
        TransferCred
    };

    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        bool PinDc(const std::wstring& domainName, const std::wstring& dcName, ULONG dcFlags) const;
        bool UnpinAllDcs() const;
        bool TransferCred(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const;

        std::shared_ptr<Lsa::Api> lsa;

    private:
        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;
    };
}