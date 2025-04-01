// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"

namespace NegoExts {
    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);
        
        bool FlushContext(ULONGLONG contextHandle) const;
        bool GetCredUIContext(ULONGLONG contextHandle, GUID& credType, LUID& logonSession) const;
        bool LookupContext(const std::wstring& target) const;
        bool UpdateCredentials(ULONGLONG contextHandle, GUID& credType, const std::string& data) const;

    protected:
        std::shared_ptr<Lsa::Api> lsa;

    private:
        // You must free all returnBuffer outputs with LsaFreeReturnBuffer
        bool CallPackage(const std::string& submitBuffer, void** returnBuffer) const;

        template<typename _Request, typename _Response>
        bool CallPackage(const _Request& submitBuffer, _Response** returnBuffer) const;
    };
}