// Copyright (C) 2025 Evan McBroom
#pragma once
#include "sspi/lsa.hpp"
#include <memory>
#include <string>
#include <vector>

namespace Kerberos {
    class Api {
    public:
        Api(const std::shared_ptr<Lsa::Api>& lsa);

        // A subset of the supported functions in Kerberos
        bool AddBindingCacheEntry(const std::wstring& realmName, const std::wstring& kdcAddress, ULONG addressType) const;
        bool AddBindingCacheEntryEx(const std::wstring& realmName, const std::wstring& kdcAddress, ULONG addressType, ULONG dcFlags, bool useEx = true) const;
        bool AddExtraCredentials(PLUID luid, const std::wstring& domainName, const std::wstring& userName, const std::wstring& password, ULONG flags) const;
        bool CleanupMachinePkinitCreds(PLUID luid) const;
        bool PinKdc(const std::wstring& domainName, const std::wstring& dcName, ULONG dcFlags) const;
        bool PrintCloudKerberosDebug(PLUID luid) const;
        bool PurgeBindingCache() const;
        bool PurgeKdcProxyCache(PLUID luid) const;
        bool PurgeTicketCache(PLUID luid, const std::wstring& serverName, const std::wstring& serverRealm) const;
        bool PurgeTicketCacheEx(PLUID luid, ULONG flags, const std::wstring& clientName, const std::wstring& clientRealm, const std::wstring& serverName, const std::wstring& serverRealm) const;
        bool QueryBindingCache() const;
        bool QueryDomainExtendedPolicies(const std::wstring& domainName) const;
        bool QueryKdcProxyCache(PLUID luid) const;
        bool QueryS4U2ProxyCache(PLUID luid) const;
        bool QueryTicketCache(PLUID luid) const;
        bool QueryTicketCacheEx(PLUID luid) const;
        bool QueryTicketCacheEx2(PLUID lRetrieveTicketuid) const;
        bool QueryTicketCacheEx3(PLUID luid) const;
        bool RetrieveTicket(PLUID luid, const std::wstring& targetName, DWORD flags = KERB_TICKET_FLAGS_reserved, DWORD options = KERB_RETRIEVE_TICKET_AS_KERB_CRED, DWORD type = KERB_ETYPE_NULL, bool encoded = false) const;
        bool RetrieveEncodedTicket(PLUID luid, const std::wstring& targetName, DWORD flags = KERB_TICKET_FLAGS_reserved, DWORD options = KERB_RETRIEVE_TICKET_AS_KERB_CRED, DWORD type = KERB_ETYPE_NULL) const;
        bool RetrieveKeyTab(const std::wstring& domainName, const std::wstring& userName, const std::wstring& password) const;
        bool TransferCreds(PLUID sourceLuid, PLUID destinationLuid, ULONG flags) const; // Flags may be CleanupCredentials or OptimisticLogon
        bool UnpinAllKdcs() const;

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