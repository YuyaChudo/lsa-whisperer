// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    KERB_QUERY_BINDING_CACHE_REQUEST request1;
    request1.MessageType = KerbQueryBindingCacheMessage;
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(request1);
    submitBuffer.data = reinterpret_cast<char*>(&request1);
    Libc::CHAR_SPAN returnBuffer;
    PIC_WSTRING(sspicli, L"SSPICLI.DLL");
    LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
    PIC_STRING(kerberos, MICROSOFT_KERBEROS_NAME_A);
    if (LsaApi::CallPackage(kerberos, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<PKERB_QUERY_BINDING_CACHE_RESPONSE>(returnBuffer.data);
        for (size_t index = 0; index < response->CountOfEntries; index++) {
            auto entry = response->Entries + index;
            PIC_STRING(message01, "Binding cache %u\n");
            BeaconPrintf(CallbackType::OUTPUT, message01, index);
            PIC_STRING(message02, "    DiscoveryTime: 0x%p\n");
            BeaconPrintf(CallbackType::OUTPUT, message02, entry->DiscoveryTime);
            PIC_STRING(message03, "    RealmName    : %wZ\n");
            BeaconPrintf(CallbackType::OUTPUT, message03, entry->RealmName);
            PIC_STRING(message04, "    KdcAddress   : %wZ\n");
            BeaconPrintf(CallbackType::OUTPUT, message04, entry->KdcAddress);
            PIC_STRING(message05, "    AddressType  : 0x%04X\n");
            BeaconPrintf(CallbackType::OUTPUT, message05, entry->AddressType);
            PIC_STRING(message06, "    Flags        : 0x%04X\n");
            BeaconPrintf(CallbackType::OUTPUT, message06, entry->Flags);
            PIC_STRING(message07, "    DcFlags      : 0x%04X\n");
            BeaconPrintf(CallbackType::OUTPUT, message07, entry->DcFlags);
            PIC_STRING(message08, "    CacheFlags   : 0x%04X\n");
            BeaconPrintf(CallbackType::OUTPUT, message08, entry->CacheFlags);
            PIC_STRING(message09, "    KdcName      : %wZ\n");
            BeaconPrintf(CallbackType::OUTPUT, message09, entry->KdcName);
        }
        if (!response->CountOfEntries) {
            PIC_STRING(message, "The binding cache is currently empty.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    } else {
        PIC_STRING(message, "Failed to query the binding cache. A binding cache entry likely does not exist for this host.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    if (BeaconDataLength(&beaconData) >= sizeof(int)) {
        KERB_QUERY_KDC_PROXY_CACHE_REQUEST request2;
        request2.MessageType = KerbQueryKdcProxyCacheMessage;
        request2.Flags = 0;
        request2.LogonId.HighPart = 0;
        request2.LogonId.LowPart = BeaconDataInt(&beaconData);
        submitBuffer.count = sizeof(request2);
        submitBuffer.data = reinterpret_cast<char*>(&request2);
        if (LsaApi::CallPackage(kerberos, &submitBuffer, &returnBuffer)) {
            auto response = reinterpret_cast<PKERB_QUERY_KDC_PROXY_CACHE_RESPONSE>(returnBuffer.data);
            PIC_STRING(yesString, "yes");
            PIC_STRING(noString, "no");
            for (size_t index = 0; index < response->CountOfEntries; index++) {
                auto& entry{ response->Entries[index] };
                PIC_STRING(message01, "Kdc proxy cache %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message01, index);
                PIC_STRING(message02, "    SinceLastUsed  : 0x%p\n");
                BeaconPrintf(CallbackType::OUTPUT, message02, entry.SinceLastUsed);
                PIC_STRING(message03, "    DomainName     : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message03, entry.DomainName);
                PIC_STRING(message04, "    ProxyServerName: %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message04, entry.ProxyServerName);
                PIC_STRING(message05, "    ProxyServerVdir: %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message05, entry.ProxyServerVdir);
                PIC_STRING(message06, "    ProxyServerPort: %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message06, entry.ProxyServerPort);
                PIC_STRING(message07, "    LogonId        : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message07, entry.LogonId);
                PIC_STRING(message08, "    CredUserName   : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message08, entry.CredUserName);
                PIC_STRING(message09, "    CredDomainName : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message09, entry.CredDomainName);
                PIC_STRING(message10, "    GlobalCache    : %s\n");
                BeaconPrintf(CallbackType::OUTPUT, message10, (entry.GlobalCache) ? yesString : noString);
            }
            (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
        } else {
            PIC_STRING(message, "Failed to query the kdc proxy cache.\n");
            BeaconPrintf(CallbackType::ERROR, message);
        }
        // KERB_QUERY_KDC_PROXY_CACHE_REQUEST is the same format as
        // KERB_QUERY_S4U2PROXY_CACHE_REQUEST and may be used as is.
        request2.MessageType = KerbQueryS4U2ProxyCacheMessage;
        if (LsaApi::CallPackage(kerberos, &submitBuffer, &returnBuffer)) {
            auto response = reinterpret_cast<PKERB_QUERY_S4U2PROXY_CACHE_RESPONSE>(returnBuffer.data);
            for (size_t index = 0; index < response->CountOfCreds; index++) {
                auto& cred{ response->Creds[index] };
                PIC_STRING(message01, "S4u2 proxy cache %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message01, index);
                PIC_STRING(message02, "    UserName  : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message02, cred.UserName);
                PIC_STRING(message03, "    DomainName: %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message03, cred.DomainName);
                PIC_STRING(message04, "    Flags     : 0x%04X\n");
                BeaconPrintf(CallbackType::OUTPUT, message04, cred.Flags);
                PIC_STRING(message05, "    LastStatus: 0x%04X\n");
                BeaconPrintf(CallbackType::OUTPUT, message05, cred.LastStatus);
                PIC_STRING(message06, "    Expiry    : 0x%p\n");
                BeaconPrintf(CallbackType::OUTPUT, message06, cred.Expiry);
                for (size_t index = 0; index < cred.CountOfEntries; index++) {
                    auto& entry{ cred.Entries[index] };
                    PIC_STRING(message07, "    Entry %u:\n");
                    BeaconPrintf(CallbackType::OUTPUT, message07, index);
                    PIC_STRING(message08, "        ServerName: %wZ\n");
                    BeaconPrintf(CallbackType::OUTPUT, message08, entry.ServerName);
                    PIC_STRING(message09, "        Flags     : 0x%04X\n");
                    BeaconPrintf(CallbackType::OUTPUT, message09, entry.Flags);
                    PIC_STRING(message10, "        LastStatus: 0x%04X\n");
                    BeaconPrintf(CallbackType::OUTPUT, message10, entry.LastStatus);
                    PIC_STRING(message11, "        Expiry    : 0x%p\n");
                    BeaconPrintf(CallbackType::OUTPUT, message11, entry.Expiry);
                }
            }
            (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
        } else {
            PIC_STRING(message, "Failed to query the s4u2 proxy cache.\n");
            BeaconPrintf(CallbackType::ERROR, message);
        }
    }
}