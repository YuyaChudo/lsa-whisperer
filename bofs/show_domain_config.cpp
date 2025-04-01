// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"
#include <dsgetdc.h>

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    KERB_QUERY_DOMAIN_EXTENDED_POLICIES_REQUEST request;
    request.MessageType = KerbQueryDomainExtendedPoliciesMessage;
    request.Flags = 0;
    int domainNameSize;
    request.DomainName.Buffer = reinterpret_cast<PWSTR>(BeaconDataExtract(&beaconData, &domainNameSize));
    request.DomainName.Length = Libc::wcslen(request.DomainName.Buffer) * sizeof(WCHAR);
    request.DomainName.MaximumLength = request.DomainName.Length + sizeof(WCHAR);
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(request);
    submitBuffer.data = reinterpret_cast<char*>(&request);
    Libc::CHAR_SPAN returnBuffer;
    PIC_STRING(kerberos, MICROSOFT_KERBEROS_NAME_A);
    if (LsaApi::CallPackage(kerberos, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<PKERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE>(returnBuffer.data);
        PIC_STRING(message01, "Domain extended policies\n");
        BeaconPrintf(CallbackType::OUTPUT, message01);
        PIC_STRING(message02, "    Flags           : 0x%04X\n");
        BeaconPrintf(CallbackType::OUTPUT, message02, response->Flags);
        if (response->Flags & KERB_QUERY_DOMAIN_EXTENDED_POLICIES_RESPONSE_FLAG_DAC_DISABLED) {
            PIC_STRING(message03, "        DAC_DISABLED\n");
            BeaconPrintf(CallbackType::OUTPUT, message03);
        }
        PIC_STRING(message04, "    ExtendedPolicies: 0x%04X\n");
        BeaconPrintf(CallbackType::OUTPUT, message04, response->DsFlags);
        PIC_STRING(message05, "    DsFlags         : 0x%04X\n");
        BeaconPrintf(CallbackType::OUTPUT, message05, response->DsFlags);
        if (response->Flags & DS_PDC_FLAG) {
            PIC_STRING(message, "        DC is the PDC of the domain.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_GC_FLAG) {
            PIC_STRING(message, "        DC is a GC of forest.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_LDAP_FLAG) {
            PIC_STRING(message, "        Server supports an LDAP.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_DS_FLAG) {
            PIC_STRING(message, "        DC supports a DS and is a Domain Controller.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_KDC_FLAG) {
            PIC_STRING(message, "        DC is running the KDC service.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_TIMESERV_FLAG) {
            PIC_STRING(message, "        DC is running the time service.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_CLOSEST_FLAG) {
            PIC_STRING(message, "        DC is in the closest site to the client.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_WRITABLE_FLAG) {
            PIC_STRING(message, "        DC has a writable DS.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_GOOD_TIMESERV_FLAG) {
            PIC_STRING(message, "        DC is running the time service (and has clock hardware).\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_NDNC_FLAG) {
            PIC_STRING(message, "        DomainName is a non-domain NC serviced by the LDAP server.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_SELECT_SECRET_DOMAIN_6_FLAG) {
            PIC_STRING(message, "        DC has some secrets.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_FULL_SECRET_DOMAIN_6_FLAG) {
            PIC_STRING(message, "        DC has all secrets.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_WS_FLAG) {
            PIC_STRING(message, "        DC is running web service.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_DS_8_FLAG) {
            PIC_STRING(message, "        DC is running Windows Server 2008 or later.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_DS_9_FLAG) {
            PIC_STRING(message, "        DC is running Windows Server 2008 R2 or later.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_DS_10_FLAG) {
            PIC_STRING(message, "        DC is running Windows Server 2016 or later.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_KEY_LIST_FLAG) {
            PIC_STRING(message, "        DC supports key list requests.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        if (response->Flags & DS_DS_13_FLAG) {
            PIC_STRING(message, "        DC is running Windows Server 2025 or later.\n");
            BeaconPrintf(CallbackType::OUTPUT, message);
        }
        PIC_WSTRING(sspicli, L"SSPICLI.DLL");
        LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    } else {
        PIC_STRING(message, "Failed to query the extended policy information for the domain.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}