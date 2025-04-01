// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    KERB_PURGE_TKT_CACHE_EX_REQUEST request;
    Libc::memset(&request, '\0', sizeof(request));
    request.MessageType = KerbPurgeTicketCacheExMessage;
    if (BeaconDataLength(&beaconData) >= sizeof(WCHAR)) {
        int dataSize;
        request.TicketTemplate.ServerName.Buffer = reinterpret_cast<PWSTR>(BeaconDataExtract(&beaconData, &dataSize));
        request.TicketTemplate.ServerName.Length = Libc::wcslen(request.TicketTemplate.ServerName.Buffer);
        request.TicketTemplate.ServerName.MaximumLength = request.TicketTemplate.ServerName.Length + 1;
        if (BeaconDataLength(&beaconData) >= sizeof(WCHAR)) {
            request.TicketTemplate.ServerRealm.Buffer = reinterpret_cast<PWSTR>(BeaconDataExtract(&beaconData, &dataSize));
            request.TicketTemplate.ServerRealm.Length = Libc::wcslen(request.TicketTemplate.ServerRealm.Buffer);
            request.TicketTemplate.ServerRealm.MaximumLength = request.TicketTemplate.ServerRealm.Length + 1;
            if (BeaconDataLength(&beaconData) >= sizeof(WCHAR)) {
                request.TicketTemplate.ClientName.Buffer = reinterpret_cast<PWSTR>(BeaconDataExtract(&beaconData, &dataSize));
                request.TicketTemplate.ClientName.Length = Libc::wcslen(request.TicketTemplate.ClientName.Buffer);
                request.TicketTemplate.ClientName.MaximumLength = request.TicketTemplate.ClientName.Length + 1;
                if (BeaconDataLength(&beaconData) >= sizeof(WCHAR)) {
                    request.TicketTemplate.ClientRealm.Buffer = reinterpret_cast<PWSTR>(BeaconDataExtract(&beaconData, &dataSize));
                    request.TicketTemplate.ClientRealm.Length = Libc::wcslen(request.TicketTemplate.ClientRealm.Buffer);
                    request.TicketTemplate.ClientRealm.MaximumLength = request.TicketTemplate.ClientRealm.Length + 1;
                }
            }
        }
    } else {
        request.Flags = KERB_PURGE_ALL_TICKETS;
    }
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(request);
    submitBuffer.data = reinterpret_cast<char*>(&request);
    PIC_STRING(kerberos, MICROSOFT_KERBEROS_NAME_A);
    if (LsaApi::CallPackage(kerberos, &submitBuffer)) {
        PIC_STRING(message, "Successfully purged kerberos tickets.\n");
        BeaconPrintf(CallbackType::OUTPUT, message);
    } else {
        PIC_STRING(message, "Failed to purge kerberos tickets.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
    PIC_STRING(pku2u, PKU2U_PACKAGE_NAME_A);
    if (LsaApi::CallPackage(pku2u, &submitBuffer)) {
        PIC_STRING(message, "Successfully purged pku2u tickets.\n");
        BeaconPrintf(CallbackType::OUTPUT, message);
    } else {
        PIC_STRING(message, "Failed to purge pku2u tickets.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}