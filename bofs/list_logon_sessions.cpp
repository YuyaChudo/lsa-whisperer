// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    PIC_WSTRING(sspicli, L"SSPICLI.DLL");
    LAZY_LOAD_PROC(sspicli, LsaEnumerateLogonSessions);
    ULONG count;
    PLUID list;
    if (NT_SUCCESS(LazyLsaEnumerateLogonSessions(&count, &list))) {
        LAZY_LOAD_PROC(sspicli, LsaGetLogonSessionData);
        LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
        PIC_WSTRING(ntdll, L"NTDLL.DLL");
        LAZY_LOAD_PROC(ntdll, RtlConvertSidToUnicodeString);
        LAZY_LOAD_PROC(ntdll, RtlFreeUnicodeString);
        for (size_t index = 0; index < count; index++) {
            PSECURITY_LOGON_SESSION_DATA data = nullptr;
            PIC_STRING(message01, "Logon session %04X-%04X\n");
            BeaconPrintf(CallbackType::OUTPUT, message01, list[index].HighPart, list[index].LowPart);
            if (NT_SUCCESS(LazyLsaGetLogonSessionData(list + index, &data))) {
                PIC_STRING(message02, "    User name         : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message02, data->UserName);
                PIC_STRING(message03, "    Logon domain      : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message03, data->LogonDomain);
                PIC_STRING(message04, "    Auth package      : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message04, data->AuthenticationPackage);
                PIC_STRING(message05, "    Logon type        : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message05, data->LogonType);
                PIC_STRING(message06, "    Session           : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message06, data->Session);
                PIC_STRING(message07, "    Sid               : %wZ\n");
                UNICODE_STRING sidString;
                if (NT_SUCCESS(LazyRtlConvertSidToUnicodeString(&sidString, data->Sid, true))) {
                    BeaconPrintf(CallbackType::OUTPUT, message07, sidString);
                    LazyRtlFreeUnicodeString(&sidString);
                }
                PIC_STRING(message08, "    LogonTime         : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message08, data->LogonTime.QuadPart);
                PIC_STRING(message09, "    LogonServer       : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message09, data->LogonServer);
                PIC_STRING(message10, "    DnsDomainName     : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message10, data->DnsDomainName);
                PIC_STRING(message11, "    Upn               : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message11, data->Upn);
                PIC_STRING(message12, "    UserFlags         : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message12, data->UserFlags);
                PIC_STRING(message13, "    LastLogonInfo\n");
                BeaconPrintf(CallbackType::OUTPUT, message13);
                PIC_STRING(message14, "        LastSuccessfulLogon: 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message14, data->LastLogonInfo.LastSuccessfulLogon.QuadPart);
                PIC_STRING(message15, "        LastFailedLogon    : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message15, data->LastLogonInfo.LastFailedLogon.QuadPart);
                PIC_STRING(message16, "        FailedAttemptCount : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message16, data->LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon);
                PIC_STRING(message17, "    LogonScript       : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message17, data->LogonScript);
                PIC_STRING(message18, "    ProfilePath       : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message18, data->ProfilePath);
                PIC_STRING(message19, "    HomeDirectory     : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message19, data->HomeDirectory);
                PIC_STRING(message20, "    HomeDirectoryDrive: %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message20, data->HomeDirectoryDrive);
                PIC_STRING(message21, "    LogoffTime        : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message21, data->LogoffTime.QuadPart);
                PIC_STRING(message22, "    KickOffTime       : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message22, data->KickOffTime.QuadPart);
                PIC_STRING(message23, "    PasswordLastSet   : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message23, data->PasswordLastSet.QuadPart);
                PIC_STRING(message24, "    PasswordCanChange : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message24, data->PasswordCanChange.QuadPart);
                PIC_STRING(message25, "    PasswordMustChange: 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message25, data->PasswordMustChange.QuadPart);
                (void)LazyLsaFreeReturnBuffer(data);
            } else {
                PIC_STRING(message, "    Could not gather data.\n");
                BeaconPrintf(CallbackType::ERROR, message, list[index].HighPart, list[index].LowPart);
            }
        }
        (void)LazyLsaFreeReturnBuffer(list);
    } else {
        PIC_STRING(message, "Could not enumerate logon sessions.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}