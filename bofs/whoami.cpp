// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport)  void go(PCHAR buffer, ULONG length) {
    PIC_WSTRING(advapi32, L"ADVAPI32.DLL");
    PIC_WSTRING(kernel32, L"KERNEL32.DLL");
    PIC_WSTRING(kernelbase, L"KERNELBASE.DLL");
    LAZY_LOAD_PROC(advapi32, OpenThreadToken);
    LAZY_LOAD_PROC(kernel32, GetCurrentThread);
    LAZY_LOAD_PROC(kernelbase, GetLastError);
    HANDLE token = INVALID_HANDLE_VALUE;
    if (!LazyOpenThreadToken(LazyGetCurrentThread(), TOKEN_ACCESS_PSEUDO_HANDLE, true, &token) && LazyGetLastError() == ERROR_NO_TOKEN) {
        LAZY_LOAD_PROC(advapi32, OpenProcessToken);
        LAZY_LOAD_PROC(kernel32, GetCurrentProcess);
        (void)LazyOpenProcessToken(LazyGetCurrentProcess(), TOKEN_ACCESS_PSEUDO_HANDLE, &token);
    }
    if (token != INVALID_HANDLE_VALUE) {
        LAZY_LOAD_PROC(advapi32, GetTokenInformation);
        DWORD returnLength;
        (void)LazyGetTokenInformation(token, TokenUser, nullptr, 0, &returnLength);
        Libc::CHAR_SPAN buffer;
        buffer.count = returnLength;
        buffer.data = reinterpret_cast<char*>(Libc::malloc(buffer.count));
        Libc::memset(buffer.data, '\0', sizeof(buffer.count));
        if (LazyGetTokenInformation(token, TokenUser, buffer.data, buffer.count, &returnLength)) {
            auto user{ reinterpret_cast<PTOKEN_USER>(buffer.data) };
            DWORD nameLength{ 0 };
            DWORD domainNameLength{ 0 };
            SID_NAME_USE use;
            LAZY_LOAD_PROC(advapi32, LookupAccountSidW);
            LazyLookupAccountSidW(nullptr, user->User.Sid, nullptr, &nameLength, nullptr, &domainNameLength, &use);
            Libc::WCHAR_SPAN name;
            name.count = nameLength;
            name.data = reinterpret_cast<wchar_t*>(Libc::malloc(name.count * sizeof(wchar_t)));
            Libc::WCHAR_SPAN domainName;
            domainName.count = domainNameLength;
            domainName.data = reinterpret_cast<wchar_t*>(Libc::malloc(domainName.count * sizeof(wchar_t)));
            if (LazyLookupAccountSidW(nullptr, user->User.Sid, name.data, &nameLength, domainName.data, &domainNameLength, &use)) {
                PIC_STRING(message, "User              : %S\\%S\n");
                BeaconPrintf(CallbackType::OUTPUT, message, domainName.data, name.data);
            }
            Libc::free(name.data);
            Libc::free(domainName.data);
        }
        LazyGetTokenInformation(token, _TOKEN_INFORMATION_CLASS(TokenStatistics), nullptr, 0, &returnLength);
        buffer.data = reinterpret_cast<char*>(Libc::realloc(buffer.data, returnLength));
        buffer.count = returnLength;
        Libc::memset(buffer.data, '\0', buffer.count);
        if (LazyGetTokenInformation(token, _TOKEN_INFORMATION_CLASS(TokenStatistics), buffer.data, buffer.count, &returnLength)) {
            auto statistics{ reinterpret_cast<PTOKEN_STATISTICS>(buffer.data) };
            PIC_STRING(message01, "Logon session     : %04X-%04X\n");
            BeaconPrintf(CallbackType::OUTPUT, message01, statistics->AuthenticationId.HighPart, statistics->AuthenticationId.LowPart);
            PIC_WSTRING(sspicli, L"SSPICLI.DLL");
            LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
            LAZY_LOAD_PROC(sspicli, LsaGetLogonSessionData);
            PIC_WSTRING(ntdll, L"NTDLL.DLL");
            LAZY_LOAD_PROC(ntdll, RtlConvertSidToUnicodeString);
            LAZY_LOAD_PROC(ntdll, RtlFreeUnicodeString);
            if (statistics->TokenType == 1) {
                PIC_STRING(message02, "Token type        : Primary\n");
                BeaconPrintf(CallbackType::OUTPUT, message02);
            } else {
                PIC_STRING(message02, "Token type        : Impersonation\n");
                BeaconPrintf(CallbackType::OUTPUT, message02);
            }
            PSECURITY_LOGON_SESSION_DATA data;
            if (LazyLsaGetLogonSessionData(&statistics->AuthenticationId, &data) == STATUS_SUCCESS) {
                PIC_STRING(message03, "Auth package      : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message03, data->AuthenticationPackage);
                PIC_STRING(message04, "Logon type        : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message04, data->LogonType);
                PIC_STRING(message05, "Session           : %d\n");
                BeaconPrintf(CallbackType::OUTPUT, message05, data->Session);
                PIC_STRING(message07, "Sid               : %wZ\n");
                UNICODE_STRING sidString;
                if (NT_SUCCESS(LazyRtlConvertSidToUnicodeString(&sidString, data->Sid, true))) {
                    BeaconPrintf(CallbackType::OUTPUT, message07, sidString);
                    LazyRtlFreeUnicodeString(&sidString);
                }
                PIC_STRING(message08, "LogonTime         : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message08, data->LogonTime.QuadPart);
                PIC_STRING(message09, "LogonServer       : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message09, data->LogonServer);
                PIC_STRING(message10, "DnsDomainName     : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message10, data->DnsDomainName);
                PIC_STRING(message11, "Upn               : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message11, data->Upn);
                PIC_STRING(message12, "UserFlags         : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message12, data->UserFlags);
                PIC_STRING(message13, "LastLogonInfo\n");
                BeaconPrintf(CallbackType::OUTPUT, message13);
                PIC_STRING(message14, "    LastSuccessfulLogon: 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message14, data->LastLogonInfo.LastSuccessfulLogon.QuadPart);
                PIC_STRING(message15, "    LastFailedLogon    : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message15, data->LastLogonInfo.LastFailedLogon.QuadPart);
                PIC_STRING(message16, "    FailedAttemptCount : %u\n");
                BeaconPrintf(CallbackType::OUTPUT, message16, data->LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon);
                PIC_STRING(message17, "LogonScript       : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message17, data->LogonScript);
                PIC_STRING(message18, "ProfilePath       : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message18, data->ProfilePath);
                PIC_STRING(message19, "HomeDirectory     : %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message19, data->HomeDirectory);
                PIC_STRING(message20, "HomeDirectoryDrive: %wZ\n");
                BeaconPrintf(CallbackType::OUTPUT, message20, data->HomeDirectoryDrive);
                PIC_STRING(message21, "LogoffTime        : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message21, data->LogoffTime.QuadPart);
                PIC_STRING(message22, "KickOffTime       : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message22, data->KickOffTime.QuadPart);
                PIC_STRING(message23, "PasswordLastSet   : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message23, data->PasswordLastSet.QuadPart);
                PIC_STRING(message24, "PasswordCanChange : 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message24, data->PasswordCanChange.QuadPart);
                PIC_STRING(message25, "PasswordMustChange: 0x%016llX\n");
                BeaconPrintf(CallbackType::OUTPUT, message25, data->PasswordMustChange.QuadPart);
                LazyLsaFreeReturnBuffer(data);
            }
        }
        Libc::free(buffer.data);
    } else {
        PIC_STRING(error, "Could not get the effective token for the current thread.");
        BeaconPrintf(CallbackType::ERROR, error);
    }
}