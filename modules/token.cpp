// Copyright (C) 2025 Evan McBroom
#define UNICODE
#include "lazy.h"
#include "lwdk.h"
#include "winsta.h"
#include <clipp.h>
#include <codecvt>
#include <iostream>
#include <lmcons.h>
#include <locale>
#include <tlhelp32.h>

extern "C" {
int elevate(int argc, char** argv) {
    bool showHelp{ false };
    long pid{ -1 };
    // clang-format off
    auto args = (
        clipp::option("-h", "--help").set(showHelp).doc("Show this help message."),
        clipp::option("--pid").doc("An alternative process id than WinLogon to impersonate.") & clipp::value("pid", pid)
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return 0;
    }
    bool succeeded{ false };
    // Enable the debug privilege for the current process
    bool enabledDebugPrivilege{ false };
    HANDLE currentPrimaryToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &currentPrimaryToken)) {
        LUID luid;
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES privileges = { 0 };
            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Luid = luid;
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            enabledDebugPrivilege = AdjustTokenPrivileges(currentPrimaryToken, false, &privileges, sizeof(privileges), nullptr, nullptr);
        }
        CloseHandle(currentPrimaryToken);
    }
    if (enabledDebugPrivilege) {
        // Resolve the pid for the WinLogon process, if needed
        if (pid == -1) {
            HANDLE processSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
            if (processSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 processEntry;
                processEntry.dwSize = sizeof(PROCESSENTRY32);
                Process32First(processSnapshot, &processEntry);
                do {
                    if (!std::wcscmp(processEntry.szExeFile, L"winlogon.exe")) {
                        pid = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(processSnapshot, &processEntry));
                CloseHandle(processSnapshot);
            } else {
                std::cout << "Failed to enumerate the currently running processes." << std::endl;
            }
        }
        if (pid != -1) {
            // Impersonate the target process
            HANDLE process{ OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) };
            HANDLE primaryToken;
            if (OpenProcessToken(process, TOKEN_DUPLICATE, &primaryToken)) {
                HANDLE impersonationToken;
                if (DuplicateTokenEx(primaryToken, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, NULL, SecurityDelegation, TokenImpersonation, &impersonationToken)) {
                    succeeded = ImpersonateLoggedOnUser(impersonationToken);
                    CloseHandle(impersonationToken);
                }
                CloseHandle(primaryToken);
            } else {
                std::cout << "Could not get a handle to the target process." << std::endl;
            }
        } else {
            std::cout << "Could not find the WinLogon process." << std::endl;
        }
    } else {
        std::cout << "Failed to enable the debug privilege. Please check that you are running as an Administrator or that you process has the privilege." << std::endl;
    }
    return (succeeded) ? 0 : -1;
}

#pragma warning(push)
#pragma warning(disable : 6387) // Disables a warning that info.UserToken isn't checked when it is
int impersonate(int argc, char** argv) {
    bool showHelp{ false };
    long session{ -1 };
    // clang-format off
    auto args = (
        clipp::required("--session").doc("Windows stations session id to impersonate.") & clipp::value("id", session),
        clipp::option("-h", "--help").set(showHelp).doc("Show this help message.")
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (session == -1 || showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return (session == -1) ? -1 : 0;
    }
    bool succeeded{ false };
    LAZY_LOAD_LIBRARY_AND_PROC(Winsta, WinStationQueryInformationW);
    if (LazyWinsta) {
        WINSTATIONUSERTOKEN info = { 0 };
        ULONG returnLength;
        if (LazyWinStationQueryInformationW(nullptr, session, WinStationUserToken, &info, sizeof(info), &returnLength) && info.UserToken) {
            HANDLE impersonationToken;
            if (DuplicateTokenEx(info.UserToken, 0, nullptr, SecurityDelegation, TokenImpersonation, &impersonationToken)) {
                if (ImpersonateLoggedOnUser(impersonationToken)) {
                    succeeded = true;
                }
            }
            CloseHandle(info.UserToken);
        }
        FreeLibrary(LazyWinsta);
    }
    return (succeeded) ? 0 : -1;
}
#pragma warning(pop)

int revert_to_self(int, char**) {
    return (RevertToSelf()) ? 0 : -1;
}

int set_privilege(int argc, char** argv) {
    bool showHelp{ false };
    std::string privilege;
    bool disable{ false };
    // clang-format off
    auto args = (
        clipp::required("--privilege").doc("Privilege to enable or disable.") & clipp::value("id", privilege),
        clipp::option("--disable").set(disable).doc("Disable the privilege instead of enabling it."),
        clipp::option("-h", "--help").set(showHelp).doc("Show this help message.")
    );
    // clang-format on
    clipp::parse(argc, argv, args);
    if (!privilege.size() || showHelp) {
        std::cout << clipp::make_man_page(args) << std::endl;
        return (!privilege.size()) ? -1 : 0;
    }
    bool succeeded{ false };
    HANDLE processToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &processToken)) {
        LUID luid;
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        auto privilegeArg{ converter.from_bytes(privilege) };
        if (LookupPrivilegeValueW(nullptr, privilegeArg.data(), &luid)) {
            TOKEN_PRIVILEGES privileges = { 0 };
            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Luid = luid;
            privileges.Privileges[0].Attributes = (!disable) ? SE_PRIVILEGE_ENABLED : 0;
            if (AdjustTokenPrivileges(processToken, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
                succeeded = true;
            }
        }
        CloseHandle(processToken);
    }
    return (succeeded) ? 0 : -1;
}

int whoami(int, char**) {
    std::vector<wchar_t> userName(UNLEN + 1, L'\0');
    DWORD length{ static_cast<DWORD>(userName.size()) };
    GetUserNameW(userName.data(), &length);
    std::wcout << userName.data() << std::endl;
    return 0;
}
}