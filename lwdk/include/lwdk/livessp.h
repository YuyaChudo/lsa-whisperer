// Copyright (C) 2024 Evan McBroom
//
// Microsoft Live security support provider (livessp)
//
#pragma once
#include <phnt_windows.h>

#define LIVE_NAME_A "LiveSSP"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct LIVESSP_SERIALIZED_VALIDATION_INFO {
    ULONG bufferVersion;
    ULONG cbStructureLength;
    ULONG cbHeaderLength;
    ULONG credType;
    GUID credKeyVersion;
    ULONG uniqueIdOffset;
    ULONG cbUniqueId;
    ULONG credHashOffset;
    ULONG cbCredHash;
    ULONG liveSSPCacheOffset;
    ULONG cbLiveSSPCache;
    ULONG daTokenOffset;
    ULONG cbDAToken;
    ULONG sessionKeyOffset;
    ULONG cbSessionKey;
} LIVESSP_SERIALIZED_VALIDATION_INFO, *PLIVESSP_SERIALIZED_VALIDATION_INFO;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Live {
    using SERIALIZED_VALIDATION_INFO = LIVESSP_SERIALIZED_VALIDATION_INFO;
}
#endif