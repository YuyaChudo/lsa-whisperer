// Copyright (C) 2024 Evan McBroom
//
// [MS-RDPEAR]: Remote Desktop Protocol Authentication Redirection Virtual Channel
//
#pragma once
#include <phnt_windows.h>

#include "um/msasn1.h"

#define TSRemoteGuardInnerPacket_PDU 0

#define SIZE_RDPEAR_Module_PDU_0 sizeof(TSRemoteGuardInnerPacket)

#ifdef __cplusplus
extern "C" {
#endif

enum TSRemoteGuardVersion;

struct TSRemoteGuardInnerPacket;

typedef enum TSRemoteGuardVersion {
    tsremoteguardv1 = 0,
} TSRemoteGuardVersion;

typedef struct TSRemoteGuardInnerPacket {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
#define version_present 0x80
    TSRemoteGuardVersion version;
    ASN1octetstring_t packageName;
    ASN1octetstring_t buffer;
#define extension_present 0x40
    ASN1open_t extension;
} TSRemoteGuardInnerPacket;

extern TSRemoteGuardVersion TSRemoteGuardInnerPacket_version_default;

extern ASN1module_t RDPEAR_Module;
extern void ASN1CALL RDPEAR_Module_Startup();
extern void ASN1CALL RDPEAR_Module_Cleanup();

#ifdef __cplusplus
} // Closes extern "C" above
namespace Asn1 {
    namespace Rdpear {
        // Enumerations
        using GuardVersion = TSRemoteGuardVersion;

        using InnerPacket = TSRemoteGuardInnerPacket;
    }
}
#endif
