// Copyright (C) 2024 Evan McBroom
// 
// DPAPI Next Generation (dpapi-ng)
// 
// Additional DPAPI-NG types my be found in efs.h
// and fve.h and they will have the suffix _DPAPI_NG.
//
#pragma once
#include <phnt_windows.h>

#include <dpapi.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _DPAPING_KEYFILE_HEADER;
struct _KEYFILE_KEYINFO;
struct _KEYFILEINFO;
struct _KEYFILENODE;
struct _SESSION_TICKET_INFO;
struct KEYPROT_PROVIDER;

typedef struct _DPAPING_KEYFILE_HEADER {
	ULONG version;
    FILETIME creationTime;
    GUID keyID;
	ULONG cbEncryptedKey;
} DPAPING_KEYFILE_HEADER, *PDPAPING_KEYFILE_HEADER;

typedef struct _KEYFILE_KEYINFO {
    GUID keyID;
} KEYFILE_KEYINFO, *PKEYFILE_KEYINFO;

typedef struct _KEYFILEINFO {
	GUID keyID;
    FILETIME creationTime;
	ULONG cbMemEncKeyBlob;
	PUCHAR pbMemEncKeyBlob;
	HANDLE hKey;
	ULONG cbHashBlob;
	PUCHAR pbHashBlob;
} KEYFILEINFO, *PKEYFILEINFO;

typedef struct _KEYFILENODE {
	PWCHAR keyFilePath;
	ULONG indexToEncryptionKey;
	BOOL fFileChanged;
	HANDLE fileChangeHandle;
    HANDLE eventWaitHandle;
    KEYFILEINFO keyFiles[2];
} KEYFILENODE, *PKEYFILENODE;

typedef struct _SESSION_TICKET_INFO {
    ULONG version;
    GUID keyID;
    UCHAR IV[16];
    UCHAR hmac[32];
} SESSION_TICKET_INFO, *PSESSION_TICKET_INFO;

struct KEYPROT_PROVIDER {
	ULONG cbSize;
	DWORD dwMagic;
	DWORD dwFlags;
	LPWSTR wszName;
};

#ifdef __cplusplus
} // Closes extern "C" above
namespace Dpaping {
    using DPAPING_KEYFILE_HEADER = _DPAPING_KEYFILE_HEADER;
    using KEYFILE_KEYINFO = _KEYFILE_KEYINFO;
    using KEYFILEINFO = _KEYFILEINFO;
    using KEYFILENODE = _KEYFILENODE;
    using SESSION_TICKET_INFO = _SESSION_TICKET_INFO;
    using KEYPROT_PROVIDER = ::KEYPROT_PROVIDER;
}
#endif