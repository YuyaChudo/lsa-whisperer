// Copyright (C) 2024 Evan McBroom
//
// Data Protection API (dpapi)
//
// Additional DPAPI types my be found in cloudap.h
// and they will have the prefix _DPAPI.
//
#pragma once
#include <phnt_windows.h>

#include <ntlsa.h>

#define SYSTEM_CREDENTIALS_VERSION 1
#define SYSTEM_CREDENTIALS_SECRET  L"DPAPI_SYSTEM"

#define CREDENTIAL_HISTORY_VERSION   1
#define CREDENTIAL_HISTORY_SALT_SIZE 16 // 128 bits

#define CRED_SIGNATURE_VERSION 1
#define SIGNATURE_SALT_SIZE    (16)

#define REGVAL_PREFERRED_MK L"Preferred"
#define REGVAL_POLICY_MK    L"ProtectionPolicy"

// MasterKeys\<GUID>\<value>
#define REGVAL_MASTER_KEY     0 // L"MK" - masterkey, encrypted with user credential
#define REGVAL_LOCAL_KEY      1 // L"LK" - phase one backup blob encryption key
#define REGVAL_BACKUP_LCL_KEY 2 // L"BK" - phase one backup blob
#define REGVAL_BACKUP_DC_KEY  3 // L"BBK" - phase two backup blob

#define POLICY_LOCAL_BACKUP 0x1 // Policy bit for local only (no DC) backup
#define POLICY_NO_BACKUP    0x2 // Policy bit for NO backup (Win95)
#define POLICY_DPAPI_OWF    0x4 // Use the DPAPI One way function of the password (SHA_1(pw))

#define LOCALKEY_MATERIAL_SIZE (32) // size of the localkey key material

#define DEFAULT_MASTERKEY_ITERATION_COUNT (4000) // 4000 == ~100ms on 400 MHz machine
#define MASTERKEY_BLOB_LOCALKEY_BACKUP    3
#define MASTERKEY_BLOB_RAW_VERSION        0
#define MASTERKEY_BLOB_VERSION            2
#define MASTERKEY_BLOB_VERSION_W2K        1
#define MASTERKEY_EXPIRES_DAYS            (90)
#define MASTERKEY_MATERIAL_SIZE           (64)
#define MASTERKEY_R2_LEN                  (16)
#define MASTERKEY_R2_LEN_W2K              (16)
#define MASTERKEY_R3_LEN                  (16)
#define MASTERKEY_R3_LEN_W2K              (16)

#define MK_DISP_OK             0 // normal disposition, no backup/restore occured
#define MK_DISP_BCK_LCL        1 // local backup/restore took place
#define MK_DISP_BCK_DC         2 // DC based backup/restore took place
#define MK_DISP_STORAGE_ERR    3 // error retrieving key from storage
#define MK_DISP_DELEGATION_ERR 4 // Recovery failure because delegation disabled
#define MK_DISP_UNKNOWN_ERR    5 // unknown error

// clang-format off
#define BACKUPKEY_BACKUP_GUID              { 0x7f752b10, 0x178e, 0x11d1, { 0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40 } }
#define BACKUPKEY_RESTORE_GUID             { 0x47270c64, 0x2fc7, 0x499b,  {0xac, 0x5b, 0x0e, 0x37, 0xcd, 0xce, 0x89, 0x9a} }
#define BACKUPKEY_RESTORE_GUID_W2K         { 0x7fe94d50, 0x178e, 0x11d1, { 0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40 } }
#define BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID { 0x018ff48a, 0xeaba, 0x40c6, { 0x8f, 0x6d, 0x72, 0x37, 0x02, 0x40, 0xe9, 0x67 } }
// clang-format on

#define BACKUPKEY_LIFETIME                  (60 * 60 * 24 * 365) // 1 Year
#define BACKUPKEY_MATERIAL_SIZE             (256) // monster key material size, excluding version, etc.
#define BACKUPKEY_NAME_PREFIX               L"G$BCKUPKEY_" // LSA secret key name prefix, textual GUID key ID follows
#define BACKUPKEY_PAYLOAD_VERSION           1
#define BACKUPKEY_PREFERRED                 L"G$BCKUPKEY_PREFERRED" // LSA secret key name which identifies GUID of preferred key
#define BACKUPKEY_PREFERRED_W2K             L"G$BCKUPKEY_P" // LSA secret key name which identifies GUID of legacy preferred key
#define BACKUPKEY_PREFIX                    L"BK-"
#define BACKUPKEY_PREFIX_LEN                3
#define BACKUPKEY_PUBLIC_VERSION            1
#define BACKUPKEY_R2_LEN                    (68) // length of random HMAC data
#define BACKUPKEY_R3_LEN                    (32) // size of inner Random R3 used to derive MAC key.
#define BACKUPKEY_RECOVERY_BLOB_VERSION     2 // Version directly contains MK and LK
#define BACKUPKEY_RECOVERY_BLOB_VERSION_W2K 1
#define BACKUPKEY_VERSION                   2 // legacy version of monster key material
#define BACKUPKEY_VERSION_W2K               1 // legacy version of monster key material

#define A_SHA_DIGEST_LEN 20

#ifdef __cplusplus
extern "C" {
#endif

enum _DPAPI_KEY_TYPE;

struct _BACKUP_PUBLIC_KEY;
struct _BACKUPKEY_INNER_BLOB;
struct _MASTERKEY_INNER_BLOB_VISTA;
struct _BACKUPKEY_INNER_BLOB_W2K;
struct _BACKUPKEY_KEY_BLOB;
struct _BACKUPKEY_KEY_BLOB_VISTA;
struct _BACKUPKEY_RECOVERY_BLOB;
struct _BACKUPKEY_RECOVERY_BLOB_W2K;
struct _CRED_SIGNATURE;
struct _CREDENTIAL_HISTORY;
struct _CREDENTIAL_HISTORY_HEADER;
struct _CREDENTIAL_HISTORY_MAP;
struct _CREDENTIAL_HISTORY_MAP_VISTA;
struct _CREDENTIAL_KEY;
struct _DP_KEK;
struct _LOCAL_BACKUP_DATA;
struct _MASTERKEY_BLOB;
struct _MASTERKEY_BLOB_W2K;
struct _MASTERKEY_CACHE_ENTRY;
struct _MASTERKEY_CACHE_ENTRY_VISTA;
struct _MASTERKEY_INNER_BLOB;
struct _MASTERKEY_INNER_BLOB_W2K;
struct _MASTERKEY_PREFERRED_INFO;
struct _MASTERKEY_STORED;
struct _MASTERKEY_STORED_ON_DISK;
struct _QUEUED_BACKUP;
struct _QUEUED_SYNC;
struct _SYSTEM_CREDENTIALS;
struct _sec_blob;

typedef enum _DPAPI_KEY_TYPE{
    KEY_TYPE_NTOWF = 0,
    KEY_TYPE_SHA = 1,
} DPAPI_KEY_TYPE,
    *PDPAPI_KEY_TYPE;

typedef struct _BACKUP_PUBLIC_KEY {
    DWORD dwVersion;
    DWORD cbPublic;
    DWORD cbSignature;
} BACKUP_PUBLIC_KEY, *PBACKUP_PUBLIC_KEY;

/// <summary>
/// Header for the inner blob of the master key recovery blob
/// Following the header is LocalKey, then the SID, and finally
/// a SHA_1 MAC of the contained data
/// </summary>
typedef struct _BACKUPKEY_INNER_BLOB {
    DWORD dwPayloadVersion;
    DWORD cbLocalKey;
} BACKUPKEY_INNER_BLOB, *PBACKUPKEY_INNER_BLOB;

/// <summary>
/// Followed by the user sid then the input data.
/// </summary>
typedef struct _BACKUPKEY_INNER_BLOB_W2K {
    BYTE R3[BACKUPKEY_R3_LEN]; // Random data used to derive MAC key
    BYTE MAC[A_SHA_DIGEST_LEN]; // HMAC(R3, pUserSid | pbClearUserData)
} BACKUPKEY_INNER_BLOB_W2K, *PBACKUPKEY_INNER_BLOB_W2K;

typedef struct _BACKUPKEY_KEY_BLOB {
    DWORD cbMasterKey;
    DWORD cbPayloadKey;
    DWORD dwEncrAlg;
    DWORD dwMacAlg;
} BACKUPKEY_KEY_BLOB, *PBACKUPKEY_KEY_BLOB;

/// <summary>
/// Key structure for Vista and prior.
/// </summary>
typedef struct _BACKUPKEY_KEY_BLOB_VISTA {
    DWORD cbMasterKey;
    DWORD cbPayloadKey;
} BACKUPKEY_KEY_BLOB_VISTA, *PBACKUPKEY_KEY_BLOB_VISTA;

/// <summary>
/// Followed by the master key and the payload key which are both
/// encrypted with the key indicated by guidKey. The encrypted
/// data is represented in a PKCS#1v2 formmated (CRYPT_OAEP) blob
/// That data is followed by the encrypted payload.
/// </summary>
typedef struct _BACKUPKEY_RECOVERY_BLOB {
    DWORD dwVersion;
    DWORD cbEncryptedMasterKey; // Byte count of encrypted master key data following structure
    DWORD cbEncryptedPayload; // Byte count of encrypted payload
    GUID guidKey; // Guid id for the backup key
} BACKUPKEY_RECOVERY_BLOB, *PBACKUPKEY_RECOVERY_BLOB;

/// <summary>
/// Followed by BACKUPKEY_INNER_BLOB_W2K, the user sid, then the input data.
/// The inner blob and the data following it are all encrypted.
/// </summary>
typedef struct _BACKUPKEY_RECOVERY_BLOB_W2K {
    DWORD dwVersion;
    DWORD cbClearData; // Byte count of input data
    DWORD cbCipherData; // Byte count of cipher data following structure
    GUID guidKey; // Guid identifying the backup key that was used
    BYTE R2[BACKUPKEY_R2_LEN];
} BACKUPKEY_RECOVERY_BLOB_W2K, *PBACKUPKEY_RECOVERY_BLOB_W2K;

typedef struct _CRED_SIGNATURE {
    DWORD dwVersion;
    GUID CredentialID;
    DWORD cIterations;
    BYTE Salt[SIGNATURE_SALT_SIZE];
    DWORD cbSid;
    DWORD cbSignature;
} CRED_SIGNATURE, *PCRED_SIGNATURE;

typedef struct _CREDENTIAL_HISTORY_HEADER {
    DWORD dwVersion;
    GUID CredentialID;
    DWORD dwPreviousCredOffset;
} CREDENTIAL_HISTORY_HEADER, *PCREDENTIAL_HISTORY_HEADER;

typedef struct _CREDENTIAL_HISTORY {
    CREDENTIAL_HISTORY_HEADER Header;
    DWORD dwFlags;
    DWORD KeyGenAlg;
    DWORD cIterationCount; // Pbkdf2 iteration count
    DWORD cbSid; // Used as mixing bytes
    DWORD KeyEncrAlg;
    DWORD cbShaOwf;
    DWORD cbNtOwf;
    BYTE Salt[CREDENTIAL_HISTORY_SALT_SIZE];
} CREDENTIAL_HISTORY, *PCREDENTIAL_HISTORY;

typedef struct _CREDENTIAL_HISTORY_MAP {
    PSID pUserSid;
    WCHAR wszFilePath[MAX_PATH + 1];
    PBYTE pMapping;
    DWORD cbMapping;
} CREDENTIAL_HISTORY_MAP, *PCREDENTIAL_HISTORY_MAP;

/// <summary>
/// The structure of CREDENTIAL_HISTORY_MAP from after NT 5.0
/// at least NT 5.2. At some point the structure changed to
/// its current form which removes several members.
/// 
/// It is assumed that this structure is correct for Vista
/// and prior because that would align with the changes that
/// occured with BACKUPKEY_KEY_BLOB.
/// </summary>
typedef struct _CREDENTIAL_HISTORY_MAP_VISTA {
    PSID pUserSid;
    WCHAR wszFilePath[MAX_PATH + 1];
    HANDLE hHistoryFile;
    HANDLE hMapping;
    DWORD dwMapSize;
    PBYTE pMapping;
    struct _CREDENTIAL_HISTORY_MAP_VISTA* pNext;
} CREDENTIAL_HISTORY_MAP_VISTA, *PCREDENTIAL_HISTORY_MAP_VISTA;

typedef struct _CREDENTIAL_KEY {
    DWORD SerializedSize;
    DWORD KeyType;
    DWORD KeyOffset;
    DWORD KeySize;
    GUID KeyId;
} CREDENTIAL_KEY, *PCREDENTIAL_KEY;

typedef struct _DP_KEK {
    GUID guidKeyId;
    DWORD dwKeyType;
    BYTE rgbShaOWF[A_SHA_DIGEST_LEN];
    BYTE rgbNTOWF[20]; // 20 - NT OWF hash length
} DP_KEK, *PDP_KEK;

typedef struct _LOCAL_BACKUP_DATA {
    DWORD dwVersion; // MASTERKEY_BLOB_LOCALKEY_BACKUP structure version
    GUID CredentialID; // CredentialID used to protect the master key
} LOCAL_BACKUP_DATA, *PLOCAL_BACKUP_DATA, *LPLOCAL_BACKUP_DATA;

typedef struct _MASTERKEY_BLOB {
    DWORD dwVersion;
    BYTE R2[MASTERKEY_R2_LEN]; // Random data used to derive symetric key via HMAC
    DWORD IterationCount; // Pkcs5 iteration count
    DWORD KEYGENAlg; // Pkcs5 key generation algorithm, in capi ALG_ID form
    DWORD EncryptionAlg; // Encryption algorithm, in capi ALG_ID form
} MASTERKEY_BLOB, *PMASTERKEY_BLOB;

typedef struct _MASTERKEY_BLOB_W2K {
    DWORD dwVersion;
    BYTE R2[MASTERKEY_R2_LEN_W2K]; // Random data used to derive symetric key via HMAC
} MASTERKEY_BLOB_W2K, *PMASTERKEY_BLOB_W2K;

typedef struct _MASTERKEY_CACHE_ENTRY {
    LIST_ENTRY Next;
    LUID LogonId;
    GUID guidMasterKey;
    FILETIME ftLastAccess;
    DWORD cbMasterKey;
    BYTE pbMasterKey[64];
    LPWSTR szUserStorageArea;
} MASTERKEY_CACHE_ENTRY, *PMASTERKEY_CACHE_ENTRY;

/// <summary>
/// The structure of MASTERKEY_CACHE_ENTRY from after NT 5.0
/// at least NT 5.2. At some point the structure changed to
/// its current form which adds the szUserStorageArea member.
///
/// It is assumed that this structure is correct for Vista
/// and prior because that would align with the changes that
/// occured with BACKUPKEY_KEY_BLOB.
/// </summary>
typedef struct _MASTERKEY_CACHE_ENTRY_VISTA {
    LIST_ENTRY Next;
    LUID LogonId;
    GUID guidMasterKey;
    FILETIME ftLastAccess;
    DWORD cbMasterKey;
    BYTE pbMasterKey[64];
} MASTERKEY_CACHE_ENTRY_VISTA, *PMASTERKEY_CACHE_ENTRY_VISTA;

typedef struct _MASTERKEY_INNER_BLOB {
    BYTE R3[MASTERKEY_R3_LEN];
} MASTERKEY_INNER_BLOB, *PMASTERKEY_INNER_BLOB;

/// <summary>
/// The structure of MASTERKEY_INNER_BLOB from after NT 5.0
/// at least NT 5.2. At some point the structure changed to
/// its current form which removes the MAC and Padding member.
/// 
/// It is assumed that this structure is correct for Vista
/// and prior because that would align with the changes that
/// occured with BACKUPKEY_KEY_BLOB. That also aligns with
/// Vista being the last Windows version to use 3DES as the
/// default master key encryption algorithm.
/// </summary>
typedef struct _MASTERKEY_INNER_BLOB_VISTA {
    BYTE R3[MASTERKEY_R3_LEN]; // Random data used to derive MAC key
    BYTE MAC[A_SHA_DIGEST_LEN]; // MAC(R3, pbMasterKey)
    DWORD Padding; // Padding to make structure divisable by 3DES_BLOCKLEN
} MASTERKEY_INNER_BLOB_VISTA, *PMASTERKEY_INNER_BLOB_VISTA;

typedef struct _MASTERKEY_INNER_BLOB_W2K {
    BYTE R3[MASTERKEY_R3_LEN_W2K]; // Random data used to derive MAC key
    BYTE MAC[A_SHA_DIGEST_LEN]; // HMAC(R3, pbMasterKey)
} MASTERKEY_INNER_BLOB_W2K, *PMASTERKEY_INNER_BLOB_W2K;

typedef struct _MASTERKEY_PREFERRED_INFO {
    GUID guidPreferredKey;
    FILETIME ftPreferredKeyExpires;
} MASTERKEY_PREFERRED_INFO, *PMASTERKEY_PREFERRED_INFO;

/// <summary>
/// Defines all the data that may be associated with a single master key.
/// </summary>
typedef struct _MASTERKEY_STORED {
    DWORD dwVersion;
    BOOL fModified; // Have contents been modified? If so, a persist operation should be done.
    LPWSTR szFilePath; // Path (not including filename) to the file for a persist operation
    WCHAR wszguidMasterKey[40]; // Filename (GUID based). 40 - max count of guid characters
    DWORD dwPolicy; // Policy bits for this key
    DWORD cbMK; // Byte count of MK. May be zero if MK is not present
    PBYTE pbMK; // MK data. May be NULL if not present
    DWORD cbLK; // Byte count of LK. May be zero if MK is not present
    PBYTE pbLK; // LK data. May be NULL if not present
    DWORD cbBK; // Byte count of backup local key (BK). May be zero if BK is not present
    PBYTE pbBK; // BK data. May be NULL if not present
    DWORD cbBBK; // Byte count of backup dc key (BBK). May be zero if BBK is not present
    PBYTE pbBBK; // BBK data. May be NULL if not present
} MASTERKEY_STORED, *PMASTERKEY_STORED;

/// <summary>
/// The on-disk version of MASTERKEY_STORED. Allows for storage
/// on 32 bit hosts and 64 bit hosts. The difference with this
/// and MASTERKEY_STORED is that pointers are swapped for 32 bit
/// offsets.
/// </summary>
typedef struct _MASTERKEY_STORED_ON_DISK {
    DWORD dwVersion;
    BOOL fModified;
    DWORD szFilePath; // Invalid on disk
    WCHAR wszguidMasterKey[40];
    DWORD dwPolicy;
    DWORD cbMK;
    DWORD pbMK; // Invalid on disk
    DWORD cbLK;
    DWORD pbLK; // Invalid on disk
    DWORD cbBK;
    DWORD pbBK; // Invalid on disk
    DWORD cbBBK;
    DWORD pbBBK; // Invalid on disk
} MASTERKEY_STORED_ON_DISK, *PMASTERKEY_STORED_ON_DISK;

/// <summary>
/// Deferred backup structure.
/// </summary>
typedef struct _QUEUED_BACKUP {
    DWORD cbSize;
    MASTERKEY_STORED hMasterKey;
    HANDLE hToken; // Client access token
    PBYTE pbLocalKey;
    DWORD cbLocalKey;
    PBYTE pbMasterKey;
    DWORD cbMasterKey;
    HANDLE hEventThread; // Signals that the thread finished processing
    HANDLE hEventSuccess; // Signall a successful backup completed
} QUEUED_BACKUP, *PQUEUED_BACKUP, *LPQUEUED_BACKUP;

/// <summary>
/// Deferred key sync structure.
/// </summary>
typedef struct _QUEUED_SYNC {
    DWORD cbSize;
    PVOID pvContext; // Duplicated server context
} QUEUED_SYNC, *PQUEUED_SYNC, *LPQUEUED_SYNC;

typedef struct _SYSTEM_CREDENTIALS {
    DWORD dwVersion;
    BYTE rgbSystemCredMachine[20];
    BYTE rgbSystemCredUser[20];
} SYSTEM_CREDENTIALS, *PSYSTEM_CREDENTIALS;

// Defines the outer and inner wrapper of a security blob
typedef struct _sec_blob {
    DWORD dwOuterVersion;
    GUID guidProvider;
    DWORD dwVersion;
    GUID guidMK;
    DWORD dwPromptFlags;
    DWORD cbDataDescr;
    WCHAR szDataDescr[ANYSIZE_ARRAY];
} sec_blob, *psec_blob, DPAPICryptUnprotectDataEx, *PDPAPICryptUnprotectDataEx;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Dpapi {
    // Enumerations
    using CREDENTIAL_KEY_SOURCE_TYPE = ::LSA_CREDENTIAL_KEY_SOURCE_TYPE;
    using KEY_TYPE = _DPAPI_KEY_TYPE;

    using BACKUP_PUBLIC_KEY = _BACKUP_PUBLIC_KEY;
    using BACKUPKEY_INNER_BLOB = _BACKUPKEY_INNER_BLOB;
    using MASTERKEY_INNER_BLOB_VISTA = _MASTERKEY_INNER_BLOB_VISTA;
    using BACKUPKEY_INNER_BLOB_W2K = _BACKUPKEY_INNER_BLOB_W2K;
    using BACKUPKEY_KEY_BLOB = _BACKUPKEY_KEY_BLOB;
    using BACKUPKEY_KEY_BLOB_VISTA = _BACKUPKEY_KEY_BLOB_VISTA;
    using BACKUPKEY_RECOVERY_BLOB = _BACKUPKEY_RECOVERY_BLOB;
    using BACKUPKEY_RECOVERY_BLOB_W2K = _BACKUPKEY_RECOVERY_BLOB_W2K;
    using CRED_SIGNATURE = _CRED_SIGNATURE;
    using CREDENTIAL_HISTORY = _CREDENTIAL_HISTORY;
    using CREDENTIAL_HISTORY_HEADER = _CREDENTIAL_HISTORY_HEADER;
    using CREDENTIAL_HISTORY_MAP = _CREDENTIAL_HISTORY_MAP;
    using CREDENTIAL_HISTORY_MAP_VISTA = _CREDENTIAL_HISTORY_MAP_VISTA;
    using CREDENTIAL_KEY = _CREDENTIAL_KEY;
    using DP_KEK = _DP_KEK;
    using LOCAL_BACKUP_DATA = _LOCAL_BACKUP_DATA;
    using MASTERKEY_BLOB = _MASTERKEY_BLOB;
    using MASTERKEY_BLOB_W2K = _MASTERKEY_BLOB_W2K;
    using MASTERKEY_CACHE_ENTRY = _MASTERKEY_CACHE_ENTRY;
    using MASTERKEY_CACHE_ENTRY_VISTA = _MASTERKEY_CACHE_ENTRY_VISTA;
    using MASTERKEY_INNER_BLOB = _MASTERKEY_INNER_BLOB;
    using MASTERKEY_INNER_BLOB_W2K = _MASTERKEY_INNER_BLOB_W2K;
    using MASTERKEY_PREFERRED_INFO = _MASTERKEY_PREFERRED_INFO;
    using MASTERKEY_STORED = _MASTERKEY_STORED;
    using MASTERKEY_STORED_ON_DISK = _MASTERKEY_STORED_ON_DISK;
    using QUEUED_BACKUP = _QUEUED_BACKUP;
    using QUEUED_SYNC = _QUEUED_SYNC;
    using SYSTEM_CREDENTIALS = _SYSTEM_CREDENTIALS;
    using sec_blob = _sec_blob;
}
#endif