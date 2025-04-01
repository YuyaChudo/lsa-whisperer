// Copyright (C) 2024 Evan McBroom
//
// Additional DPAPI-NG types my be found in efs.h
// and fve.h and they will have the suffix _DPAPI_NG.
//
#pragma once
#include <phnt_windows.h>

#include <ntlsa.h>
#include <wincrypt.h>

#define EFS_AES_IVH 0x1989adbe44918961
#define EFS_AES_IVL 0x5816657be9161312
#define EFS_IV      0x169119629891ad13

#define EFS_MAX_LENGTH       256 * 1024
#define EFS_SIGNATURE_LENGTH 4

#define szOID_EFS_CRYPTO   "1.3.6.1.4.1.311.10.3.4"
#define szOID_EFS_RECOVERY "1.3.6.1.4.1.311.10.3.4.1"

#ifdef __cplusplus
extern "C" {
#endif

enum _EFS_ACTION_STATUS;
enum _EFS_FSCTL_FORMAT;
enum _EFSP_OPERATION;
enum EFS_CERT_EXTENDED_USAGE;
enum EFS_PUBLIC_KEY_TYPE;
enum EFS_SUITE_B_POLICY;

struct _EFS_CERT_HASH_DATA;
struct _EFS_COMPATIBILITY_INFO;
struct _EFS_CRYPT_KEY;
struct _EFS_CRYPT_PROVIDER;
struct _EFS_DATA_STREAM_HEADER;
struct _EFS_DECRYPTION_STATUS_INFO;
struct _EFS_DESCRIPTOR_CACHE_ENTRY;
struct _EFS_DESCRIPTOR_DATA_HEADER;
struct _EFS_ECC_SECONDARY_KEY;
struct _EFS_ENCRYPTION_STATUS_INFO;
struct _EFS_FILE_IV;
struct _EFS_FILE_KEY;
struct _EFS_FSCTL_BUFFER_INFO;
struct _EFS_FSCTL_INPUT;
struct _EFS_GP_NOTIFICATION_CONTEXT;
struct _EFS_HASH_BLOB;
struct _EFS_HEADER_COMPARE_OFFSETS;
struct _EFS_KEY_INFO;
struct _EFS_KEY;
struct _EFS_LICENSE_POINTER;
struct _EFS_LSA_NOTIFICATION_CONTEXT;
struct _EFS_MKHISTORY_CONFIGURATION;
struct _EFS_MKHISTORY_ECC_REG_DATA;
struct _EFS_MKHISTORY_ELEMENT;
struct _EFS_MKHISTORY_LIST;
struct _EFS_MKHISTORY_REG_DATA_HEADER;
struct _EFS_MKHISTORY_RSA_REG_DATA;
struct _EFS_PFILE_HEADER;
struct _EFS_PFILE_PREAMBLE;
struct _EFS_PFILE_STREAM;
struct _EFS_PIN_BLOB;
struct _EFS_POL_CALLBACK_DATA;
struct _EFS_POL_SETTINGS;
struct _EFS_PUBLIC_KEY_INFO;
struct _EFS_RPC_BLOB;
struct _EFS_RSA_ENCRYPTION_CONTEXT;
struct _EFS_SID_INFORMATION;
struct _EFS_STREAM_DATA;
struct _EFS_STREAM_INFO;
struct _EFS_STREAM_SIZE;
struct _EFS_USER_INFO;
struct _EFS_USER_KEY_INFO;
struct _EFS_USER_NAME_INFO_DESCRIPTOR;
struct _EFS_USER_PROFILE_DESCRIPTOR;
struct _EFS_VERSION_INFO;

struct _EFSEXP_FILE_HEADER;
struct _EFSEXP_STREAM_HEADER;
struct _EFSEXP_DATA_HEADER;

struct _EFSL_DATA_STREAM;
struct _EFSL_PERSIST_KEY;

struct _EFSX_DATA_STREAM;
struct _EFSX_DATUM_BLOB;
struct _EFSX_DATUM_DESCRIPTOR;
struct _EFSX_DATUM_DPAPI_NG_DATA;
struct _EFSX_DATUM_FEK_INFO;
struct _EFSX_DATUM_KEY_AGMT_DATA;
struct _EFSX_DATUM_KEY_PROTECTOR;
struct _EFSX_DATUM_PFILE_PROTECTOR_LIST;
struct _EFSX_DATUM_PROTECTOR_INFO;
struct _EFSX_DATUM_TYPE_PROPERTIES;
struct _EFSX_DATUM;
struct _EFSX_FILE_KEY;
struct _EFSX_PROTECTOR_LIST;

// Miscellaneous
struct _ENCRYPTED_KEY;
struct _ENCRYPTED_KEYS;
struct _POLICY_EFS_RECOVERY;
struct _USER_CACHE;
struct _USER_CACHE_KEY;

// clang-format off
#if _WIN32_WINNT <= _WIN32_WINNT_WS03

#define DES_KEYSIZE      8
#define MD5_HASH_SIZE    16
#define SESSION_KEY_SIZE 8
// clang-format on

struct _EFS_INIT_DATAEXG;
struct _EFS_KEY_SALT;
struct _EFS_STREAM;
struct _GENERAL_FS_DATA;
struct _KEY_INTEGRITY_INFO;

typedef struct _EFS_DATA_STREAM_HEADER {
    ULONG Length;
    ULONG State;
    ULONG EfsVersion;
    ULONG CryptoApiVersion;
    GUID EfsId;
    UCHAR EfsHash[MD5_HASH_SIZE];
    UCHAR DrfIntegrity[MD5_HASH_SIZE];
    ULONG DataDecryptionField; // Offset to DDF
    ULONG DataRecoveryField; // Offset to DRF
    ULONG Reserved;
    ULONG Reserved2;
    ULONG Reserved3;
} EFS_DATA_STREAM_HEADER, *PEFS_DATA_STREAM_HEADER;

typedef struct _EFS_INIT_DATAEXG {
    UCHAR Key[SESSION_KEY_SIZE];
    SIZE_T LsaProcessID;
} EFS_INIT_DATAEXG, *PEFS_INIT_DATAEXG;

typedef struct _EFS_KEY {
    ULONG KeyLength;
    ULONG Entropy;
    ALG_ID Algorithm;
    ULONG Pad;
    // UCHAR KeyData[ANYSIZE_ARRAY];
} EFS_KEY, *EFS_KEY;

typedef struct _EFS_KEY_SALT {
    ULONG Length;
    ULONG SaltType;
    // UCHAR data[]
} EFS_KEY_SALT, *PEFS_KEY_SALT;

typedef struct _EFS_STREAM {
    ULONG Length;
    ULONG Status;
    UCHAR Private[ANYSIZE_ARRAY];
} EFS_STREAM, *PEFS_STREAM;

typedef struct _GENERAL_FS_DATA {
    UCHAR Sk1[DES_KEYSIZE];
    ULONG Hdl1;
    ULONG Hdl2;
    UCHAR Sk2[DES_KEYSIZE];
    ULONG Hdl3;
    ULONG Hdl4;
    UCHAR EfsData[ANYSIZE_ARRAY];
} GENERAL_FS_DATA, *PGENERAL_FS_DATA;

typedef struct _KEY_INTEGRITY_INFO {
    ULONG Length;
    ALG_ID HashAlgorithm;
    ULONG HashDataLength;
    // UCHAR Integrity Info[]
} KEY_INTEGRITY_INFO, *PKEY_INTEGRITY_INFO;

#else

typedef struct _EFS_DATA_STREAM_HEADER {
    ULONG Length;
    ULONG State;
    ULONG EfsVersion;
    USHORT PaddingOffset;
    USHORT Reserved;
    GUID EfsId;
} EFS_DATA_STREAM_HEADER, *PEFS_DATA_STREAM_HEADER;

typedef struct _EFS_FILE_IV {
    ULONGLONG FileIVLow;
    ULONGLONG FileIVHigh;
} EFS_FILE_IV, *PEFS_FILE_IV;

typedef struct _EFS_KEY {
    ULONG KeyLength;
    ULONG Algorithm;
    ULONG IVGenerationMode;
    EFS_FILE_IV FileIV;
    // UCHAR KeyData[ANYSIZE_ARRAY];
} EFS_KEY, *PEFS_KEY;

#endif

typedef enum _EFS_ACTION_STATUS : LONG {
    BeginEncryptDir = 0,
    BeginDecryptDir = 1,
    BeginEncryptFile = 2,
    BeginDecryptFile = 3,
    EncryptTmpFileWritten = 4,
    DecryptTmpFileWritten = 5,
    EncryptionDone = 6,
    DecryptionDone = 7,
    EncryptionBackout = 8,
    EncryptionMessup = 9,
    EncryptionSrcDone = 10,
} EFS_ACTION_STATUS,
                                  *PEFS_ACTION_STATUS;

typedef enum _EFS_FSCTL_FORMAT : LONG {
    EfsFormatIllegal = 0,
    EfsFormatPlain = 1,
    EfsFormatFekAndEfs = 2,
    EfsFormatEfs = 3,
} EFS_FSCTL_FORMAT,
                                 *PEFS_FSCTL_FORMAT;

typedef enum _EFSP_OPERATION : LONG {
    EfspOperationInvalid = -1,
    EfspOperationEncrypting = 0,
    EfspOperationDecrypting = 1,
    EfspOperationEncryptRecovering = 2,
    EfspOperationDecryptRecovering = 3,
} EFSP_OPERATION,
                               *PEFSP_OPERATION;

typedef enum EFS_CERT_EXTENDED_USAGE : LONG {
    EfsEkuNone = 0,
    EfsEkuUserEfs = 1,
    EfsEkuAny = 2,
    EfsEkuNotValid = 3,
} EFS_CERT_EXTENDED_USAGE,
                                       *PEFS_CERT_EXTENDED_USAGE;

typedef enum EFS_PUBLIC_KEY_TYPE : LONG {
    eEfsKeyTypeUnsupported = 0,
    eEfsKeyTypeRsa = 1,
    eEfsKeyTypeEcdh = 2,
} EFS_PUBLIC_KEY_TYPE,
                                   *PEFS_PUBLIC_KEY_TYPE;

typedef enum EFS_SUITE_B_POLICY : LONG {
    eEfsSuiteBAllowed = 1,
    eEfsSuiteBDisabled = 2,
    eEfsSuiteBRequired = 3,
} EFS_SUITE_B_POLICY,
                                  *PEFS_SUITE_B_POLICY;

typedef struct _EFS_CERT_HASH_DATA {
    ULONG pbHash;
    ULONG cbHash;
    ULONG ContainerName;
    ULONG ProviderName;
    ULONG lpDisplayInformation;
} EFS_CERT_HASH_DATA, *PEFS_CERT_HASH_DATA;

typedef struct _EFS_COMPATIBILITY_INFO {
    ULONG EfsVersion;
} EFS_COMPATIBILITY_INFO, *PEFS_COMPATIBILITY_INFO;

typedef struct _EFS_CRYPT_KEY {
    DWORD IsCngKey;
    union {
        struct
        {
            ULONG KeySpec;
            LPVOID Provider;
            LPVOID Key;
        } CapiKey;
        LPVOID CngKey;
    };
} EFS_CRYPT_KEY, *PEFS_CRYPT_KEY;

typedef struct _EFS_CRYPT_PROVIDER {
    DWORD IsCngProvider;
    union {
        LPVOID CapiProvider;
        LPVOID CngProvider;
    };
} EFS_CRYPT_PROVIDER, *PEFS_CRYPT_PROVIDER;

typedef struct _EFS_DECRYPTION_STATUS_INFO {
    DWORD dwDecryptionError;
    DWORD dwHashOffset;
    ULONG cbHash;
} EFS_DECRYPTION_STATUS_INFO, *PEFS_DECRYPTION_STATUS_INFO;

typedef struct _EFS_DESCRIPTOR_DATA_HEADER {
    ULONG Size;
    ULONG Type;
    // clang-format off
    LONG (* FreeCallback)(PVOID);
    // clang-format on
} EFS_DESCRIPTOR_DATA_HEADER, *PEFS_DESCRIPTOR_DATA_HEADER;

typedef struct _EFS_DESCRIPTOR_CACHE_ENTRY {
    LPWSTR Descriptor;
    PEFS_DESCRIPTOR_DATA_HEADER EntryData;
    LIST_ENTRY List;
} EFS_DESCRIPTOR_CACHE_ENTRY, *PEFS_DESCRIPTOR_CACHE_ENTRY;

typedef struct _EFS_ENCRYPTION_STATUS_INFO {
    BOOL bHasCurrentKey;
    DWORD dwEncryptionError;
} EFS_ENCRYPTION_STATUS_INFO, *PEFS_ENCRYPTION_STATUS_INFO;

/// <summary>
/// The structure of EFS_FILE_KEY is currently unknown.
/// </summary>
typedef struct _EFS_FILE_KEY {
} EFS_FILE_KEY, *PEFS_FILE_KEY;

typedef struct _EFS_KEY_INFO {
    DWORD dwVersion;
    ULONG Entropy;
    ULONG Algorithm;
    ULONG KeyLength;
} EFS_KEY_INFO, *PEFS_KEY_INFO;

typedef struct _EFS_FSCTL_BUFFER_INFO {
    EFS_FSCTL_FORMAT Type;
    union {
        struct
        {
            PEFS_KEY Fek;
            PEFS_DATA_STREAM_HEADER pEfsStream;
        } FekEfs;
        PEFS_DATA_STREAM_HEADER pEfsStream;
    };
} EFS_FSCTL_BUFFER_INFO, *PEFS_FSCTL_BUFFER_INFO;

typedef struct _EFS_FSCTL_INPUT {
    ULONG PlainSubCode;
    ULONG EfsFsCode;
    ULONG CipherSubCode;
    ULONG EfsFsDataLength;
    UCHAR EfsFsData[ANYSIZE_ARRAY];
} EFS_FSCTL_INPUT, *PEFS_FSCTL_INPUT;

typedef struct _EFS_POL_CALLBACK_DATA {
    PBYTE EfsDisable;
    PULONG EfsOptions;
    LPWSTR* TemplateName;
    LPWSTR* SuiteBAlgorithm;
    PEFS_SUITE_B_POLICY SuiteBPolicy;
    PULONG RsaKeyLength;
    PULONG CacheTimeout;
} EFS_POL_CALLBACK_DATA, *PEFS_POL_CALLBACK_DATA;

typedef struct _EFS_GP_NOTIFICATION_CONTEXT {
    HANDLE hGPNotification;
    HANDLE hNewGPNotification;
    // clang-format off
    VOID (* Callback)(PVOID, UCHAR);
    // clang-format on
    EFS_POL_CALLBACK_DATA Data;
} EFS_GP_NOTIFICATION_CONTEXT, *PEFS_GP_NOTIFICATION_CONTEXT;

typedef struct _EFS_HASH_BLOB {
    ULONG cbData;
    PBYTE pbData;
} EFS_HASH_BLOB, *PEFS_HASH_BLOB;

typedef struct _EFS_HEADER_COMPARE_OFFSETS {
    ULONG StartOffset;
    ULONG EndOffset;
} EFS_HEADER_COMPARE_OFFSETS, *PEFS_HEADER_COMPARE_OFFSETS;

typedef struct _EFS_LICENSE_POINTER {
    PBYTE License;
    ULONG LicenseSize;
} EFS_LICENSE_POINTER, *PEFS_LICENSE_POINTER;

typedef struct _EFS_LSA_NOTIFICATION_CONTEXT {
    HANDLE hEfsNotification;
    HANDLE hNewEfsNotification;
    // clang-format off
    VOID (* Callback)(PVOID, UCHAR);
    // clang-format on
    POLICY_NOTIFICATION_INFORMATION_CLASS PolicyInfo;
} EFS_LSA_NOTIFICATION_CONTEXT, *PEFS_LSA_NOTIFICATION_CONTEXT;

typedef struct _EFS_ECC_SECONDARY_KEY {
    ULONG cbUserPublicKey;
    PBYTE pbUserPublicKey;
    ULONG cbSecondaryKey;
    PBYTE pbSecondaryKey;
} EFS_ECC_SECONDARY_KEY, *PEFS_ECC_SECONDARY_KEY;

typedef struct _EFS_MKHISTORY_CONFIGURATION {
    DWORD dwKeyType;
    PBYTE pbHash;
    ULONG cbHash;
    PEFS_ECC_SECONDARY_KEY pSecondaryKeyInfo;
} EFS_MKHISTORY_CONFIGURATION, *PEFS_MKHISTORY_CONFIGURATION;

typedef struct _EFS_MKHISTORY_REG_DATA_HEADER {
    ULONG cbSize;
} EFS_MKHISTORY_REG_DATA_HEADER, *PEFS_MKHISTORY_REG_DATA_HEADER;

typedef struct _EFS_MKHISTORY_ECC_REG_DATA {
    EFS_MKHISTORY_REG_DATA_HEADER h;
    ULONG cbUserKey;
    ULONG cbSecondaryKey;
    ULONG cbCachedKey;
} EFS_MKHISTORY_ECC_REG_DATA, *PEFS_MKHISTORY_ECC_REG_DATA;

typedef struct _EFS_MKHISTORY_ELEMENT {
    DWORD dwKeyType;
    ULONG cbMasterKey;
    PBYTE pbMasterKey;
    LPWSTR wszHash;
    PEFS_ECC_SECONDARY_KEY pSecondaryKeyInfo;
    LIST_ENTRY Chain;
} EFS_MKHISTORY_ELEMENT, *PEFS_MKHISTORY_ELEMENT;

typedef struct _EFS_MKHISTORY_LIST {
    LIST_ENTRY Head;
} EFS_MKHISTORY_LIST, *PEFS_MKHISTORY_LIST;

typedef struct _EFS_MKHISTORY_RSA_REG_DATA {
    EFS_MKHISTORY_REG_DATA_HEADER h;
    ULONG cbMasterKey;
    PBYTE pbMasterKey;
} EFS_MKHISTORY_RSA_REG_DATA, *PEFS_MKHISTORY_RSA_REG_DATA;

typedef struct _EFS_PFILE_HEADER {
    ULONG HeaderLength;
    ULONG FileExtOffset;
    ULONG FileExtLength;
    ULONG LicenseOffset;
    ULONG LicenseLength;
    ULONG EncryptedDataOffset;
    ULONGLONG PlaintextSize;
    ULONG MetadataOffset;
    ULONG MetadataLength;
} EFS_PFILE_HEADER, *PEFS_PFILE_HEADER;

typedef struct _EFS_PFILE_PREAMBLE {
    BYTE MagicValue[6];
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG ClearTextRedirectLength;
} EFS_PFILE_PREAMBLE, *PEFS_PFILE_PREAMBLE;

typedef struct _EFS_PFILE_STREAM {
    EFS_PFILE_PREAMBLE PFilePreamble;
} EFS_PFILE_STREAM, *PEFS_PFILE_STREAM;

typedef struct _EFS_PIN_BLOB {
    ULONG cbPadding;
    ULONG cbData;
    PBYTE pbData;
} EFS_PIN_BLOB, *PEFS_PIN_BLOB;

typedef struct _EFS_POL_SETTINGS {
    ULONG EfsConfig;
    ULONG EfsOptions;
    ULONG CacheTimeout;
    ULONG RsaKeyLength;
    PWCHAR TemplateName;
    PWCHAR SuiteBAlgorithm;
} EFS_POL_SETTINGS, *PEFS_POL_SETTINGS;

typedef struct _EFS_PUBLIC_KEY_INFO {
    ULONG Length;
    ULONG PossibleKeyOwner;
    ULONG KeySourceTag;
    union {
        struct
        {
            ULONG ContainerName;
            ULONG ProviderName;
            ULONG PublicKeyBlob;
            ULONG PublicKeyBlobLength;
        } ContainerInfo;
        struct
        {
            ULONG CertificateLength;
            ULONG Certificate;
        } CertificateInfo;
        struct
        {
            ULONG ThumbprintLength;
            ULONG CertHashData;
        } CertificateThumbprint;
    };
} EFS_PUBLIC_KEY_INFO, *PEFS_PUBLIC_KEY_INFO;

typedef struct _EFS_RPC_BLOB {
    ULONG cbData;
    PBYTE pbData;
} EFS_RPC_BLOB, *PEFS_RPC_BLOB;

typedef struct _EFS_RSA_ENCRYPTION_CONTEXT {
    DWORD dwBlockLen;
    DWORD dwBlockSize;
    ULONG cbSource;
    PBYTE pbSource;
    PBYTE pbSourceCurrent;
    ULONG cbDest;
    PBYTE pbDest;
    PBYTE pbDestCurrent;
    ULONG cbWorkBuffer;
    PBYTE pbWorkBuffer;
} EFS_RSA_ENCRYPTION_CONTEXT, *PEFS_RSA_ENCRYPTION_CONTEXT;

typedef struct _EFS_SID_INFORMATION {
    PSID pAnonymousSid;
    PSID pInteractiveSid;
    UNICODE_STRING AnonymousSidName;
    UNICODE_STRING AnonymousSidDomainName;
} EFS_SID_INFORMATION, *PEFS_SID_INFORMATION;

typedef struct _EFS_STREAM_SIZE {
    ULONG StreamFlag;
    LARGE_INTEGER EOFSize;
    LARGE_INTEGER AllocSize;
} EFS_STREAM_SIZE, *PEFS_STREAM_SIZE;

typedef struct _EFS_STREAM_DATA {
    ULONG StreamCount;
    PUNICODE_STRING StreamNames;
    PEFS_STREAM_SIZE StreamSizes;
    PHANDLE StreamHandles;
} EFS_STREAM_DATA, *PEFS_STREAM_DATA;

typedef struct _EFS_STREAM_INFO {
    const LPWSTR wszFileName;
    HANDLE hFile;
    DWORD dwFileAttributes;
    PEFS_DATA_STREAM_HEADER pEfsStream;
} EFS_STREAM_INFO, *PEFS_STREAM_INFO;

typedef struct _USER_CACHE {
    ULONG SessionId;
    PVOID UserId;
    ULONG cbDecryptionStatusInfo;
    PEFS_DECRYPTION_STATUS_INFO pDecryptionStatusInfo;
    RTL_SRWLOCK srwDecryptionStatusLock;
    RTL_SRWLOCK srwMKHistoryLock;
    UCHAR bMasterKeyHistoryLoaded;
    UCHAR bFreeWhenNoMoreReferences;
    UCHAR bCheckFreedKeysWhenNoMoreReferences;
    UCHAR bStopTakingReferences;
    ULONG cKeys;
    LONG UseRefCount;
    LIST_ENTRY KeyListHead;
    LIST_ENTRY CacheChain;
    LIST_ENTRY DescriptorListHead;
} USER_CACHE, *PUSER_CACHE;

typedef struct _EFS_USER_INFO {
    LPWSTR lpUserName;
    LPWSTR lpDomainName;
    LPWSTR lpProfilePath;
    LPWSTR lpUserSid;
    LPWSTR lpKeyPath;
    PTOKEN_USER pTokenUser;
    PUSER_CACHE pUserCache;
    HANDLE hThreadToken;
    HANDLE hProfile;
    ULONG SessionId;
    HANDLE hMyStore;
    LONG InterActiveUser;
    UCHAR bDomainAccount;
    UCHAR bIsSystem;
    UCHAR bReceivedSessionNotification;
    LPVOID pUserProfileDesc;
} EFS_USER_INFO, *PEFS_USER_INFO;

typedef struct _EFS_USER_KEY_INFO {
    LONG CertValidated;
    ULONG cbHash;
    PBYTE pbHash;
    LPWSTR ContainerName;
    LPWSTR ProviderName;
    LPWSTR DisplayInformation;
    DWORD dwCapabilities;
    UCHAR bIsCurrentKey;
    UCHAR bInCache;
    DWORD dwKeyType;
    union {
        struct
        {
            PEFS_CRYPT_KEY UserKey;
            struct
            {
                RTL_SRWLOCK srwLock;
                DWORD dwRefCount;
                HANDLE hKey;
                ULONG cbBlockLen;
                ULONG cbMasterKey;
                PBYTE pbMasterKey;
            } MasterKeyInfo;
            LPVOID PublicKey;
        } KeyInfo;
        struct
        {
            PEFS_CRYPT_KEY UserKey;
            struct
            {
                RTL_SRWLOCK srwLock;
                DWORD dwRefCount;
                LPVOID Kek;
                PBYTE KekObject;
                ULONG KekObjectSize;
                EFS_ECC_SECONDARY_KEY SecondaryKeyInfo;
            } CachedKeyAgmtInfo;
            void* PublicKey;
        } KeyInfoX;
        LPWSTR DpapiNgDesc;
        struct
        {
            ULONG HeaderType;
            ULONG ExternalKeyInfoSize;
            PBYTE ExternalKeyInfo;
        } ExternalManagedKey;
    };
} EFS_USER_KEY_INFO, *PEFS_USER_KEY_INFO;

typedef struct _EFS_USER_NAME_INFO_DESCRIPTOR {
    EFS_DESCRIPTOR_DATA_HEADER h;
    LPWSTR lpUserName;
    LPWSTR lpDomainName;
    LPWSTR lpKeyPath;
} EFS_USER_NAME_INFO_DESCRIPTOR, *PEFS_USER_NAME_INFO_DESCRIPTOR;

typedef struct _EFS_USER_PROFILE_DESCRIPTOR {
    EFS_DESCRIPTOR_DATA_HEADER h;
    LONG RefCount;
    HANDLE hThreadToken;
    HANDLE hProfile;
} EFS_USER_PROFILE_DESCRIPTOR, *PEFS_USER_PROFILE_DESCRIPTOR;

typedef struct _EFS_VERSION_INFO {
    ULONG EfsVersion;
    ULONG SubVersion;
} EFS_VERSION_INFO, *PEFS_VERSION_INFO;

typedef struct _EFSEXP_FILE_HEADER {
    ULONG VersionID;
    WCHAR FileSignature[EFS_SIGNATURE_LENGTH];
    ULONG Reserved[2];
    // _EFS_STREAM_DATA Streams[0];
} EFSEXP_FILE_HEADER, *PEFSEXP_FILE_HEADER;

typedef struct _EFSEXP_STREAM_HEADER {
    ULONG Length;
    WCHAR StreamSignature[EFS_SIGNATURE_LENGTH];
    ULONG Flag;
    ULONG Reserved[2];
    ULONG NameLength;
    // WCHAR StreamName[0];
    // DATA_BLOCK DataBlocks[0];
} EFSEXP_STREAM_HEADER, *PEFSEXP_STREAM_HEADER;

typedef struct _EFSEXP_DATA_HEADER {
    ULONG Length;
    WCHAR DataSignature[EFS_SIGNATURE_LENGTH];
    ULONG Flag;
    // BYTE  DataBlock[Length - 2 * sizeof (ULONG) - 4 * sizeof (WCHAR)];
} EFSEXP_DATA_HEADER, *PEFSEXP_DATA_HEADER;

typedef struct _EFSL_DATA_STREAM {
    EFS_DATA_STREAM_HEADER h;
    UCHAR Unused2[16];
    UCHAR Unused3[16];
    ULONG DataDecryptionField;
    ULONG DataRecoveryField;
    ULONG Reserved;
    ULONG Reserved2;
    ULONG Reserved3;
} EFSL_DATA_STREAM, *PEFSL_DATA_STREAM;

typedef struct _EFSL_PERSIST_KEY {
    ULONG KeyLength;
    ULONG Entropy;
    ULONG Algorithm;
    ULONG Pad;
} EFSL_PERSIST_KEY, *PEFSL_PERSIST_KEY;

typedef struct _EFSX_DATUM {
    USHORT StructureSize;
    USHORT Role;
    USHORT Type;
    USHORT Flags;
} EFSX_DATUM, *PEFSX_DATUM;

typedef struct _EFSX_DATUM_FEK_INFO {
    EFSX_DATUM h;
    ULONG AlgorithmID;
} EFSX_DATUM_FEK_INFO, *PEFSX_DATUM_FEK_INFO;

typedef struct _EFSX_DATA_STREAM {
    EFS_DATA_STREAM_HEADER h;
    ULONG DdfOffset;
    ULONG DrfOffset;
    EFSX_DATUM_FEK_INFO FekInfo;
} EFSX_DATA_STREAM, *PEFSX_DATA_STREAM;

typedef struct _EFSX_DATUM_BLOB {
    EFSX_DATUM h;
    USHORT BlobType;
    USHORT BlobFlags;
    UCHAR BlobData[ANYSIZE_ARRAY];
} EFSX_DATUM_BLOB, *PEFSX_DATUM_BLOB;

typedef struct _EFSX_DATUM_DESCRIPTOR {
    EFSX_DATUM h;
    WCHAR Text[ANYSIZE_ARRAY];
} EFSX_DATUM_DESCRIPTOR, *PEFSX_DATUM_DESCRIPTOR;

typedef struct _EFSX_DATUM_DPAPI_NG_DATA {
    EFSX_DATUM h;
    USHORT DpapiNgFlags;
} EFSX_DATUM_DPAPI_NG_DATA, *PEFSX_DATUM_DPAPI_NG_DATA;

typedef struct _EFSX_DATUM_KEY_AGMT_DATA {
    EFSX_DATUM h;
    USHORT KeyAgmtFlags;
} EFSX_DATUM_KEY_AGMT_DATA, *PEFSX_DATUM_KEY_AGMT_DATA;

typedef struct _EFSX_DATUM_KEY_PROTECTOR {
    EFSX_DATUM h;
    USHORT ProtectorType;
    USHORT ProtectorFlags;
} EFSX_DATUM_KEY_PROTECTOR, *PEFSX_DATUM_KEY_PROTECTOR;

typedef struct _EFSX_DATUM_PFILE_PROTECTOR_LIST {
    EFSX_DATUM h;
    USHORT ProtectorListFlags;
    USHORT ProtectorListCount;
} EFSX_DATUM_PFILE_PROTECTOR_LIST, *PEFSX_DATUM_PFILE_PROTECTOR_LIST;

typedef struct _EFSX_DATUM_PROTECTOR_INFO {
    EFSX_DATUM h;
} EFSX_DATUM_PROTECTOR_INFO, *PEFSX_DATUM_PROTECTOR_INFO;

typedef struct _EFSX_DATUM_TYPE_PROPERTIES {
    USHORT BaseSize;
    UCHAR IsComplex;
} EFSX_DATUM_TYPE_PROPERTIES, *PEFSX_DATUM_TYPE_PROPERTIES;

typedef struct _EFSX_FILE_KEY {
    PVOID Fmk;
    PUCHAR FmkKeyObject;
} EFSX_FILE_KEY, *PEFSX_FILE_KEY;

typedef struct _EFSX_PROTECTOR_LIST {
    ULONG StructureSize;
    USHORT ProtectorsCount;
} EFSX_PROTECTOR_LIST, *PEFSX_PROTECTOR_LIST;

typedef struct _ENCRYPTED_KEY {
    ULONG Length;
    ULONG PublicKeyInfo;
    ULONG EncryptedFEKLength;
    ULONG EncryptedFEK;
#if _WIN32_WINNT <= _WIN32_WINNT_WS03
    ULONG EfsKeySalt;
#else
    ULONG FekFlags;
#endif
} ENCRYPTED_KEY, *PENCRYPTED_KEY;

typedef struct _ENCRYPTED_KEYS {
    ULONG KeyCount;
    ENCRYPTED_KEY EncryptedKey[ANYSIZE_ARRAY];
} ENCRYPTED_KEYS, *PENCRYPTED_KEYS, DDF, *PDDF, DRF, *PDRF;

typedef struct _POLICY_EFS_RECOVERY {
    ULONG InfoLength;
    PBYTE EfsBlob;
} POLICY_EFS_RECOVERY, *PPOLICY_EFS_RECOVERY;

typedef struct _USER_CACHE_KEY {
    PEFS_USER_KEY_INFO pEfsKeyInfo;
    FILETIME CertExpTime;
    LARGE_INTEGER TimeStamp;
    ULONGLONG qwTickCountLastAccess;
    LONG bFreeWhenNoMoreReferences;
    LIST_ENTRY KeyChain;
} USER_CACHE_KEY, *PUSER_CACHE_KEY;

#ifdef __cplusplus
} // Closes extern "C" above
namespace Efs {
    // Enumerations
    using ACTION_STATUS = _EFS_ACTION_STATUS;
    using CERT_EXTENDED_USAGE = EFS_CERT_EXTENDED_USAGE;
    using FSCTL_FORMAT = _EFS_FSCTL_FORMAT;
    using P_OPERATION = _EFSP_OPERATION;
    using PUBLIC_KEY_TYPE = EFS_PUBLIC_KEY_TYPE;
    using SUITE_B_POLICY = EFS_SUITE_B_POLICY;

    using CERT_HASH_DATA = _EFS_CERT_HASH_DATA;
    using COMPATIBILITY_INFO = _EFS_COMPATIBILITY_INFO;
    using CRYPT_KEY = _EFS_CRYPT_KEY;
    using CRYPT_PROVIDER = _EFS_CRYPT_PROVIDER;
    using DATA_STREAM_HEADER = _EFS_DATA_STREAM_HEADER;
    using DECRYPTION_STATUS_INFO = _EFS_DECRYPTION_STATUS_INFO;
    using DESCRIPTOR_CACHE_ENTRY = _EFS_DESCRIPTOR_CACHE_ENTRY;
    using DESCRIPTOR_DATA_HEADER = _EFS_DESCRIPTOR_DATA_HEADER;
    using ECC_SECONDARY_KEY = _EFS_ECC_SECONDARY_KEY;
    using ENCRYPTION_STATUS_INFO = _EFS_ENCRYPTION_STATUS_INFO;
    using FILE_IV = _EFS_FILE_IV;
    using FILE_KEY = _EFS_FILE_KEY;
    using FSCTL_BUFFER_INFO = _EFS_FSCTL_BUFFER_INFO;
    using FSCTL_INPUT = _EFS_FSCTL_INPUT;
    using GP_NOTIFICATION_CONTEXT = _EFS_GP_NOTIFICATION_CONTEXT;
    using HASH_BLOB = _EFS_HASH_BLOB;
    using HEADER_COMPARE_OFFSETS = _EFS_HEADER_COMPARE_OFFSETS;
    using KEY_INFO = _EFS_KEY_INFO;
    using KEY = _EFS_KEY;
    using LICENSE_POINTER = _EFS_LICENSE_POINTER;
    using LSA_NOTIFICATION_CONTEXT = _EFS_LSA_NOTIFICATION_CONTEXT;
    using MKHISTORY_CONFIGURATION = _EFS_MKHISTORY_CONFIGURATION;
    using MKHISTORY_ECC_REG_DATA = _EFS_MKHISTORY_ECC_REG_DATA;
    using MKHISTORY_ELEMENT = _EFS_MKHISTORY_ELEMENT;
    using MKHISTORY_LIST = _EFS_MKHISTORY_LIST;
    using MKHISTORY_REG_DATA_HEADER = _EFS_MKHISTORY_REG_DATA_HEADER;
    using MKHISTORY_RSA_REG_DATA = _EFS_MKHISTORY_RSA_REG_DATA;
    using PFILE_HEADER = _EFS_PFILE_HEADER;
    using PFILE_PREAMBLE = _EFS_PFILE_PREAMBLE;
    using PFILE_STREAM = _EFS_PFILE_STREAM;
    using PIN_BLOB = _EFS_PIN_BLOB;
    using POL_CALLBACK_DATA = _EFS_POL_CALLBACK_DATA;
    using POL_SETTINGS = _EFS_POL_SETTINGS;
    using PUBLIC_KEY_INFO = _EFS_PUBLIC_KEY_INFO;
    using RPC_BLOB = _EFS_RPC_BLOB;
    using RSA_ENCRYPTION_CONTEXT = _EFS_RSA_ENCRYPTION_CONTEXT;
    using SID_INFORMATION = _EFS_SID_INFORMATION;
    using STREAM_DATA = _EFS_STREAM_DATA;
    using STREAM_INFO = _EFS_STREAM_INFO;
    using STREAM_SIZE = _EFS_STREAM_SIZE;
    using USER_INFO = _EFS_USER_INFO;
    using USER_KEY_INFO = _EFS_USER_KEY_INFO;
    using USER_NAME_INFO_DESCRIPTOR = _EFS_USER_NAME_INFO_DESCRIPTOR;
    using USER_PROFILE_DESCRIPTOR = _EFS_USER_PROFILE_DESCRIPTOR;
    using VERSION_INFO = _EFS_VERSION_INFO;

    using EXP_FILE_HEADER = _EFSEXP_FILE_HEADER;
    using EXP_STREAM_HEADER = _EFSEXP_STREAM_HEADER;
    using EXP_DATA_HEADER = _EFSEXP_DATA_HEADER;

    using L_DATA_STREAM = _EFSL_DATA_STREAM;
    using L_PERSIST_KEY = _EFSL_PERSIST_KEY;

    using X_DATA_STREAM = _EFSX_DATA_STREAM;
    using X_DATUM_BLOB = _EFSX_DATUM_BLOB;
    using X_DATUM_DESCRIPTOR = _EFSX_DATUM_DESCRIPTOR;
    using X_DATUM_DPAPI_NG_DATA = _EFSX_DATUM_DPAPI_NG_DATA;
    using X_DATUM_FEK_INFO = _EFSX_DATUM_FEK_INFO;
    using X_DATUM_KEY_AGMT_DATA = _EFSX_DATUM_KEY_AGMT_DATA;
    using X_DATUM_KEY_PROTECTOR = _EFSX_DATUM_KEY_PROTECTOR;
    using X_DATUM_PFILE_PROTECTOR_LIST = _EFSX_DATUM_PFILE_PROTECTOR_LIST;
    using X_DATUM_PROTECTOR_INFO = _EFSX_DATUM_PROTECTOR_INFO;
    using X_DATUM_TYPE_PROPERTIES = _EFSX_DATUM_TYPE_PROPERTIES;
    using X_DATUM = _EFSX_DATUM;
    using X_FILE_KEY = _EFSX_FILE_KEY;
    using X_PROTECTOR_LIST = _EFSX_PROTECTOR_LIST;

    // Miscellaneous
    using ENCRYPTED_KEY = _ENCRYPTED_KEY;
    using ENCRYPTED_KEYS = _ENCRYPTED_KEYS;
    using POLICY_DOMAIN_EFS_INFO = _POLICY_DOMAIN_EFS_INFO;
    using POLICY_EFS_RECOVERY = _POLICY_EFS_RECOVERY;

    #if _WIN32_WINNT <= _WIN32_WINNT_WS03
    using EFS_INIT_DATAEXG = _EFS_INIT_DATAEXG;
    using EFS_KEY_SALT = _EFS_KEY_SALT;
    using EFS_STREAM = _EFS_STREAM;
    using GENERAL_FS_DATA = _GENERAL_FS_DATA;
    using KEY_INTEGRITY_INFO = _KEY_INTEGRITY_INFO;
    #endif
}
#endif