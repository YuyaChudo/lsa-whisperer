//// Copyright (C) 2024 Evan McBroom
////
//// Security package manager (spm) which also includes the
//// authentication package (ap) api calls
////
//// This header is a work in progress. It will eventually
//// be reorganized and used to replace the spm header in
//// the sspi library.
////
#pragma once
// clang-format off
#include <phnt_windows.h>
#include <phnt.h>
// clang-format on

#define MAX_BUFFERS_IN_CALL 8

struct _LSAP_SECURITY_PACKAGE;
typedef _LSAP_SECURITY_PACKAGE* PLSAP_SECURITY_PACKAGE;

typedef SECURITY_USER_DATA SecurityUserData, *PSecurityUserData;

// The authentication package message format, which may be included as a component of an SPM API call
namespace AuApi {
    constexpr auto AddressLength() {
        return 32;
    }

    constexpr auto MaxLogonProcNameLength() {
        return 127;
    }

    constexpr auto MaxPackageNameLength() {
        return 127;
    }

    // Used for the ClientMode argument to SspirConnectRpc
    enum class ClientMode : DWORD {
        Undefined,
        Kernel, // Mainly used by ksecdd.sys
        Usermode
    };

    typedef struct _REGISTER_CONNECT_INFO {
        NTSTATUS CompletionStatus;
        ULONG SecurityMode;
        ULONG LogonProcessNameLength;
        CHAR LogonProcessName[MaxPackageNameLength() + 1];
    } REGISTER_CONNECT_INFO, *PREGISTER_CONNECT_INFO;

#undef LogonUser

    enum class NUMBER_PRE_NT61 : DWORD {
        LookupPackage,
        LogonUser,
        CallPackage,
        DeregisterLogonProcess,
        MaxApiNumber
    };

    enum class NUMBER : DWORD {
        LookupPackage,
        CallPackage,
        DeregisterLogonProcess,
        MaxApiNumber
    };

    namespace Args {
        typedef struct _LOOKUP_PACKAGE {
            ULONG AuthenticationPackage; // OUT
            ULONG PackageNameLength;
            CHAR PackageName[MaxPackageNameLength() + 1];
        } LOOKUP_PACKAGE, *PLOOKUP_PACKAGE;

        typedef struct _CALL_PACKAGE {
            ULONG AuthenticationPackage;
            PVOID ProtocolSubmitBuffer;
            ULONG SubmitBufferLength;
            NTSTATUS ProtocolStatus; // OUT
            PVOID ProtocolReturnBuffer; // OUT
            ULONG ReturnBufferLength; // OUT
            ULONG CallFlags; // Added later
        } CALL_PACKAGE, *PCALL_PACKAGE;

        // Albeit not available anymore via an AuApi call afaik, the
        // original args struct for logon user is included due to it
        // being useful for determining type information for ms-sspir.idl
        typedef struct _LOGON_USER {
            STRING OriginName;
            SECURITY_LOGON_TYPE LogonType;
            ULONG AuthenticationPackage;
            PVOID AuthenticationInformation;
            ULONG AuthenticationInformationLength;
            ULONG LocalGroupsCount;
            PVOID LocalGroups;
            TOKEN_SOURCE SourceContext;
            NTSTATUS SubStatus; // OUT parameter
            PVOID ProfileBuffer; // OUT parameter
            ULONG ProfileBufferLength; // OUT parameter
            ULONG DummySpacer; // Spacer to force LUID to 8 byte alignment
            LUID LogonId; // OUT parameter
            HANDLE Token; // OUT parameter
            QUOTA_LIMITS Quotas; // OUT parameter
            CHAR IpAddress[AddressLength()]; // At the end to avoid compat problems with clients
                //   built with older versions of lsadll.lib
        } LOGON_USER, *PLOGON_USER;
    }
}

// The Security Package Manager (SPM) message format for calling SPM APIs over an LPC port
// The message format existed as early as NT 3.5
// The format is still used on NT 10 for the SspirCallRpc operation in the SSPI RPC interface
namespace SpmApi {

#define SPM_AUTH_PKG_FLAG 0x00001000

    //
    // Buffers that will fit into the message are placed in there and the
    // their pointers will be replaced with this value.  Since all buffers and
    // strings are sent with their lengths, to unpack the data move pull out the
    // buffers in the order they are listed in the API message.
    //
    // Since all buffers must be passed from VM, any address above 0x80000000
    // will not be confused for an address
    //

#define SEC_PACKED_BUFFER_VALUE (IntToPtr(0xFFFFFFFF))
// Max secbuffers allowed in a SecBufferDesc
#define MAX_SECBUFFERS 10
// This bit gets set in the SecurityMode word, indicating that the DLL
// is running in the LSA process.  The DLL will turn around and get the
// direct dispatch routine, and avoid the whole LPC issue
#define LSA_MODE_SAME_PROCESS 0x00010000
// This flag is added to the version information in a SecBufferDesc to
// indicate that the memory is already mapped to the LSA.
#define LSA_MEMORY_KERNEL_MAP      0x80000000
#define LSA_SECBUFFER_VERSION_MASK 0x0000FFFF

    typedef SECURITY_STRING SECURITY_STRING;
    typedef PVOID PVOID;
    typedef SecHandle SEC_HANDLE;
    typedef SecBufferDesc SEC_BUFFER_DESC;
    typedef SecBuffer SEC_BUFFER;
    typedef ULONG_PTR LSA_SEC_HANDLE;

    typedef SEC_HANDLE CRED_HANDLE_LPC, *PCRED_HANDLE_LPC;
    typedef SEC_HANDLE CONTEXT_HANDLE_LPC, *PCONTEXT_HANDLE_LPC;
    typedef SEC_HANDLE* PSEC_HANDLE;
    typedef SEC_BUFFER* PSEC_BUFFER;

    //
    // Connection specific data types
    //

    //
    // The following are message structures for internal routines, such as
    // synchronization and state messages
    //
#define PACKAGEINFO_THUNKS 16

    typedef struct _SEC_PACKAGE_BINDING_INFO_LPC {
        SECURITY_STRING PackageName;
        SECURITY_STRING Comment;
        SECURITY_STRING ModuleName;
        ULONG PackageIndex;
        ULONG fCapabilities;
        ULONG Flags;
        ULONG RpcId;
        ULONG Version;
        ULONG TokenSize;
        ULONG ContextThunksCount;
        ULONG ContextThunks[PACKAGEINFO_THUNKS];
    } SEC_PACKAGE_BINDING_INFO_LPC, *PSEC_PACKAGE_BINDING_INFO_LPC;

    typedef SEC_PACKAGE_BINDING_INFO_LPC SEC_PACKAGE_BINDING_INFO;
    typedef SEC_PACKAGE_BINDING_INFO_LPC* PSEC_PACKAGE_BINDING_INFO;

#define PACKAGEINFO_BUILTIN 0x00000001
#define PACKAGEINFO_AUTHPKG 0x00000002
#define PACKAGEINFO_SIGNED  0x00000004

    namespace Args {
        typedef struct _SPMGetBindingAPI {
            LSA_SEC_HANDLE ulPackageId;
            SEC_PACKAGE_BINDING_INFO_LPC BindingInfo;
        } SPMGetBindingAPI;

        //
        // Internal SetSession API.
        // not supported in Wow64
        //

        typedef struct _SPMSetSession {
            ULONG Request;
            ULONG_PTR Argument;
            ULONG_PTR Response;
            PVOID ResponsePtr;
            PVOID Extra;
        } SPMSetSessionAPI;

#define SETSESSION_GET_STATUS       0x00000001
#define SETSESSION_ADD_WORKQUEUE    0x00000002
#define SETSESSION_REMOVE_WORKQUEUE 0x00000003
#define SETSESSION_GET_DISPATCH     0x00000004

        typedef struct _SPMFindPackageAPI {
            SECURITY_STRING ssPackageName;
            LSA_SEC_HANDLE ulPackageId;
        } SPMFindPackageAPI;

        // SPM API arguments

        // EnumeratePackages API
        typedef struct _SPMEnumPackagesAPI {
            ULONG cPackages; // OUT
            PSecPkgInfoW pPackages; // OUT
        } SPMEnumPackagesAPI;

        // Credential APIs

        // AcquireCredentialsHandle API
        typedef struct _SPMAcquireCredsAPI {
            SECURITY_STRING ssPrincipal;
            SECURITY_STRING ssSecPackage;
            ULONG fCredentialUse;
            LUID LogonID;
            PVOID pvAuthData;
            PVOID pvGetKeyFn;
            PVOID ulGetKeyArgument;
            CRED_HANDLE_LPC hCredential; // OUT
            TimeStamp tsExpiry; // OUT
            SEC_BUFFER AuthData;
        } SPMAcquireCredsAPI;

        // EstablishCredentials API (not supported in Wow64)
        typedef struct _SPMEstablishCredsAPI {
            SECURITY_STRING Name;
            SECURITY_STRING Package;
            ULONG cbKey;
            PUCHAR pbKey;
            CredHandle hCredentials; // OUT
            TimeStamp tsExpiry; // OUT
        } SPMEstablishCredsAPI;

        // FreeCredentialsHandle API
        typedef struct _SPMFreeCredHandleAPI {
            CRED_HANDLE_LPC hCredential;
        } SPMFreeCredHandleAPI;

        // Context APIs

        // InitializeSecurityContext API
        typedef struct _SPMInitSecContextAPI {
            CRED_HANDLE_LPC hCredential; // IN
            CONTEXT_HANDLE_LPC hContext; // IN
            SECURITY_STRING ssTarget; // IN
            ULONG fContextReq; // IN
            ULONG dwReserved1; // IN
            ULONG TargetDataRep; // IN
            SEC_BUFFER_DESC sbdInput; // IN
            ULONG dwReserved2; // IN
            CONTEXT_HANDLE_LPC hNewContext; // OUT
            SEC_BUFFER_DESC sbdOutput; // IN OUT
            ULONG fContextAttr; // OUT
            TimeStamp tsExpiry; // OUT
            BOOLEAN MappedContext; // OUT
            SEC_BUFFER ContextData; // OUT
            SEC_BUFFER sbData[0]; // IN
        } SPMInitContextAPI;

        // AcceptSecurityContext API

        typedef struct _SPMAcceptContextAPI {
            CRED_HANDLE_LPC hCredential; // IN
            CONTEXT_HANDLE_LPC hContext; // IN
            SEC_BUFFER_DESC sbdInput; // IN
            ULONG fContextReq; // IN
            ULONG TargetDataRep; // IN
            CHAR IpAddress[32]; // IN
            CONTEXT_HANDLE_LPC hNewContext; // OUT
            SEC_BUFFER_DESC sbdOutput; // IN OUT
            ULONG fContextAttr; // OUT
            TimeStamp tsExpiry; // OUT
            BOOLEAN MappedContext; // OUT
            SEC_BUFFER ContextData; // OUT
            SEC_BUFFER sbData[0]; // IN OUT
        } SPMAcceptContextAPI;

        //
        // ApplyControlToken API
        //

        typedef struct _SPMApplyTokenAPI {
            CONTEXT_HANDLE_LPC hContext;
            SEC_BUFFER_DESC sbdInput;
            SEC_BUFFER sbInputBuffer[MAX_SECBUFFERS];
        } SPMApplyTokenAPI;

        // DeleteContext API

        typedef struct _SPMDeleteContextAPI {
            CONTEXT_HANDLE_LPC hContext; // IN - Context to delete
        } SPMDeleteContextAPI;

        //
        // Miscelanneous, extension APIs
        //

        // QueryPackage API

        typedef struct _SPMQueryPackageAPI {
            SECURITY_STRING ssPackageName;
            PSecPkgInfoW pPackageInfo;
        } SPMQueryPackageAPI;

        // GetSecurityUserInfo
        // not supported in Wow64

        typedef struct _SPMGetUserInfoAPI {
            LUID LogonId; // IN
            ULONG fFlags; // IN
            PSecurityUserData pUserInfo; // OUT
        } SPMGetUserInfoAPI;

        //
        // Credentials APIs.  Not used.
        //

        typedef struct _SPMGetCredsAPI {
            CredHandle hCredentials; // IN
            SecBuffer Credentials; // OUT
        } SPMGetCredsAPI;

        typedef struct _SPMSaveCredsAPI {
            CredHandle hCredentials; // IN
            SecBuffer Credentials; // IN
        } SPMSaveCredsAPI;

        typedef struct _SPMQueryCredAttributesAPI {
            CRED_HANDLE_LPC hCredentials;
            ULONG ulAttribute;
            PVOID pBuffer;
            ULONG Allocs;
            PVOID Buffers[MAX_BUFFERS_IN_CALL];
        } SPMQueryCredAttributesAPI;

        typedef struct _SPMAddPackageAPI {
            SECURITY_STRING Package;
            ULONG OptionsFlags;
        } SPMAddPackageAPI;

        typedef struct _SPMDeletePackageAPI {
            SECURITY_STRING Package;
        } SPMDeletePackageAPI;

        typedef struct _SPMQueryContextAttrAPI {
            CONTEXT_HANDLE_LPC hContext;
            ULONG ulAttribute;
            PVOID pBuffer;
            ULONG Allocs;
            PVOID Buffers[MAX_BUFFERS_IN_CALL];
        } SPMQueryContextAttrAPI;

        typedef struct _SPMSetContextAttrAPI {
            CONTEXT_HANDLE_LPC hContext;
            ULONG ulAttribute;
            PVOID pBuffer;
            ULONG cbBuffer;
        } SPMSetContextAttrAPI;

        //
        // Kernel mode EFS API.  None of these are Wow64
        //

        typedef struct _SPMEfsGenerateKeyAPI {
            PVOID EfsStream;
            PVOID DirectoryEfsStream;
            ULONG DirectoryEfsStreamLength;
            PVOID Fek;
            ULONG BufferLength;
            PVOID BufferBase;
        } SPMEfsGenerateKeyAPI;

        typedef struct _SPMEfsGenerateDirEfsAPI {
            PVOID DirectoryEfsStream;
            ULONG DirectoryEfsStreamLength;
            PVOID EfsStream;
            PVOID BufferBase;
            ULONG BufferLength;
        } SPMEfsGenerateDirEfsAPI;

        typedef struct _SPMEfsDecryptFekAPI {
            PVOID Fek;
            PVOID EfsStream;
            ULONG EfsStreamLength;
            ULONG OpenType;
            PVOID NewEfs;
            PVOID BufferBase;
            ULONG BufferLength;
        } SPMEfsDecryptFekAPI;

        typedef struct _SPMEfsGenerateSessionKeyAPI {
            PVOID InitDataExg;
        } SPMEfsGenerateSessionKeyAPI;

        //
        // Usermode policy change notifications
        //
        //
        // Note: Instead of a HANDLE structure use a ULONG64 for EventHandle member
        //  to guarantee that passed value will be 64 bits. If not, in Wow64 the passed
        //  handle will be 32 bits, while the server side expects it to be 64 bits.
        //  Therefore always extend the handle to a 64 bit variable.
        //
        typedef struct _SPMLsaPolicyChangeNotifyAPI {
            ULONG Options;
            BOOLEAN Register;
            ULONG64 EventHandle;
            POLICY_NOTIFICATION_INFORMATION_CLASS NotifyInfoClass;
        } SPMLsaPolicyChangeNotifyAPI;

        typedef struct _SPMCallbackAPI {
            ULONG Type;
            PVOID CallbackFunction;
            PVOID Argument1;
            PVOID Argument2;
            SEC_BUFFER Input;
            SEC_BUFFER Output;
        } SPMCallbackAPI;

        enum class CallbackType {
            INTERNAL = 1, // Handled by the security DLL
            GETKEY, // Getkey function being called
            PACKAGE, // Package function
            EXPORT, // Ptr to string
        };
        //
        // Fast name lookup
        //

        typedef struct _SPMGetUserNameXAPI {
            ULONG Options;
            SECURITY_STRING Name;
        } SPMGetUserNameXAPI;

#define SPM_NAME_OPTION_MASK 0xFFFF0000
#define SPM_NAME_OPTION_NT4_ONLY 0x00010000 // GetUserNameX only, not Ex
#define SPM_NAME_OPTION_FLUSH    0x00020000

        // AddCredential API
        typedef struct _SPMAddCredential {
            CRED_HANDLE_LPC hCredentials;
            SECURITY_STRING ssPrincipal;
            SECURITY_STRING ssSecPackage;
            ULONG fCredentialUse;
            LUID LogonID;
            PVOID pvAuthData;
            PVOID pvGetKeyFn;
            PVOID ulGetKeyArgument;
            TimeStamp tsExpiry; // OUT
        } SPMAddCredentialAPI;

        typedef struct _SPMEnumLogonSession {
            PVOID LogonSessionList; // OUT
            ULONG LogonSessionCount; // OUT
        } SPMEnumLogonSessionAPI;

        typedef struct _SPMGetLogonSessionData {
            LUID LogonId;
            PVOID LogonSessionInfo; // OUT
        } SPMGetLogonSessionDataAPI;

        // What SPMCallbackAPI::Argument1 is set to when SPMCallbackAPI::Type is CallbackType::INTERNAL
        enum class CallbackCode {
            ADDRESS_CHECK = 1, // Setting up shared buffer
            SHUTDOWN, // Inproc shutdown notification
        };

        // SID translation APIs (for kmode callers, primarily)
        typedef struct _SPMLookupAccountSidX {
            PVOID Sid;
            SECURITY_STRING Name; // OUT
            SECURITY_STRING Domain; // OUT
            SID_NAME_USE NameUse; // OUT
        } SPMLookupAccountSidXAPI;

        typedef struct _SPMLookupAccountNameX {
            SECURITY_STRING Name;
            SECURITY_STRING Domain;
            PVOID Sid;
            SID_NAME_USE NameUse;
        } SPMLookupAccountNameXAPI;

        typedef struct _SPMLookupWellKnownSid {
            WELL_KNOWN_SID_TYPE SidType;
            PVOID Sid;
        } SPMLookupWellKnownSidAPI;
    }

    enum class NUMBER_PRE_NT61 {
        GetBinding = (static_cast<DWORD>(AuApi::NUMBER::MaxApiNumber) + 1),
        SetSession,
        FindPackage,
        EnumPackages,
        AcquireCreds,
        EstablishCreds,
        FreeCredHandle,
        InitContext,
        AcceptContext,
        ApplyToken,
        DeleteContext,
        QueryPackage,
        GetUserInfo,
        GetCreds,
        SaveCreds,
        QueryCredAttributes,
        AddPackage,
        DeletePackage,
        EfsGenerateKey,
        EfsGenerateDirEfs,
        EfsDecryptFek,
        EfsGenerateSessionKey,
        Callback,
        QueryContextAttr,
        LsaPolicyChangeNotify,
        GetUserNameX,
        AddCredential,
        EnumLogonSession,
        GetLogonSessionData,
        SetContextAttr,
        LookupAccountNameX,
        LookupAccountSidX,
        LookupWellKnownSid,
        // MaxApiNumber
    };

#undef QueryContextAttributes
#undef SetContextAttributes
#undef LookupAccountName
#undef ChangeAccountPassword

    enum class NUMBER {
        GetBinding = (static_cast<DWORD>(AuApi::NUMBER::MaxApiNumber) + 1),
        SetSession,
        FindPackage,
        EnumPackages,
        QueryPackage,
        GetUserInfo,
        QueryCredAttributes,
        AddPackage,
        EfsGenerateKey,
        // The next 3 entries of the SPM function table are duplicates like so:
        // EfsGenerateKey,
        // EfsGenerateKey,
        // EfsGenerateKey,
        Callback = 16,
        QueryContextAttributes,
        LsaPolicyChangeNotify,
        AddCredential,
        EnumLogonSessions,
        GetLogonSessionData,
        SetContextAttributes,
        LookupAccountName,
        LookupAccountSidX,
        LookupWellKnownSid,
        SetCredAttributes,
        ChangeAccountPassword,
        // MaxApiNumber
    };

#pragma push_macro("CALLBACK")
#undef CALLBACK
    enum class FLAG : USHORT {
        ERROR_RET = 0x0001, // Indicates an error return
        MEMORY = 0x0002, // Memory was allocated in client
        PREPACK = 0x0004, // Data packed in bData field
        GETSTATE = 0x0008, // driver should call GetState
        ANSI_CALL = 0x0010, // Called via ANSI stub
        HANDLE_CHG = 0x0020, // A handle was changed
        CALLBACK = 0x0040, // Callback to calling process
        ALLOCS = 0x0080, // VM Allocs were placed in prepack
        EXEC_NOW = 0x0100, // Execute in LPC thread
        WIN32_ERROR = 0x0200, // Status is a win32 error
        KMAP_MEM = 0x0400 // Call contains buffers in the kmap
    };
#pragma pop_macro("CALLBACK")

    typedef union _API_ARGUMENTS {
        union {
            AuApi::Args::LOOKUP_PACKAGE LookupPackage;
            AuApi::Args::CALL_PACKAGE CallPackage;
        } ApArguments;
        struct _SPM_API_ARGUMENTS {
            USHORT fAPI; // Set using FLAG
            USHORT VMOffset;
            PVOID ContextPointer;
            union {
                Args::SPMGetBindingAPI GetBinding;
                Args::SPMSetSessionAPI SetSession;
                Args::SPMFindPackageAPI FindPackage;
                Args::SPMEnumPackagesAPI EnumPackages;
                Args::SPMAcquireCredsAPI AcquireCreds;
                Args::SPMEstablishCredsAPI EstablishCreds;
                Args::SPMFreeCredHandleAPI FreeCredHandle;
                Args::SPMInitContextAPI InitContext;
                Args::SPMAcceptContextAPI AcceptContext;
                Args::SPMApplyTokenAPI ApplyToken;
                Args::SPMDeleteContextAPI DeleteContext;
                Args::SPMQueryPackageAPI QueryPackage;
                Args::SPMGetUserInfoAPI GetUserInfo;
                Args::SPMGetCredsAPI GetCreds;
                Args::SPMSaveCredsAPI SaveCreds;
                Args::SPMQueryCredAttributesAPI QueryCredAttributes;
                Args::SPMAddPackageAPI AddPackage;
                Args::SPMDeletePackageAPI DeletePackage;
                Args::SPMEfsGenerateKeyAPI EfsGenerateKey;
                Args::SPMEfsGenerateDirEfsAPI EfsGenerateDirEfs;
                Args::SPMEfsDecryptFekAPI EfsDecryptFek;
                Args::SPMEfsGenerateSessionKeyAPI EfsGenerateSessionKey;
                Args::SPMQueryContextAttrAPI QueryContextAttr;
                Args::SPMCallbackAPI Callback;
                Args::SPMLsaPolicyChangeNotifyAPI LsaPolicyChangeNotify;
                Args::SPMGetUserNameXAPI GetUserNameX;
                Args::SPMAddCredentialAPI AddCredential;
                Args::SPMEnumLogonSessionAPI EnumLogonSession;
                Args::SPMGetLogonSessionDataAPI GetLogonSessionData;
                Args::SPMSetContextAttrAPI SetContextAttr;
                Args::SPMLookupAccountSidXAPI LookupAccountSidX;
                Args::SPMLookupAccountNameXAPI LookupAccountNameX;
                Args::SPMLookupWellKnownSidAPI LookupWellKnownSid;
            } Arguments;
        } SpmArguments;
    } API_ARGUMENTS, *PAPI_ARGUMENTS;

    //
    // For performance, some APIs will attempt to pack small parameters in the
    // message being sent to the SPM, rather than have the SPM read it out of
    // their memory.  So, this value defines how much data can be stuck in the
    // message.
    //
    // Two items are defined here.  One, CBAPIHDR, is the size of everything
    // in the message except the packed data.  The other, CBPREPACK, is the
    // left over space.  I subtract 4 at the end to avoid potential boundary
    // problems with an LPC message.
    //

    constexpr auto ApiHeaderSize() {
        return sizeof(PORT_MESSAGE) + sizeof(ULONG) + sizeof(HRESULT) + sizeof(API_ARGUMENTS);
    }

    constexpr auto MaxPortMessageLength() {
        return 256;
    }

    constexpr auto PrePackSize() {
        return MaxPortMessageLength() - ApiHeaderSize() - sizeof(PVOID);
    }

    constexpr auto SecBufferCount() {
        return PrePackSize() / sizeof(SecBuffer);
    }

    // This structure is sent over during an API call rather than a connect message
    typedef struct _API_CALL_INFO {
        NUMBER dwAPI;
        HRESULT scRet;
        API_ARGUMENTS Args;
        UCHAR bData[ApiHeaderSize()];
    } API_CALL_INFO, *PAPI_CALL_INFO;

    inline auto SecBaseMessageSize(size_t argSize) {
        return sizeof(NUMBER) + sizeof(HRESULT) + sizeof(API_ARGUMENTS) - sizeof(API_ARGUMENTS::SpmArguments.Arguments) + argSize;
    }
}