# Copyright (C) 2024 Evan McBroom
cmake_minimum_required(VERSION 3.5.0)
project(lwdk
    VERSION "1.0"
    DESCRIPTION "LSA Whisperer Development Kit"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/lsa-whisperer"
    LANGUAGES C CXX
)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
include(cmake/midl.cmake)

# Process Hacker Native API library
add_subdirectory(include/phnt)

# Cryptographic Provider Development Kit
# https://www.microsoft.com/en-us/download/details.aspx?id=30688
add_library(lwdk_cpdk INTERFACE)
target_include_directories(lwdk_cpdk INTERFACE include)
add_library(lwdk::cpdk ALIAS lwdk_cpdk)

# Microsoft ASN.1 Library
add_library(lwdk_asn1 INTERFACE)
target_include_directories(lwdk_asn1 INTERFACE include)
# https://asawicki.info/news_1420_generating_lib_file_for_dll_library
#add_custom_command(
#    OUTPUT msasn1.lib
#    COMMAND lib
#        /def:${CMAKE_CURRENT_SOURCE_DIR}/sources/msasn1.def
#        /out:msasn1.lib
#        /machine: $<IF:$<CONFIG:Debug>,X64,X86>
#    MAIN_DEPENDENCY ${CMAKE_CURRENT_SOURCE_DIR}/sources/msasn1.def
#    COMMENT "Generating asn.1 lib file"
#)
#target_link_libraries(lwdk_asn1 INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/msasn1.lib)
add_library(lwdk::asn1 ALIAS lwdk_asn1)

add_library(lwdk STATIC)
set_target_properties(lwdk PROPERTIES LINKER_LANGUAGE C)
target_include_directories(lwdk PUBLIC include)
target_link_libraries(lwdk PUBLIC lwdk_asn1 lwdk_cpdk phnt::phnt)
target_sources(lwdk PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lazy.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/cloudap.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/cng.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/credman.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/credssp.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/crypt.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/cssp.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/dpapi.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/dpaping.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/efs.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/gssapi.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/fve.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/kerberos.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/krb5.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/ksecdd.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/ldap.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/livessp.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/lsa.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/msv1_0.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/native.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/negoexts.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/negotiate.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/netlogon.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/ngc.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/ntasn1.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/ntlm.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/pkcs12.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/pku2u.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/rdpear.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/schannel.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/spm.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/spnego.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/tspkg.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/vault.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/wdigest.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/lwdk/x509.h
)
add_subdirectory(pickling)
add_subdirectory(rpc)
add_subdirectory(sources)

add_library(lwdk::lwdk ALIAS lwdk)