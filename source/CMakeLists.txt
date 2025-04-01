
if (${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    # boflib.cpp should not be compiled. It should instead be
    # included in each source file for bofs as if boflib.cpp
    # was a header file so that the preprocessor will include
    # its contents in each single compilation unit for the
    # bofs project.
    # https://cmake.org/pipermail/cmake/2008-June/022387.html
    set_source_files_properties(boflib.cpp TARGET_DIRECTORY bof-archive PROPERTIES HEADER_FILE_ONLY TRUE)
    target_sources(bof-archive PRIVATE boflib.cpp)
    target_include_directories(bof-archive PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# Absolute paths are used to allow the USE_STAMP_FILE option to be used with doxygen_add_docs
set(SSPI_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/all.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/cloudap.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/crypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/kerberos.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/livessp.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/lsa.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/msv1_0.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/negoexts.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/negotiate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/pku2u.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/rpc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/schannel.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/spm.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/wdigest.cpp

)
set(SSPI_SOURCES ${SSPI_SOURCES} PARENT_SCOPE)
target_sources(sspi PRIVATE ${SSPI_SOURCES})
target_link_libraries(sspi PUBLIC Bcrypt.lib Crypt32.lib Ntdll.lib Rpcrt4.dll Secur32.lib)
target_idl_sources(sspi CLIENT SOURCES sspir.idl)

target_sources(lsa-whisperer PRIVATE
    cli.cpp
    commands.cpp
    main.cpp
)