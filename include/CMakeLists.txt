# Absolute paths are used to allow the USE_STAMP_FILE option to be used with doxygen_add_docs
set(SSPI_HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/all.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/cloudap.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/crypt.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/livessp.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/lsa.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/msv1_0.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/negoexts.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/negotiate.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/pku2u.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/rpc.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/schannel.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/spm.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/wdigest.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/sspi/kerberos.hpp

)
set(SSPI_HEADERS ${SSPI_HEADERS} PARENT_SCOPE)
target_sources(sspi PRIVATE ${SSPI_HEADERS})
target_include_directories(sspi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_sources(lsa-whisperer PRIVATE
    cli.hpp
    commands.hpp
)