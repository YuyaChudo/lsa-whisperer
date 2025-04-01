macro(SetModuleProperties TARGET_NAME)
    set_target_properties(${TARGET_NAME} PROPERTIES
        PROJECT_LABEL module-${TARGET_NAME}
        # Generator expressions are used to force CMAKE to not append
        # a per-configuration subdirectory to the output directory path.
        ARCHIVE_OUTPUT_DIRECTORY $<$<BOOL:true>:${ARTIFACT_DIR}/modules>
        LIBRARY_OUTPUT_DIRECTORY $<$<BOOL:true>:${ARTIFACT_DIR}/modules>
        PDB_OUTPUT_DIRECTORY $<$<BOOL:true>:${ARTIFACT_DIR}/modules>
        RUNTIME_OUTPUT_DIRECTORY $<$<BOOL:true>:${ARTIFACT_DIR}/modules>
    )
endmacro()

target_sources(cloudapcache PRIVATE cloudapcache.cpp cloudapcache.def)
target_link_libraries(cloudapcache PRIVATE sspi clipp::clipp cppcodec nlohmann_json::nlohmann_json bcrypt.lib rpcrt4.lib)
SetModuleProperties(cloudapcache)

target_sources(token PRIVATE token.cpp token.def)
target_include_directories(token PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(token PRIVATE clipp::clipp sspi)
SetModuleProperties(token)

target_sources(wlid PRIVATE wlid.cpp wlid.def)
target_link_libraries(wlid PRIVATE clipp::clipp nlohmann_json::nlohmann_json sspi wininet.lib)
SetModuleProperties(wlid)