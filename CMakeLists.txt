cmake_minimum_required(VERSION 3.21.0)
project(lsa-whisperer
    VERSION "2.1"
    DESCRIPTION "A CLI for interacting with LSA"
    HOMEPAGE_URL "https://github.com/EvanMcBroom/lsa-whisperer"
    LANGUAGES CXX
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Remove run-time error checks because these introduce imports that are are non-compliant for bofs
string(REGEX REPLACE "/RTC[1csu]?" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
string(REGEX REPLACE "/RTC[1csu]?" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

if (MSVC AND NOT DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
# Workaround for unexpected evaluations in if statement.
# https://stackoverflow.com/questions/19982340/cmake-compare-to-empty-string-with-strequal-failed
# https://cmake.org/pipermail/cmake/2011-October/046939.html
string(COMPARE EQUAL "${CMAKE_BUILD_TYPE}" "" NO_CMAKE_BUILD_TYPE)
if(NO_CMAKE_BUILD_TYPE)
    set(ARTIFACT_DIR ${CMAKE_CURRENT_BINARY_DIR})
else()
    set(ARTIFACT_DIR ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_BUILD_TYPE})
endif()

# Suppress warnings regarding some libraries specifying
# a cmake_minimum_required to below 3.10 .
set(CMAKE_WARN_DEPRECATED FALSE)

find_package(PythonInterp 3)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
include(cmake/midl.cmake)
include(cmake/requirements.cmake)

add_subdirectory(lwdk)

add_library(sspi STATIC)
target_compile_definitions(sspi PUBLIC NOMINMAX)
target_link_libraries(sspi PUBLIC lwdk::lwdk spdlog::spdlog)

add_executable(lsa-whisperer)
target_link_libraries(lsa-whisperer PRIVATE advapi32 Userenv.lib clipp::clipp cxxopts::cxxopts magic_enum::magic_enum replxx::replxx sspi)

# Add the bofs library when the project is not being
# included as a subdirectory of a larger project.
if (${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    # Define a static library which will be used to build the bofs
    add_library(bof-archive STATIC)
    if (MSVC)
        target_compile_options(bof-archive PRIVATE
            /GS- # Remove stack cookie checks
            /Od # Disable optimizations
            # Disable safe thread initialization because these introduce
            # imports that are are non-compliant for bofs
            /Zc:threadSafeInit-
            # Remove C++ exception handling
            /EHa-
            /EHc-
            /EHr-
            /EHs-
        )
        target_link_options(bof-archive PRIVATE /ignore:4006)
    endif()
    target_link_libraries(bof-archive PUBLIC lwdk::lwdk sspi)
    add_subdirectory(bofs)
    # If Python and the required modules are installed, then add
    # a target to extract the bofs from the static library
    if (${PYTHONINTERP_FOUND})
        execute_process(
            COMMAND ${PYTHON_EXECUTABLE} -c "import arpy"
            RESULT_VARIABLE PY_EXIT_CODE
            OUTPUT_QUIET
        )
        if (${PY_EXIT_CODE} EQUAL 0)
            # Define the output files that will be extracted from the library
            get_target_property(BOF_SOURCES bof-archive SOURCES)
            foreach (SOURCE IN LISTS BOF_SOURCES)
                get_filename_component(SOURCE_NAME ${SOURCE} NAME_WE) # Source name without the extension
                set(BOF_OUTPUTS ${BOF_OUTPUTS} ${SOURCE_NAME})
            endforeach()
            list(TRANSFORM BOF_OUTPUTS PREPEND "${ARTIFACT_DIR}/bofs/")
            list(TRANSFORM BOF_OUTPUTS APPEND ".o")
            # Extracted all objects from the bof-archive target after its built
            add_custom_command(OUTPUT ${BOF_OUTPUTS}
                COMMAND ${CMAKE_COMMAND} -E make_directory "${ARTIFACT_DIR}/bofs"
                COMMAND ${PYTHON_EXECUTABLE} "${PROJECT_SOURCE_DIR}/cmake/ar2objs.py" $<TARGET_FILE:bof-archive> "${ARTIFACT_DIR}/bofs"
                DEPENDS bof-archive
            )
            add_custom_target(bof-objects ALL DEPENDS ${BOF_OUTPUTS})
        endif()
    endif()
endif()

add_subdirectory(include)
add_subdirectory(source)

# Modules
file(MAKE_DIRECTORY "${ARTIFACT_DIR}/modules")
add_library(cloudapcache SHARED)
add_library(token SHARED)
add_library(wlid SHARED)
add_subdirectory(modules)

find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    set(DOXYGEN_PROJECT_NAME "SSPI Library")
    set(DOXYGEN_PROJECT_BRIEF "The library used by lsa-whisperer to interact with LSA")
    set(DOXYGEN_EXTRACT_ANON_NSPACES NO)
    set(DOXYGEN_QUIET YES)
    set(DOXYGEN_WARN_IF_INCOMPLETE_DOC NO)
    set(DOXYGEN_WARN_IF_UNDOCUMENTED NO)
    set(DOXYGEN_OUTPUT_DIRECTORY docs/doxygen)
    set(DOXYGEN_GENERATE_XML YES)
    doxygen_add_docs(docs-doxygen
        ${SSPI_HEADERS}
        ${SSPI_SOURCES}
        ALL USE_STAMP_FILE
        COMMENT "Generating Doxygen docs"
    )
    # Add sphinx doc generation as a seperate command,
    # not a post build command for the doxygen doc generation
    # because the required python modules may not be installed
    find_package(Breathe QUIET)
    find_package(Sphinx QUIET)
    if (BREATHE_FOUND AND SPHINX_FOUND)
        add_custom_target(docs-sphinx
            COMMAND ${SPHINX_EXECUTABLE}
                -b html
                -Drelease=${PROJECT_VERSION}
                -Dbreathe_projects.SspiLibrary=${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/xml
                ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/rst ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/html
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating Sphinx docs"
        )
        add_custom_command(TARGET docs-sphinx PRE_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/docs ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/rst
            COMMENT "Copying docs directory to RST directory"
        )
        add_custom_command(TARGET docs-sphinx PRE_BUILD
            COMMAND ${BREATHE_APIDOC_EXECUTABLE} -o ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/rst ${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/xml
            COMMENT "Converting Doxygen XML to RSTs"
        )
        add_dependencies(docs-sphinx docs-doxygen)
        set_target_properties(docs-sphinx PROPERTIES EXCLUDE_FROM_ALL TRUE)
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/sphinx/html DESTINATION docs)
    else()
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/docs/doxygen/html DESTINATION docs)
    endif()
endif()