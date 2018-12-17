CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(PLUGIN 0 CACHE BOOL "Build a plugin.")

PROJECT(sysrepo-plugin-dt-firmware)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall")

set(SOURCES
	src/parse.c
	src/firmware.c)

# git SHA1 hash
execute_process(COMMAND
  git describe --always --abbrev=40
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_SHA1
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

# by default set to older version for backward compatibility
set(SYSREPO_LESS_0_7_5 ON CACHE BOOL "Sysrepo version older than 0.7.5 (< 0.7.5)")
set(SYSREPO_LESS_0_7_7 ON CACHE BOOL "Sysrepo version older than 0.7.7 (< 0.7.7)")

# get sysrepo version
find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--modversion" "libsysrepo" OUTPUT_VARIABLE SYSREPO_VERSION)
    if(SYSREPO_VERSION)
        # strip new line from string
        string(STRIP ${SYSREPO_VERSION} SYSREPO_VERSION)
        if(${SYSREPO_VERSION} VERSION_GREATER "0.7.4")
            set(SYSREPO_LESS_0_7_5 OFF)
        endif()
        if(${SYSREPO_VERSION} VERSION_GREATER "0.7.6")
            set(SYSREPO_LESS_0_7_7 OFF)
        endif()
    endif()
endif()

# generate version.h
configure_file("${PROJECT_SOURCE_DIR}/src/version.h.in" "${PROJECT_SOURCE_DIR}/src/version.h" ESCAPE_QUOTES @ONLY)

if(PLUGIN)
	add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION lib)
else()
	add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
	install(TARGETS ${CMAKE_PROJECT_NAME} DESTINATION bin)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME} PREFIX "")

# dependencies - sysrepo
find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

# dependencies - libubox
FIND_PACKAGE(LIBUBOX REQUIRED)
INCLUDE_DIRECTORIES(${LIBUBOX_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME} ${LIBUBOX_LIBRARIES})

find_package(LIBUBUS REQUIRED)
include_directories(${LIBUBUS_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBUBUS_LIBRARIES})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${CURL_LIBRARIES})

find_package(OpenSSL REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${OPENSSL_LIBRARIES})
include_directories(${OPENSSL_INCLUDE_DIR})

TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME} json-c)
