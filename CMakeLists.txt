cmake_minimum_required(VERSION 3.16)
project(vpn_client_win VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network)

if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/Progra~1/OpenSSL-Win64")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")

    find_library(OPENSSL_SSL_LIBRARY
        NAMES libssl ssl
        PATHS "${OPENSSL_ROOT_DIR}/lib" "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD"
        NO_DEFAULT_PATH
    )

    find_library(OPENSSL_CRYPTO_LIBRARY
        NAMES libcrypto crypto
        PATHS "${OPENSSL_ROOT_DIR}/lib" "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD"
        NO_DEFAULT_PATH
    )

    if(NOT OPENSSL_SSL_LIBRARY OR NOT OPENSSL_CRYPTO_LIBRARY)
        message(FATAL_ERROR "OpenSSL libraries not found!")
    endif()

    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL SSL: ${OPENSSL_SSL_LIBRARY}")
    message(STATUS "OpenSSL Crypto: ${OPENSSL_CRYPTO_LIBRARY}")
endif()

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    tun_interface.h
    vpn_client.h
    vpn_client.cpp
    tun_interface_win.cpp
    tls_wrapper_client.cpp
    tls_wrapper_client.h
    crypto_client.h
    crypto_client.cpp
    wintun.h
    logo.ico
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(vpn_client_win MANUAL_FINALIZATION ${PROJECT_SOURCES})
else()
    add_executable(vpn_client_win ${PROJECT_SOURCES})
endif()

target_link_libraries(vpn_client_win PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
)

target_include_directories(vpn_client_win PRIVATE ${OPENSSL_INCLUDE_DIR})

if(WIN32)
    target_link_libraries(vpn_client_win PRIVATE
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        iphlpapi
        ws2_32
        Advapi32
        crypt32
    )

    target_compile_definitions(vpn_client_win PRIVATE
        _WIN32
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )

    if(MSVC)
        set_target_properties(vpn_client_win PROPERTIES
            LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
            WIN32_EXECUTABLE TRUE
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )
    endif()
endif()

if(WIN32)
    add_custom_command(TARGET vpn_client_win POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Copying OpenSSL DLLs..."
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "C:/Windows/System32/libssl-3-x64.dll"
            $<TARGET_FILE_DIR:vpn_client_win>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "C:/Windows/System32/libcrypto-3-x64.dll"
            $<TARGET_FILE_DIR:vpn_client_win>

        # ← NEW: Copy wintun.dll
        COMMAND ${CMAKE_COMMAND} -E echo "Copying WinTun DLL..."
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/wintun.dll"
            $<TARGET_FILE_DIR:vpn_client_win>

        COMMENT "Copying required DLLs to output directory"
    )
endif()

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(vpn_client_win)
endif()
