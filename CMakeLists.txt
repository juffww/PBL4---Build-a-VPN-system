cmake_minimum_required(VERSION 3.16)
project(vpn_client_win VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network)

# ====== THÊM OPENSSL ======
if(WIN32)
    # Set OpenSSL root directory
    # set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    set(OPENSSL_ROOT_DIR "C:/Progra~1/OpenSSL-Win64")
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")

    # Find OpenSSL libraries
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
        message(FATAL_ERROR "OpenSSL libraries not found! Please install OpenSSL 3.6.0 (64-bit)")
    endif()

    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL SSL: ${OPENSSL_SSL_LIBRARY}")
    message(STATUS "OpenSSL Crypto: ${OPENSSL_CRYPTO_LIBRARY}")
else()
    find_package(OpenSSL REQUIRED)
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_SSL_LIBRARY})
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_CRYPTO_LIBRARY})
endif()
# ==========================

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
    logo.ico
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(vpn_client_win
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        app.rc
    )
else()
    if(ANDROID)
        add_library(vpn_client_win SHARED ${PROJECT_SOURCES})
    else()
        add_executable(vpn_client_win ${PROJECT_SOURCES})
    endif()
endif()

# ====== LINK LIBRARIES ======
target_link_libraries(vpn_client_win PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
)

# Add OpenSSL include directories
target_include_directories(vpn_client_win PRIVATE ${OPENSSL_INCLUDE_DIR})

# Windows-specific configuration
if(WIN32)
    target_link_libraries(vpn_client_win PRIVATE
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        iphlpapi
        ws2_32
        Advapi32
        crypt32
    )

    # Add Windows definitions
    target_compile_definitions(vpn_client_win PRIVATE
        _WIN32
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )

    # Request administrator privileges
    if(MSVC)
        set_target_properties(vpn_client_win PROPERTIES
            LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
        )
        # Add Windows subsystem flag
        set_target_properties(vpn_client_win PROPERTIES
            WIN32_EXECUTABLE TRUE
        )
        # Set runtime library to MultiThreadedDLL
        set_property(TARGET vpn_client_win PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    elseif(MINGW)
        # For MinGW, embed manifest for admin rights
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--subsystem,windows")
        # Create manifest file
        file(WRITE "${CMAKE_BINARY_DIR}/vpn_client_win.exe.manifest"
"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">
  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>")
    endif()
else()
    # macOS/Linux OpenSSL linking
    target_link_libraries(vpn_client_win PRIVATE
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
    )
endif()
# ============================

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
if(${QT_VERSION} VERSION_LESS 6.1.0)
    set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.vpn_client_win)
endif()

set_target_properties(vpn_client_win PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS vpn_client_win
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install OpenSSL DLLs on Windows
if(WIN32)
    # Find and install OpenSSL DLLs
    find_file(OPENSSL_SSL_DLL
        NAMES libssl-3-x64.dll
        PATHS "C:/Windows/System32" "${OPENSSL_ROOT_DIR}/bin"
        NO_DEFAULT_PATH
    )

    find_file(OPENSSL_CRYPTO_DLL
        NAMES libcrypto-3-x64.dll
        PATHS "C:/Windows/System32" "${OPENSSL_ROOT_DIR}/bin"
        NO_DEFAULT_PATH
    )

    if(OPENSSL_SSL_DLL AND OPENSSL_CRYPTO_DLL)
        install(FILES ${OPENSSL_SSL_DLL} ${OPENSSL_CRYPTO_DLL}
            DESTINATION ${CMAKE_INSTALL_BINDIR})
        message(STATUS "OpenSSL DLLs will be installed")
    else()
        message(WARNING "OpenSSL DLLs not found - you may need to copy them manually")
    endif()

    # Install config file
    if(EXISTS "${CMAKE_SOURCE_DIR}/win_config.ini")
        install(FILES win_config.ini DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endif()

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(vpn_client_win)
endif()

# ====== POST-BUILD: Copy OpenSSL DLLs to build directory ======
if(WIN32)
    add_custom_command(TARGET vpn_client_win POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Copying OpenSSL DLLs..."
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "C:/Windows/System32/libssl-3-x64.dll"
            $<TARGET_FILE_DIR:vpn_client_win>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "C:/Windows/System32/libcrypto-3-x64.dll"
            $<TARGET_FILE_DIR:vpn_client_win>
        COMMENT "Copying OpenSSL DLLs to output directory"
    )
endif()
# =======================================
