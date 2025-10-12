cmake_minimum_required(VERSION 3.16)
project(vpn_client_win VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets Network)

set(PROJECT_SOURCES
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    tun_interface.h
    vpn_client.h
    vpn_client.cpp
    tun_interface_win.cpp
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(vpn_client_win
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}

    )
else()
    if(ANDROID)
        add_library(vpn_client_win SHARED ${PROJECT_SOURCES})
    else()
        add_executable(vpn_client_win ${PROJECT_SOURCES})
    endif()
endif()

target_link_libraries(vpn_client_win PRIVATE
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Network
)

# Windows-specific configuration
if(WIN32)
    target_link_libraries(vpn_client_win PRIVATE
        iphlpapi
        ws2_32
        Advapi32
    )

    # Request administrator privileges
    if(MSVC)
        set_target_properties(vpn_client_win PROPERTIES
            LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
        )
    elseif(MINGW)
        set_target_properties(vpn_client_win PROPERTIES
            LINK_FLAGS "-Wl,--subsystem,windows"
        )
    endif()
endif()

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

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(vpn_client_win)
endif()
