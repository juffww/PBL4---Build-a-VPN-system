cmake_minimum_required(VERSION 3.16)
project(VPNProject VERSION 1.0.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)

# Platform-specific settings
if(WIN32)
    set(PLATFORM_LIBS ws2_32)
    add_definitions(-D_WIN32_WINNT=0x0601)
else()
    set(PLATFORM_LIBS)
endif()

# Create directory structure
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB_RECURSE SERVER_SOURCES
    src/core/*.cpp
    src/network/*.cpp
)

# VPN Server executable
# add_executable(vpn_server
#     main.cpp
#     src/core/vpn_server.cpp
#     src/core/vpn_server.h
# )

add_executable(vpn_server
    ${SERVER_SOURCES}
)

target_include_directories(vpn_server PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(vpn_server 
    Threads::Threads 
    ${PLATFORM_LIBS}
)

# Compiler-specific flags
if(MSVC)
    target_compile_options(vpn_server PRIVATE /W4)
else()
    target_compile_options(vpn_server PRIVATE -Wall -Wextra -O2)
endif()

# Qt Client (optional - only if Qt is available)
find_package(Qt6 COMPONENTS Core Widgets Network QUIET)
if(Qt6_FOUND)
    message(STATUS "Qt6 found - building GUI client")
    
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    
    add_executable(vpn_client
        pbl4/main.cpp
        pbl4/mainwindow.cpp
        pbl4/mainwindow.h
    )
    
    target_link_libraries(vpn_client
        Qt6::Core
        Qt6::Widgets  
        Qt6::Network
    )
else()
    message(STATUS "Qt6 not found - skipping GUI client build")
endif()

# Install targets
install(TARGETS vpn_server 
    RUNTIME DESTINATION bin
)

if(Qt6_FOUND)
    install(TARGETS vpn_client
        RUNTIME DESTINATION bin
    )
endif()

# Print build information
message(STATUS "")
message(STATUS "=== VPN Project Build Configuration ===")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Qt6 available: ${Qt6_FOUND}")
message(STATUS "=====================================")
message(STATUS "")

# Thêm vào cuối file CMakeLists.txt
if(Qt6_FOUND)
    message(STATUS "Qt6 found - building GUI client")
    
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    
    add_executable(vpn_client
        client/main.cpp
        client/mainwindow.cpp
        client/mainwindow.h
        client/vpn_client.cpp
        client/vpn_client.h
    )
    
    target_link_libraries(vpn_client
        Qt6::Core
        Qt6::Widgets  
        Qt6::Network
    )
endif()