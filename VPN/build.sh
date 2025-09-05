#!/bin/bash
# build.sh - Build script for Linux/Mac

echo "==================================="
echo "    VPN Project Build Script      "
echo "==================================="

# Create directory structure
mkdir -p src/core
mkdir -p src/network
mkdir -p client 
mkdir -p build
mkdir -p bin

# Check if CMake is installed
if ! command -v cmake &> /dev/null; then
    echo "CMake is not installed. Please install CMake first."
    exit 1
fi

# Build with CMake
cd build

echo "Configuring project..."
cmake .. -DCMAKE_BUILD_TYPE=Release

if [ $? -eq 0 ]; then
    echo "Building project..."
    cmake --build . --config Release
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "==================================="
        echo "         Build Successful!         "
        echo "==================================="
        echo "Server executable: ./bin/vpn_server"
        if [ -f "./bin/vpn_client" ]; then
            echo "Client executable: ./bin/vpn_client"
        else
            echo "Qt client not built (Qt6 not found)"
        fi
        echo "==================================="
        echo ""
        echo "To run the server:"
        echo "  cd bin && ./vpn_server"
        echo ""
        echo "Server commands:"
        echo "  start [port]  - Start server (default port 1194)"
        echo "  stop          - Stop server"
        echo "  status        - Show server status"
        echo "  clients       - List connected clients"
        echo "  help          - Show help"
        echo "  quit          - Exit"
        echo ""
    else
        echo "Build failed!"
        exit 1
    fi
else
    echo "Configuration failed!"
    exit 1
fi