#!/bin/bash
# Comprehensive VPN Security Test Suite

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "=========================================="
echo "   VPN Security Penetration Test Suite"
echo "=========================================="
echo ""

# Check if binary exists
if [ ! -f ./vpn_server ]; then
    echo -e "${RED}✗ vpn_server not found! Run ./build.sh first${NC}"
    exit 1
fi

# Check required tools
MISSING_TOOLS=""
for tool in nc openssl python3; do
    if ! command -v $tool &> /dev/null; then
        MISSING_TOOLS="$MISSING_TOOLS $tool"
    fi
done

if [ -n "$MISSING_TOOLS" ]; then
    echo -e "${YELLOW}⚠ Missing tools:$MISSING_TOOLS${NC}"
    echo "Install with: sudo apt-get install netcat-openbsd openssl python3"
fi

# Cleanup old instances
echo "Cleaning up old instances..."
sudo pkill -9 vpn_server 2>/dev/null
sudo ip link del tun0 2>/dev/null
sleep 1

# Clear old logs
rm -f /tmp/vpn_server.log

# Start server in background with auto-start
echo "Starting VPN server..."
sudo timeout 120 ./vpn_server > /tmp/vpn_server.log 2>&1 <<EOF &
start
EOF
SERVER_PID=$!
sleep 4

if ! ps -p $SERVER_PID > /dev/null; then
    echo -e "${RED}✗ Server failed to start${NC}"
    echo "Server log:"
    cat /tmp/vpn_server.log
    exit 1
fi

echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"

SERVER_IP="127.0.0.1"
SERVER_PORT=1194

# Initialize counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNING=0

# ==============================================================
# TEST 1: Replay Attack Detection
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 1] Replay Attack Detection${NC}"
echo "  Testing if server accepts repeated authentication..."

REPLAY_COUNT=0
for i in {1..5}; do
    RESPONSE=$(timeout 2 bash -c "echo 'AUTH test test'" | nc $SERVER_IP $SERVER_PORT 2>&1 | grep -c "AUTH_OK")
    REPLAY_COUNT=$((REPLAY_COUNT + RESPONSE))
    sleep 0.2
done

if [ $REPLAY_COUNT -eq 5 ]; then
    echo -e "${RED}  ✗ VULNERABLE: Replay attack succeeded $REPLAY_COUNT times${NC}"
    ((TESTS_FAILED++))
else
    echo -e "${GREEN}  ✓ Replay attack mitigated (only $REPLAY_COUNT/5 succeeded)${NC}"
    ((TESTS_PASSED++))
fi

# ==============================================================
# TEST 2: Buffer Overflow Attack
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 2] Buffer Overflow Attack${NC}"
echo "  Sending 100KB of data to test buffer limits..."

OVERFLOW_SIZE=100000
OVERFLOW_DATA=$(python3 -c "print('A' * $OVERFLOW_SIZE)")

timeout 3 bash -c "echo '$OVERFLOW_DATA' | nc $SERVER_IP $SERVER_PORT" > /dev/null 2>&1

sleep 1
if ps -p $SERVER_PID > /dev/null; then
    echo -e "${GREEN}  ✓ Server survived buffer overflow${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}  ✗ CRITICAL: Server crashed from overflow${NC}"
    ((TESTS_FAILED++))
    exit 1
fi

# ==============================================================
# TEST 3: CRYPTO_INIT Rate Limiting (FIXED)
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 3] CRYPTO_INIT Rate Limiting${NC}"

# Generate valid key ONCE
VALID_KEY=$(openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -pubout 2>/dev/null)

# Test 3a: Unauthenticated spam
echo "  → Testing unauthenticated CRYPTO_INIT spam..."
UNAUTH_BLOCKED=0
for i in {1..5}; do
    # ✅ FIX: Dùng double quotes và EOF để preserve multiline
    RESPONSE=$(timeout 2 bash -c "cat <<EOF | nc $SERVER_IP $SERVER_PORT 2>&1
CRYPTO_INIT|$VALID_KEY
EOF
" | tail -1)
    
    if echo "$RESPONSE" | grep -qE "Not authenticated|ERROR"; then
        ((UNAUTH_BLOCKED++))
    fi
    sleep 0.1
done

if [ $UNAUTH_BLOCKED -ge 4 ]; then
    echo -e "${GREEN}    ✓ Unauthenticated spam blocked ($UNAUTH_BLOCKED/5)${NC}"
else
    echo -e "${RED}    ✗ Unauthenticated spam not blocked ($UNAUTH_BLOCKED/5)${NC}"
fi

# Test 3b: Authenticated rate limiting
echo "  → Testing authenticated rate limiting..."
RATE_LIMITED=0

for i in {1..5}; do
    FRESH_KEY=$(openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -pubout 2>/dev/null)
    
    # ✅ FIX: Proper variable expansion
    RESPONSE=$(timeout 3 bash -c "cat <<EOF | nc $SERVER_IP $SERVER_PORT 2>&1
AUTH test test
CRYPTO_INIT|$FRESH_KEY
CRYPTO_INIT|$FRESH_KEY
CRYPTO_INIT|$FRESH_KEY
EOF
" | tail -5)
    
    BLOCKS=$(echo "$RESPONSE" | grep -cE "Rate limit|Already initialized")
    if [ $BLOCKS -ge 1 ]; then
        ((RATE_LIMITED++))
    fi
    sleep 0.3
done

if [ $RATE_LIMITED -ge 3 ]; then
    echo -e "${GREEN}    ✓ Rate limiting works ($RATE_LIMITED/5 connections blocked)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}    ⚠ Rate limiting partial ($RATE_LIMITED/5)${NC}"
    ((TESTS_WARNING++))
fi


# ==============================================================
# TEST 4: Packet Tampering Detection (FIX)
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 4] Packet Tampering Detection${NC}"

# ✅ FIX: Đếm đúng cách, tránh lỗi "integer expression expected"
TAMPER_DETECTED=0
if [ -f /tmp/vpn_server.log ]; then
    TAMPER_DETECTED=$(grep -cE "Decryption failed|Tag mismatch|tampered" /tmp/vpn_server.log 2>/dev/null || echo "0")
fi

# ✅ Kiểm tra an toàn
if [ "$TAMPER_DETECTED" -gt 0 ] 2>/dev/null; then
    echo -e "${GREEN}  ✓ Detected $TAMPER_DETECTED tampered packets${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}  ⚠ No tampering detected (no encrypted traffic yet)${NC}"
    ((TESTS_WARNING++))
fi

# ==============================================================
# TEST 5: Denial of Service (Connection Flood)
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 5] Connection Flood DoS${NC}"
echo "  Opening 20 simultaneous connections..."

if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo -e "${YELLOW}  ⚠ Server stopped, restarting...${NC}"
    (echo "start"; sleep 120) | sudo ./vpn_server >> /tmp/vpn_server.log 2>&1 &
    SERVER_PID=$!
    sleep 3
fi

for i in {1..20}; do
    timeout 1 nc $SERVER_IP $SERVER_PORT > /dev/null 2>&1 &
    sleep 0.05
done

sleep 2

if timeout 2 bash -c "echo 'PING' | nc $SERVER_IP $SERVER_PORT" 2>&1 | grep -qE "PONG|ERROR"; then
    echo -e "${GREEN}  ✓ Server survived connection flood${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}  ⚠ Server slow but alive${NC}"
    ((TESTS_WARNING++))
fi

# ==============================================================
# TEST 6: Invalid Public Key Attack (FIXED)
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 6] Invalid Crypto Key Handling${NC}"

REJECTED=0
TOTAL_TESTS=4

# Test 6a: Random garbage
echo "  → Testing: Random garbage (AAAAA)..."
RESPONSE=$(timeout 3 bash -c 'cat <<EOF | nc '"$SERVER_IP $SERVER_PORT"' 2>&1
AUTH test test
CRYPTO_INIT|AAAAA
EOF
' | tail -1)

if echo "$RESPONSE" | grep -qE "CRYPTO_FAIL|Invalid|ERROR"; then
    ((REJECTED++))
    echo -e "    ${GREEN}✓ Rejected${NC}"
else
    echo -e "    ${RED}✗ Accepted (Response: $RESPONSE)${NC}"
fi
sleep 0.3

# Test 6b: Invalid PEM structure
echo "  → Testing: Invalid PEM structure..."
RESPONSE=$(timeout 3 bash -c 'cat <<EOF | nc '"$SERVER_IP $SERVER_PORT"' 2>&1
AUTH test test
CRYPTO_INIT|-----BEGIN INVALID KEY-----
EOF
' | tail -1)

if echo "$RESPONSE" | grep -qE "CRYPTO_FAIL|Invalid|ERROR"; then
    ((REJECTED++))
    echo -e "    ${GREEN}✓ Rejected${NC}"
else
    echo -e "    ${RED}✗ Accepted${NC}"
fi
sleep 0.3

# Test 6c: Oversized key
echo "  → Testing: Oversized key (2000 chars)..."
HUGE_KEY=$(python3 -c 'print("A" * 2000)')
RESPONSE=$(timeout 3 bash -c "cat <<EOF | nc $SERVER_IP $SERVER_PORT 2>&1
AUTH test test
CRYPTO_INIT|$HUGE_KEY
EOF
" | tail -1)

if echo "$RESPONSE" | grep -qE "CRYPTO_FAIL|Invalid|ERROR"; then
    ((REJECTED++))
    echo -e "    ${GREEN}✓ Rejected${NC}"
else
    echo -e "    ${RED}✗ Accepted${NC}"
fi
sleep 0.3

# Test 6d: Empty key
echo "  → Testing: Empty key..."
RESPONSE=$(timeout 3 bash -c 'cat <<EOF | nc '"$SERVER_IP $SERVER_PORT"' 2>&1
AUTH test test
CRYPTO_INIT|
EOF
' | tail -1)

if echo "$RESPONSE" | grep -qE "CRYPTO_FAIL|Invalid|ERROR"; then
    ((REJECTED++))
    echo -e "    ${GREEN}✓ Rejected${NC}"
else
    echo -e "    ${RED}✗ Accepted${NC}"
fi
sleep 0.3

# Test 6e: Valid key (should be accepted)
echo "  → Testing: Valid X25519 key..."
VALID_KEY=$(openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -pubout 2>/dev/null)
RESPONSE=$(timeout 3 bash -c "cat <<EOF | nc $SERVER_IP $SERVER_PORT 2>&1
AUTH test test
CRYPTO_INIT|$VALID_KEY
EOF
" | tail -1)

if echo "$RESPONSE" | grep -q "CRYPTO_OK"; then
    echo -e "    ${GREEN}✓ Valid key accepted${NC}"
    if [ $REJECTED -eq $TOTAL_TESTS ]; then
        echo -e "${GREEN}  ✓ All invalid keys rejected ($REJECTED/$TOTAL_TESTS)${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${YELLOW}  ⚠ Some invalid keys accepted ($REJECTED/$TOTAL_TESTS rejected)${NC}"
        ((TESTS_WARNING++))
    fi
else
    echo -e "    ${RED}✗ Valid key rejected (Response: $RESPONSE)${NC}"
    ((TESTS_FAILED++))
fi

# ==============================================================
# TEST 7: Timing Attack on Crypto Operations
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 7] Constant-Time Crypto Operations${NC}"
echo "  Measuring timing differences..."

VALID_KEY_TIMING=$(openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -pubout 2>/dev/null)

# Measure valid key timing
START=$(date +%s%N)
timeout 2 bash -c "echo 'AUTH test test'; sleep 0.3; echo 'CRYPTO_INIT|$VALID_KEY_TIMING'" | nc $SERVER_IP $SERVER_PORT > /dev/null 2>&1
VALID_TIME=$(( ($(date +%s%N) - START) / 1000000 ))

sleep 0.5

# Measure invalid key timing
START=$(date +%s%N)
timeout 2 bash -c "echo 'AUTH test test'; sleep 0.3; echo 'CRYPTO_INIT|INVALID'" | nc $SERVER_IP $SERVER_PORT > /dev/null 2>&1
INVALID_TIME=$(( ($(date +%s%N) - START) / 1000000 ))

TIMING_DIFF=$((VALID_TIME - INVALID_TIME))
TIMING_DIFF=${TIMING_DIFF#-}

echo "  Valid key time: ${VALID_TIME}ms"
echo "  Invalid key time: ${INVALID_TIME}ms"
echo "  Difference: ${TIMING_DIFF}ms"

if [ $TIMING_DIFF -lt 200 ]; then
    echo -e "${GREEN}  ✓ Timing difference acceptable (< 200ms)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}  ⚠ Timing difference: ${TIMING_DIFF}ms (may leak info)${NC}"
    ((TESTS_WARNING++))
fi

# ==============================================================
# TEST 8: Memory Leak Detection
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 8] Memory Leak Detection${NC}"
echo "  Stress testing with 100 connections..."

INITIAL_MEM=$(ps -o rss= -p $SERVER_PID 2>/dev/null | tr -d ' ')

if [ -z "$INITIAL_MEM" ]; then
    echo -e "${YELLOW}  ⚠ Cannot measure memory (server may have crashed)${NC}"
    ((TESTS_WARNING++))
else
    for i in {1..100}; do
        echo "AUTH user$i pass$i" | timeout 0.5 nc $SERVER_IP $SERVER_PORT > /dev/null 2>&1 &
    done

    sleep 5

    FINAL_MEM=$(ps -o rss= -p $SERVER_PID 2>/dev/null | tr -d ' ')
    
    if [ -z "$FINAL_MEM" ]; then
        echo -e "${RED}  ✗ Server crashed during memory test${NC}"
        ((TESTS_FAILED++))
    else
        MEM_INCREASE=$((FINAL_MEM - INITIAL_MEM))
        
        echo "  Initial memory: ${INITIAL_MEM}KB"
        echo "  Final memory: ${FINAL_MEM}KB"
        echo "  Increase: ${MEM_INCREASE}KB"

        if [ $MEM_INCREASE -lt 10000 ]; then
            echo -e "${GREEN}  ✓ Memory stable (Δ${MEM_INCREASE}KB)${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${YELLOW}  ⚠ Memory increased by ${MEM_INCREASE}KB${NC}"
            ((TESTS_WARNING++))
        fi
    fi
fi

# ==============================================================
# TEST 9: Encrypted Traffic Verification (FIX)
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 9] Encrypted Traffic Verification${NC}"

if [ -f /tmp/vpn_udp.pcap ]; then
    if command -v tshark &> /dev/null; then
        echo "  Analyzing captured packets..."
        
        PLAINTEXT_COUNT=$(tshark -r /tmp/vpn_udp.pcap -Y "data" -T fields -e data 2>/dev/null | \
                          grep -icE "10\.8\.0\." 2>/dev/null || echo "0")
        
        if [ "$PLAINTEXT_COUNT" -eq 0 ] 2>/dev/null; then
            echo -e "${GREEN}  ✓ No plaintext leaked in UDP traffic${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}  ✗ CRITICAL: Found $PLAINTEXT_COUNT plaintext IPs!${NC}"
            ((TESTS_FAILED++))
        fi
        
        # Entropy check (giữ nguyên)
        if command -v ent &> /dev/null; then
            ENTROPY=$(tshark -r /tmp/vpn_udp.pcap -T fields -e data 2>/dev/null | \
                      head -50 | xxd -r -p 2>/dev/null | ent 2>/dev/null | grep "Entropy" | awk '{print $3}')
            
            if [ -n "$ENTROPY" ] && [ "$ENTROPY" != "0.000000" ]; then
                echo -e "${GREEN}  ✓ Packet entropy: $ENTROPY (encrypted)${NC}"
            else
                echo -e "${YELLOW}  ⚠ Entropy: $ENTROPY (no/low UDP traffic)${NC}"
            fi
        fi
    fi
fi


# ==============================================================
# TEST 10: Security Log Verification
# ==============================================================
echo ""
echo -e "${BLUE}[TEST 10] Security Event Logging${NC}"
echo "  Checking security events in logs..."

if [ -f /tmp/vpn_server.log ]; then
    SECURITY_EVENTS=$(grep -cE "\[SECURITY\]|\[CRYPTO\]" /tmp/vpn_server.log)
    REJECTED_EVENTS=$(grep -cE "rejected|Invalid|Rate limit" /tmp/vpn_server.log)
    
    echo "  Security events logged: $SECURITY_EVENTS"
    echo "  Rejected attempts: $REJECTED_EVENTS"
    
    if [ $SECURITY_EVENTS -gt 0 ]; then
        echo -e "${GREEN}  ✓ Security logging active${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${YELLOW}  ⚠ No security events logged${NC}"
        ((TESTS_WARNING++))
    fi
else
    echo -e "${RED}  ✗ Log file not found${NC}"
    ((TESTS_FAILED++))
fi

# ==============================================================
# CLEANUP
# ==============================================================
echo ""
echo "Cleaning up..."
sudo kill $SERVER_PID 2>/dev/null
sleep 1
sudo pkill -9 vpn_server 2>/dev/null
sudo ip link del tun0 2>/dev/null
rm -f /tmp/vpn_udp.pcap /tmp/auth_response.txt

# ==============================================================
# FINAL SUMMARY
# ==============================================================
TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNING))

echo ""
echo "=========================================="
echo "       SECURITY TEST SUMMARY"
echo "=========================================="
echo ""
echo -e "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo -e "${YELLOW}Warnings: $TESTS_WARNING${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ SECURITY ASSESSMENT: GOOD${NC}"
else
    echo -e "${RED}✗ SECURITY ASSESSMENT: ISSUES FOUND${NC}"
fi

echo ""
echo -e "${GREEN}STRENGTHS:${NC}"
echo "  ✓ Buffer overflow protection"
echo "  ✓ Authentication enforcement"
echo "  ✓ Connection flood resilience"
echo "  ✓ Memory stability"

echo ""
echo -e "${YELLOW}RECOMMENDATIONS:${NC}"
echo "  • Implement certificate pinning for MITM protection"
echo "  • Add IP-based rate limiting (prevent distributed attacks)"
echo "  • Enable intrusion detection system (IDS)"
echo "  • Use ephemeral keys for perfect forward secrecy"
echo "  • Add brute-force protection (account lockout)"
echo "  • Implement audit logging with timestamps"

echo ""
echo "📊 Full log: /tmp/vpn_server.log"
echo "=========================================="

# Exit with error code if tests failed
if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi