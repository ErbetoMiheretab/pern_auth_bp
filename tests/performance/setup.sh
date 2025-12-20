#!/bin/bash

# Performance Test Setup Script
# This script prepares the environment for running performance tests

set -e  # Exit on error

echo "================================================"
echo "  Performance Test Environment Setup"
echo "================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_URL="${API_URL:-http://localhost:4000}"
TEST_USER_EMAIL="test@example.com"
TEST_USER_PASSWORD="Password123!"
TEST_USER_USERNAME="testuser"

# Function to check if service is running
check_service() {
    local service=$1
    local port=$2
    
    if nc -z localhost $port 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $service is running on port $port"
        return 0
    else
        echo -e "${RED}✗${NC} $service is NOT running on port $port"
        return 1
    fi
}

# Function to wait for service
wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    echo "Waiting for $service to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if nc -z localhost $port 2>/dev/null; then
            echo -e "${GREEN}✓${NC} $service is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 1
        attempt=$((attempt + 1))
    done
    
    echo -e "\n${RED}✗${NC} $service failed to start within ${max_attempts} seconds"
    return 1
}

echo "Step 1: Checking prerequisites..."
echo "-----------------------------------"

# Check if Artillery is installed
if command -v artillery &> /dev/null; then
    echo -e "${GREEN}✓${NC} Artillery is installed ($(artillery version))"
else
    echo -e "${YELLOW}!${NC} Artillery is not installed"
    echo "  Installing Artillery globally..."
    npm install -g artillery
fi

# Check if netcat is available
if ! command -v nc &> /dev/null; then
    echo -e "${YELLOW}!${NC} netcat (nc) is not installed. Service checks will be skipped."
    echo "  Install with: sudo apt-get install netcat  (Ubuntu/Debian)"
fi

echo ""
echo "Step 2: Checking services..."
echo "-----------------------------------"

# Check PostgreSQL
if check_service "PostgreSQL" 5432 || check_service "PostgreSQL" 5549; then
    :
else
    echo -e "${YELLOW}!${NC} PostgreSQL not detected. Make sure it's running on port 5432 or 5549"
    echo "  Start with: docker-compose up -d postgres"
fi

# Check Redis
if check_service "Redis" 6379 || check_service "Redis" 6381; then
    :
else
    echo -e "${YELLOW}!${NC} Redis not detected. Make sure it's running on port 6379 or 6381"
    echo "  Start with: docker-compose up -d redis"
fi

# Check Application
if check_service "Application API" 4000; then
    :
else
    echo -e "${YELLOW}!${NC} Application API not detected on port 4000"
    echo "  Start with: npm run dev"
    echo ""
    read -p "Would you like to wait for the API to start? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        wait_for_service "Application API" 4000
    else
        echo -e "${RED}Cannot proceed without the API running${NC}"
        exit 1
    fi
fi

echo ""
echo "Step 3: Creating test user..."
echo "-----------------------------------"

# Check if test user already exists by trying to login
echo "Checking if test user exists..."
LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEST_USER_EMAIL\",\"password\":\"$TEST_USER_PASSWORD\"}" 2>/dev/null || echo "000")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n 1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}✓${NC} Test user already exists and credentials are correct"
else
    echo "Test user does not exist or credentials are wrong. Creating..."
    
    # Create test user
    REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/auth/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$TEST_USER_USERNAME\",\"email\":\"$TEST_USER_EMAIL\",\"password\":\"$TEST_USER_PASSWORD\"}" 2>/dev/null || echo "000")
    
    REG_HTTP_CODE=$(echo "$REGISTER_RESPONSE" | tail -n 1)
    
    if [ "$REG_HTTP_CODE" = "201" ]; then
        echo -e "${GREEN}✓${NC} Test user created successfully"
    elif [ "$REG_HTTP_CODE" = "409" ]; then
        echo -e "${YELLOW}!${NC} User already exists but password might be different"
        echo "  Please ensure the test user has password: $TEST_USER_PASSWORD"
    else
        echo -e "${RED}✗${NC} Failed to create test user (HTTP $REG_HTTP_CODE)"
        echo "  Response: $(echo "$REGISTER_RESPONSE" | head -n -1)"
        exit 1
    fi
fi

echo ""
echo "Step 4: Verifying test user..."
echo "-----------------------------------"

# Try to login again to verify
VERIFY_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEST_USER_EMAIL\",\"password\":\"$TEST_USER_PASSWORD\"}" 2>/dev/null || echo "000")

VERIFY_CODE=$(echo "$VERIFY_RESPONSE" | tail -n 1)

if [ "$VERIFY_CODE" = "200" ]; then
    echo -e "${GREEN}✓${NC} Test user verification successful"
else
    echo -e "${RED}✗${NC} Test user verification failed (HTTP $VERIFY_CODE)"
    exit 1
fi

echo ""
echo "Step 5: Environment summary..."
echo "-----------------------------------"
echo "API URL:       $API_URL"
echo "Test User:     $TEST_USER_EMAIL"
echo "Test Password: $TEST_USER_PASSWORD"

echo ""
echo "================================================"
echo -e "${GREEN}  Setup Complete!${NC}"
echo "================================================"
echo ""
echo "You can now run performance tests:"
echo ""
echo "  # Quick test (30 seconds, low load)"
echo "  artillery quick --duration 30 --rate 10 $API_URL/api/auth/login"
echo ""
echo "  # Full test suite"
echo "  artillery run tests/performance/auth.yml"
echo ""
echo "  # Generate HTML report"
echo "  artillery run tests/performance/auth.yml --output results.json"
echo "  artillery report results.json"
echo ""
echo "  # Test against staging"
echo "  artillery run -e staging tests/performance/auth.yml"
echo ""
