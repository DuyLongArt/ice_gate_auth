#!/bin/bash

# Configuration
BASE_URL=${1:-"https://passkey.duylong.art"}
EMAIL="duylongmind432001@gmail.com"
USER_ID="550e8400-e29b-411d-a716-446655440000"

echo "🚀 Testing Ice Gate Passkey Hub at $BASE_URL"
echo "------------------------------------------------"

# 1. Health Check
echo "🔍 Testing Health Check..."
res=$(curl -s "$BASE_URL/health")
echo "$res" | json_pp 2>/dev/null || echo "$res"
echo -e "\n"

# 2. Begin Registration
echo "🔑 Testing Begin Registration..."
res=$(curl -s -X POST "$BASE_URL/v1/register/begin" \
     -H "Content-Type: application/json" \
     -d "{
           \"email\": \"$EMAIL\",
           \"user_id\": \"$USER_ID\"
         }")
echo "$res" | json_pp 2>/dev/null || echo "$res"
echo -e "\n"

# 3. Begin Login
echo "🔓 Testing Begin Login..."
res=$(curl -s -X POST "$BASE_URL/v1/login/begin" \
     -H "Content-Type: application/json" \
     -d "{
           \"email\": \"$EMAIL\"
         }")
echo "$res" | json_pp 2>/dev/null || echo "$res"
echo -e "\n"

echo "------------------------------------------------"
echo "✅ Mock requests sent."
echo "Note: 'finish' steps require real WebAuthn authenticator data and are usually handled by the Flutter client."
