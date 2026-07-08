#!/bin/bash
# End-to-end demo script for OAuth 2.0 Token Exchange
# Usage: ./test-token-exchange.sh [stack-name] [region]
# Example: ./test-token-exchange.sh TokenExchangeCfn eu-west-1
# Example: ./test-token-exchange.sh TokenExchangeStack eu-west-1

set -e

STACK_NAME="${1:-TokenExchangeStack}"
REGION="${2:-eu-west-1}"
TEST_PASSWORD="TestPass123!"

echo "============================================"
echo "OAuth 2.0 Token Exchange - End-to-End Demo"
echo "============================================"
echo "Stack: $STACK_NAME"
echo "Region: $REGION"
echo ""
echo "This demo walks through the RFC 8693 OAuth 2.0"
echo "Token Exchange flow using Amazon Cognito."
echo ""
echo "Scenario: A global mobile app where users"
echo "authenticate with country-specific IdPs (e.g."
echo "Germany, Switzerland, Direct) and receive a"
echo "global identity token for cross-business-unit"
echo "access — without Cognito's 5-linked-identity limit."
echo ""
echo "--------------------------------------------"
echo "STEP 1: Retrieve Stack Configuration"
echo "--------------------------------------------"
echo ""
echo "We fetch the deployed resource IDs from"
echo "CloudFormation. In production, your app"
echo "would already know these endpoints."
echo ""
echo "📋 Fetching stack outputs..."
OUTPUTS=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query 'Stacks[0].Outputs' \
  --output json 2>&1)

if [[ $? -ne 0 ]]; then
  echo "❌ Failed to get stack outputs. Is the stack deployed?"
  echo "$OUTPUTS"
  exit 1
fi

# Extract values from outputs
get_output() {
  echo "$OUTPUTS" | jq -r ".[] | select(.OutputKey==\"$1\") | .OutputValue"
}

EXTERNAL_USER_POOL_ID=$(get_output "ExternalUserPoolId")
EXTERNAL_CLIENT_ID=$(get_output "ExternalUserPoolClientId")
TOKEN_EXCHANGE_ENDPOINT=$(get_output "TokenExchangeEndpoint")
SSM_PARAMETER=$(get_output "SSMParameterName")

echo "  Country IdP User Pool:    $EXTERNAL_USER_POOL_ID"
echo "  Country IdP Client ID:    $EXTERNAL_CLIENT_ID"
echo "  Token Exchange Endpoint:  $TOKEN_EXCHANGE_ENDPOINT"
echo "  SSM Parameter:            $SSM_PARAMETER"
echo ""
echo "  ℹ️  The Country IdP User Pool represents a local"
echo "     identity provider (e.g. Example Insurance) where"
echo "     users authenticate with country-specific credentials."
echo ""
echo "     The Token Exchange Endpoint converts that local"
echo "     token into a Global Identity token."
echo ""
echo "--------------------------------------------"
echo "STEP 2: Retrieve Service Client Credentials"
echo "--------------------------------------------"
echo ""
echo "The service client represents the global mobile"
echo "app. Its credentials are stored securely in AWS"
echo "Systems Manager Parameter Store."
echo ""
echo "In production, only the mobile app backend would"
echo "have access — they prove the app is authorized"
echo "to perform token exchanges."
echo ""
echo "🔑 Fetching service credentials from SSM..."
CREDS=$(aws ssm get-parameter \
  --name "$SSM_PARAMETER" \
  --region "$REGION" \
  --query 'Parameter.Value' \
  --output text)

SERVICE_CLIENT_ID=$(echo "$CREDS" | jq -r '.clientId')
SERVICE_CLIENT_SECRET=$(echo "$CREDS" | jq -r '.clientSecret')
echo "  Service Client ID: $SERVICE_CLIENT_ID"
echo ""
echo "--------------------------------------------"
echo "STEP 3: Authenticate with Country IdP"
echo "--------------------------------------------"
echo ""
echo "This simulates a user logging into their local"
echo "country app (e.g. Example Insurance). In production"
echo "this would be a browser/mobile OAuth flow, and"
echo "could include social login (Google, etc.)."
echo ""
echo "The user authenticates with the Country IdP and"
echo "receives an access token — this is the local"
echo "'subject token' that will be exchanged for a"
echo "global identity token."
echo ""
echo "  ℹ️  In this demo, the Country IdP is a standard"
echo "     Cognito User Pool issuing RFC 7519 JWTs."
echo ""
echo "     BUT — the token exchange architecture does NOT"
echo "     require a standard IdP or standard JWTs."
echo ""
echo "     If a country unit has a non-standard or legacy"
echo "     auth system, the VerifyAuthChallenge Lambda is"
echo "     the extensibility point. You control the"
echo "     verification logic entirely."
echo "     We'll look at this in detail after the exchange."
echo ""

# Set password for test user (in case it's not set)
echo "👤 Setting up test user..."
aws cognito-idp admin-set-user-password \
  --user-pool-id "$EXTERNAL_USER_POOL_ID" \
  --username "testuser@example.com" \
  --password "$TEST_PASSWORD" \
  --permanent \
  --region "$REGION" 2>/dev/null || true
echo "  Test user ready: testuser@example.com"
echo ""

# Get user token from country IDP
echo "🎫 Authenticating user with Country IdP..."
USER_TOKEN=$(aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id "$EXTERNAL_CLIENT_ID" \
  --auth-parameters "USERNAME=testuser@example.com,PASSWORD=$TEST_PASSWORD" \
  --region "$REGION" \
  --query 'AuthenticationResult.AccessToken' \
  --output text)

if [[ -z "$USER_TOKEN" || "$USER_TOKEN" == "None" ]]; then
  echo "❌ Failed to get user token"
  exit 1
fi
echo "  ✅ Country IdP token obtained (${#USER_TOKEN} chars)"
echo ""

# Decode and show the ORIGINAL token claims for comparison
echo "📝 Country IdP token claims (before exchange):"
ORIG_PAYLOAD=$(echo "$USER_TOKEN" | cut -d'.' -f2 | tr '_-' '/+')
# Fix base64 padding
ORIG_PAD_LEN=$((4 - ${#ORIG_PAYLOAD} % 4))
if [[ $ORIG_PAD_LEN -lt 4 ]]; then
  ORIG_PADDED="${ORIG_PAYLOAD}$(printf '=%.0s' $(seq 1 $ORIG_PAD_LEN))"
else
  ORIG_PADDED="$ORIG_PAYLOAD"
fi
echo "$ORIG_PADDED" | base64 -d 2>/dev/null | jq '{
  sub: .sub,
  iss: .iss,
  client_id: .client_id,
  token_use: .token_use,
  scope: .scope,
  exp: .exp
}' 2>/dev/null || echo "(Could not decode token)"
echo ""
echo "  ℹ️  This token is scoped to the Country IdP only."
echo "     It has no global identity claims and can't be"
echo "     used across business units."
echo ""
echo "--------------------------------------------"
echo "STEP 4: Exchange for Global Identity Token"
echo "         (RFC 8693 Token Exchange)"
echo "--------------------------------------------"
echo ""
echo "The mobile app backend calls the token exchange"
echo "endpoint to convert the country-specific token"
echo "into a global identity token."
echo ""
echo "It sends:"
echo "  • The country IdP token (subject_token)"
echo "  • The app's credentials (Basic auth header)"
echo "  • The RFC 8693 grant type"
echo ""
echo "Behind the scenes, the endpoint will:"
echo "  1. Validate the app's service credentials"
echo "  2. Cryptographically verify the country token"
echo "     against the Country IdP"
echo "  3. Issue a global token via the Global Identity Pool"
echo "  4. Embed the local user identity as custom claims"
echo "  5. Apply global scopes (least privilege)"
echo ""
echo "  ℹ️  This bypasses Cognito's 5-linked-identity limit."
echo "     The linking is logical (via claims), not a native"
echo "     Cognito federation link."
echo ""

# Create Basic auth header
AUTH_HEADER=$(echo -n "${SERVICE_CLIENT_ID}:${SERVICE_CLIENT_SECRET}" | base64 | tr -d '\n')

# Perform token exchange
echo "🔄 Performing token exchange..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TOKEN_EXCHANGE_ENDPOINT" \
  -H "Authorization: Basic ${AUTH_HEADER}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=${USER_TOKEN}&subject_token_type=urn:ietf:params:oauth:token-type:access_token")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "  HTTP Status: $HTTP_CODE"
echo ""

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "✅ Token exchange successful!"
  echo ""
  echo "Response (RFC 8693 format):"
  echo "$BODY" | jq .
  
  # Decode and show the new token claims
  NEW_TOKEN=$(echo "$BODY" | jq -r '.access_token')
  if [[ -n "$NEW_TOKEN" && "$NEW_TOKEN" != "null" ]]; then
    echo ""
    echo "--------------------------------------------"
    echo "STEP 5: Verification Extensibility"
    echo "        (Non-Standard IdP / Token Support)"
    echo "--------------------------------------------"
    echo ""
    echo "Key point: not all country IdPs may be standard."
    echo "A legacy auth system or non-compliant IdP can"
    echo "still participate in this flow."
    echo ""
    echo "The VerifyAuthChallenge Lambda is where token"
    echo "verification happens. In this demo, it uses"
    echo "aws-jwt-verify for standard Cognito JWTs:"
    echo ""
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │ CURRENT: Standard JWT Verification       │"
    echo "  │                                          │"
    echo "  │  const verifier = CognitoJwtVerifier     │"
    echo "  │    .create({                             │"
    echo "  │      userPoolId: COUNTRY_IDP_POOL_ID,    │"
    echo "  │      tokenUse: 'access',                 │"
    echo "  │      clientId: COUNTRY_CLIENT_ID         │"
    echo "  │    });                                   │"
    echo "  │                                          │"
    echo "  │  payload = await verifier.verify(token); │"
    echo "  │  answerCorrect = true;                   │"
    echo "  └─────────────────────────────────────────┘"
    echo ""
    echo "  But you have FULL CONTROL over this Lambda."
    echo "  You can replace it with ANY verification logic:"
    echo ""
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │ OPTION A: Call country's verification    │"
    echo "  │           API endpoint                   │"
    echo "  │                                          │"
    echo "  │  // Country unit exposes /verify endpoint│"
    echo "  │  const resp = await fetch(               │"
    echo "  │    COUNTRY_VERIFY_URL,                   │"
    echo "  │    { headers: { token: subjectToken } }  │"
    echo "  │  );                                      │"
    echo "  │  answerCorrect = resp.ok;                │"
    echo "  └─────────────────────────────────────────┘"
    echo ""
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │ OPTION B: Verify with a shared secret    │"
    echo "  │           or public key (HMAC/RSA)       │"
    echo "  │                                          │"
    echo "  │  // Country provides their signing key   │"
    echo "  │  const key = await getKeyFromSecrets();  │"
    echo "  │  const decoded = jwt.verify(token, key); │"
    echo "  │  answerCorrect = !!decoded;              │"
    echo "  └─────────────────────────────────────────┘"
    echo ""
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │ OPTION C: Custom token format            │"
    echo "  │           (not even a JWT)               │"
    echo "  │                                          │"
    echo "  │  // Parse proprietary token format       │"
    echo "  │  const parsed = parseCustomToken(token); │"
    echo "  │  // Validate signature, expiry, etc.     │"
    echo "  │  answerCorrect = isValid(parsed);        │"
    echo "  └─────────────────────────────────────────┘"
    echo ""
    echo "  The rest of the flow stays exactly the same."
    echo "  Once answerCorrect = true, Cognito issues a"
    echo "  global identity token regardless of how the"
    echo "  country token was verified."
    echo ""
    echo "  This means:"
    echo "  • Standard country IdP? → Works out of the box"
    echo "  • Legacy/non-standard auth? → Customize the Lambda"
    echo "  • Need to call an external API? → Do it in the Lambda"
    echo "  • The output is ALWAYS a standard Cognito JWT"
    echo "    from the Global Identity Pool"
    echo ""
    echo "--------------------------------------------"
    echo "STEP 6: Inspect the Global Identity Token"
    echo "--------------------------------------------"
    echo ""
    echo "Let's decode the global token and look at the"
    echo "claims. The token now carries the global identity"
    echo "AND a link back to the country-specific user."
    echo ""
    echo "📝 Global Identity token claims:"
    # Add padding if needed and decode (works on both macOS and Linux)
    PAYLOAD=$(echo "$NEW_TOKEN" | cut -d'.' -f2 | tr '_-' '/+')
    PAD_MOD=$((${#PAYLOAD} % 4))
    if [[ $PAD_MOD -ne 0 ]]; then
      PADDED="${PAYLOAD}$(printf '=%.0s' $(seq 1 $((4 - PAD_MOD))))"
    else
      PADDED="$PAYLOAD"
    fi
    echo "$PADDED" | base64 -d 2>/dev/null | jq . 2>/dev/null || \
    echo "$PADDED" | base64 -D 2>/dev/null | jq . 2>/dev/null || \
    echo "(Could not decode token)"
    echo ""
    echo "--------------------------------------------"
    echo "Key Observations (N:1 Identity Mapping)"
    echo "--------------------------------------------"
    echo ""
    echo "🌍 LOCAL → GLOBAL IDENTITY MAPPING:"
    CLAIMS=$(echo "$PADDED" | base64 -d 2>/dev/null | jq -r '
      "   local_user_sub:    " + (."custom:original_sub" // "N/A"),
      "   local_username:    " + (."custom:original_username" // "N/A"),
      "   country_idp:       " + (."custom:original_iss" // "N/A"),
      "   global_identity:   " + (.sub // "N/A")
    ' 2>/dev/null)
    echo "$CLAIMS"
    echo ""
    echo "🔐 GLOBAL TOKEN CONTEXT:"
    SVC_CLAIMS=$(echo "$PADDED" | base64 -d 2>/dev/null | jq -r '
      "   token_exchange:    " + (."custom:token_exchange" // "N/A"),
      "   global_scopes:     " + (."custom:service_scopes" // "N/A"),
      "   global_issuer:     " + (.iss // "N/A")
    ' 2>/dev/null)
    echo "$SVC_CLAIMS"
    echo ""
    echo "📋 GLOBAL SCOPES (least privilege):"
    SCOPES=$(echo "$PADDED" | base64 -d 2>/dev/null | jq -r '.scope // "N/A"' 2>/dev/null)
    echo "   $SCOPES"
    echo ""
    echo "  ℹ️  The country-specific scope has been replaced"
    echo "     with global scopes. The global token can be"
    echo "     used across all business units."
    echo ""
    echo "  ℹ️  Multiple country identities (Germany, Swiss,"
    echo "     Direct) can all map to the SAME global identity."
    echo "     No Cognito linked-identity limit applies — the"
    echo "     mapping is logical, stored in claims or DynamoDB."
  fi
else
  echo "❌ Token exchange failed!"
  echo ""
  echo "Response:"
  echo "$BODY" | jq . 2>/dev/null || echo "$BODY"
  exit 1
fi

echo ""
echo "============================================"
echo "Demo complete!"
echo "============================================"
echo ""
echo "Summary:"
echo "  • User authenticated with Country IdP"
echo "  • Country token exchanged for Global Identity token"
echo "  • Global token carries local user identity as claims"
echo "  • N:1 mapping: many country identities → one global"
echo "  • No 5-linked-identity limit (logical linking)"
echo "  • Non-standard country IdPs supported via Lambda"
echo "============================================"
