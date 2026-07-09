#!/bin/bash
# End-to-end test matrix for the OAuth 2.0 Token Exchange sample.
# Exercises the COMPLETE deployed flow (real Cognito auth + real HTTPS exchange +
# real JWT decode) across happy and non-happy paths, asserting each outcome.
#
# Usage: ./e2e-test-matrix.sh [stack-name] [region]
#   e.g. ./e2e-test-matrix.sh TokenExchangeStack us-east-1
#
# Exit code 0 = all assertions passed; non-zero = at least one failed.
set -uo pipefail

STACK_NAME="${1:-TokenExchangeStack}"
REGION="${2:-us-east-1}"
TEST_PASSWORD="TestPass123!"
PASS=0; FAIL=0

ok()   { echo "  ✅ PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  ❌ FAIL: $1"; FAIL=$((FAIL+1)); }
assert_eq()   { if [[ "$2" == "$3" ]]; then ok "$1 ($2)"; else bad "$1 (expected '$3', got '$2')"; fi; }
assert_has()  { if echo "$2" | grep -q -- "$3"; then ok "$1"; else bad "$1 (missing '$3' in: $2)"; fi; }
assert_absent(){ if echo "$2" | grep -q -- "$3"; then bad "$1 (found '$3')"; else ok "$1"; fi; }

echo "=== Config: stack=$STACK_NAME region=$REGION ==="
OUT=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" --query 'Stacks[0].Outputs' --output json)
get(){ echo "$OUT" | jq -r ".[] | select(.OutputKey==\"$1\") | .OutputValue"; }
EP=$(get TokenExchangeEndpoint); EXT_CLIENT=$(get ExternalUserPoolClientId)
EXT_POOL=$(get ExternalUserPoolId); SSM=$(get SSMParameterName)

# --- SecureString assertion ---
PTYPE=$(aws ssm describe-parameters --region "$REGION" --parameter-filters "Key=Name,Values=$SSM" --query 'Parameters[0].Type' --output text)
assert_eq "SSM parameter is SecureString" "$PTYPE" "SecureString"

CREDS=$(aws ssm get-parameter --name "$SSM" --with-decryption --region "$REGION" --query 'Parameter.Value' --output text)
CID=$(echo "$CREDS" | jq -r .clientId); SEC=$(echo "$CREDS" | jq -r .clientSecret)
AUTH=$(echo -n "$CID:$SEC" | base64 | tr -d '\n')

aws cognito-idp admin-set-user-password --user-pool-id "$EXT_POOL" --username testuser@example.com \
  --password "$TEST_PASSWORD" --permanent --region "$REGION" >/dev/null 2>&1 || true
UT=$(aws cognito-idp initiate-auth --auth-flow USER_PASSWORD_AUTH --client-id "$EXT_CLIENT" \
  --auth-parameters "USERNAME=testuser@example.com,PASSWORD=$TEST_PASSWORD" --region "$REGION" \
  --query 'AuthenticationResult.AccessToken' --output text)
[[ -n "$UT" && "$UT" != "None" ]] && ok "Obtained user (subject) token" || bad "Could not obtain user token"

# Helpers to call the endpoint
GT="urn:ietf:params:oauth:grant-type:token-exchange"
STT="urn:ietf:params:oauth:token-type:access_token"
exchange(){ # $1 auth header, $2 body -> prints "HTTP\nbody"
  curl -s -w "\n%{http_code}" -X POST "$EP" -H "Authorization: Basic $1" \
    -H "Content-Type: application/x-www-form-urlencoded" -d "$2"; }
jwt_claim(){ echo "$1" | cut -d. -f2 | tr '_-' '/+' | sed 's/$/===/' | base64 -d 2>/dev/null | jq -r "$2"; }

echo; echo "=== HAPPY PATH ==="
# H1: default exchange (no requested scope) -> full ceiling + delegation claims
R=$(exchange "$AUTH" "grant_type=$GT&subject_token=$UT&subject_token_type=$STT")
CODE=$(echo "$R" | tail -1); BODY=$(echo "$R" | sed '$d')
assert_eq "H1 default exchange returns 200" "$CODE" "200"
TK=$(echo "$BODY" | jq -r .access_token)
assert_eq "H1 issued_token_type" "$(echo "$BODY" | jq -r .issued_token_type)" "$STT"
assert_eq "H1 token_type Bearer" "$(echo "$BODY" | jq -r .token_type)" "Bearer"
SUBJ_SUB=$(jwt_claim "$UT" .sub); EX_SUB=$(jwt_claim "$TK" .sub); EX_OSUB=$(jwt_claim "$TK" '."custom:original_sub"')
assert_eq "H1 delegation: original_sub == user sub" "$EX_OSUB" "$SUBJ_SUB"
if [[ "$EX_SUB" != "$SUBJ_SUB" ]]; then ok "H1 delegation: exchanged sub is the SERVICE (not the user)"; else bad "H1 exchanged sub equals user sub (impersonation, not delegation)"; fi
assert_eq "H1 token_exchange claim" "$(jwt_claim "$TK" '."custom:token_exchange"')" "true"
assert_has "H1 full ceiling scopes granted" "$(jwt_claim "$TK" .scope)" "access:downstream-apis"

# H2: valid single-scope down-scope
R=$(exchange "$AUTH" "grant_type=$GT&subject_token=$UT&subject_token_type=$STT&scope=read:user-profile")
CODE=$(echo "$R" | tail -1); TK=$(echo "$R" | sed '$d' | jq -r .access_token)
assert_eq "H2 down-scope returns 200" "$CODE" "200"
assert_eq "H2 exchanged scope == requested subset" "$(jwt_claim "$TK" .scope)" "read:user-profile"

# H3: valid multi-scope subset
R=$(exchange "$AUTH" "grant_type=$GT&subject_token=$UT&subject_token_type=$STT&scope=read:user-profile write:audit-logs")
CODE=$(echo "$R" | tail -1); TK=$(echo "$R" | sed '$d' | jq -r .access_token)
assert_eq "H3 multi-scope subset returns 200" "$CODE" "200"
SC=$(jwt_claim "$TK" .scope)
assert_has "H3 contains read:user-profile" "$SC" "read:user-profile"
assert_has "H3 contains write:audit-logs" "$SC" "write:audit-logs"
assert_absent "H3 does NOT contain non-requested scope" "$SC" "access:downstream-apis"

echo; echo "=== NON-HAPPY PATH ==="
# N1: requested scope beyond ceiling -> 400 invalid_scope
R=$(exchange "$AUTH" "grant_type=$GT&subject_token=$UT&subject_token_type=$STT&scope=admin:everything")
assert_eq "N1 over-request rejected 400" "$(echo "$R" | tail -1)" "400"
assert_has "N1 error=invalid_scope" "$(echo "$R" | sed '$d')" "invalid_scope"

# N2: mix of valid + invalid scope -> 400 invalid_scope
R=$(exchange "$AUTH" "grant_type=$GT&subject_token=$UT&subject_token_type=$STT&scope=read:user-profile admin:everything")
assert_eq "N2 partial-invalid rejected 400" "$(echo "$R" | tail -1)" "400"
assert_has "N2 error=invalid_scope" "$(echo "$R" | sed '$d')" "invalid_scope"

# N3: garbage subject token -> 401 invalid_grant (fail closed)
R=$(exchange "$AUTH" "grant_type=$GT&subject_token=not.a.jwt&subject_token_type=$STT")
assert_eq "N3 invalid token fails closed 401" "$(echo "$R" | tail -1)" "401"
assert_has "N3 error=invalid_grant" "$(echo "$R" | sed '$d')" "invalid_grant"

# N4: missing/invalid grant_type -> 400
R=$(exchange "$AUTH" "grant_type=client_credentials&subject_token=$UT&subject_token_type=$STT")
assert_eq "N4 bad grant_type rejected 400" "$(echo "$R" | tail -1)" "400"

# N5: bad client secret -> 403 (authorizer deny, constant-time compare)
BADAUTH=$(echo -n "$CID:wrongsecret" | base64 | tr -d '\n')
R=$(exchange "$BADAUTH" "grant_type=$GT&subject_token=$UT&subject_token_type=$STT")
assert_eq "N5 bad client secret denied 403" "$(echo "$R" | tail -1)" "403"

# N6: no Authorization header -> 401 (API Gateway rejects the missing identity
# source BEFORE invoking the custom authorizer; a present-but-wrong header -> 403)
R=$(curl -s -w "\n%{http_code}" -X POST "$EP" -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=$GT&subject_token=$UT&subject_token_type=$STT")
assert_eq "N6 missing auth header rejected 401 (pre-authorizer)" "$(echo "$R" | tail -1)" "401"

echo; echo "============================================"
echo "RESULT: $PASS passed, $FAIL failed"
echo "============================================"
[[ $FAIL -eq 0 ]] || exit 1
