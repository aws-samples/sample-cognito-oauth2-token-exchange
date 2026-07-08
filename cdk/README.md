# OAuth 2.0 Token Exchange - AWS CDK Implementation

This is the AWS CDK (TypeScript) implementation of the OAuth 2.0 Token Exchange solution using Amazon Cognito with SSM Parameter Store for credential management.

## Architecture

This CDK stack deploys:

- **External IDP User Pool**: Simulates an external identity provider
- **Token Exchange User Pool**: Target user pool for token exchange
- **Custom Auth Lambda Functions**: Define, Create, Verify auth challenges
- **Pre-Token Generation Lambda**: Adds delegation claims to tokens
- **Token Exchange Lambda**: Handles RFC 8693 token exchange requests
- **Authorizer Lambda**: Validates service client credentials via SSM
- **API Gateway**: REST API with custom authorizer
- **SSM Parameter Store**: Stores service client credentials (1000 TPS vs 15 RPS)
- **Custom Resource**: Automatically populates SSM with Cognito secrets

## Prerequisites

- Node.js 18+ and npm
- AWS CLI configured with appropriate credentials
- AWS CDK CLI installed globally: `npm install -g aws-cdk`
- JWT Verify Lambda Layer (see below)

## Setup

### 1. Install Dependencies

```bash
cd cdk
npm install
```

### 2. Create JWT Verify Lambda Layer

The stack requires a Lambda Layer with the `aws-jwt-verify` library. Create it:

```bash
# Create layer directory
mkdir -p lambda-layers/jwt-verify/nodejs
cd lambda-layers/jwt-verify/nodejs

# Install aws-jwt-verify
npm init -y
npm install aws-jwt-verify

# Go back to layer directory
cd ..

# Create zip file
zip -r jwt-verify.zip nodejs

# Publish layer
aws lambda publish-layer-version \
  --layer-name jwt-verify-layer \
  --description "AWS JWT Verify library for token validation" \
  --zip-file fileb://jwt-verify.zip \
  --compatible-runtimes nodejs22.x \
  --region eu-west-1

# Note the LayerVersionArn from the output
```

### 3. Update Layer ARN

Edit `lib/token-exchange-stack.ts` and update the layer ARN:

```typescript
const jwtVerifyLayer = lambda.LayerVersion.fromLayerVersionArn(
  this,
  'JwtVerifyLayer',
  'arn:aws:lambda:eu-west-1:YOUR_ACCOUNT:layer:jwt-verify-layer:1' // Update this
);
```

## Deployment

### Bootstrap CDK (first time only)

```bash
cdk bootstrap aws://ACCOUNT-NUMBER/REGION
```

### Deploy the Stack

```bash
# Synthesize CloudFormation template
cdk synth

# Preview changes
cdk diff

# Deploy
cdk deploy

# Or deploy with auto-approval
cdk deploy --require-approval never
```

### Deployment Output

After deployment, you'll see outputs like:

```
Outputs:
TokenExchangeStack.ExternalUserPoolId = eu-west-1_XXXXXXXXX
TokenExchangeStack.ExternalUserPoolClientId = 1234567890abcdef
TokenExchangeStack.TokenExchangeUserPoolId = eu-west-1_YYYYYYYYY
TokenExchangeStack.ServiceClientId = abcdef1234567890
TokenExchangeStack.ApiGatewayUrl = https://xxxxxxxxxx.execute-api.eu-west-1.amazonaws.com/v1/
TokenExchangeStack.TokenExchangeEndpoint = https://xxxxxxxxxx.execute-api.eu-west-1.amazonaws.com/v1/token-exchange
TokenExchangeStack.SSMParameterName = /TokenExchangeStack/service-client-secret
TokenExchangeStack.SSMParameterCommand = aws ssm get-parameter --name /TokenExchangeStack/service-client-secret --region eu-west-1
```

## Testing

### 1. Set Test User Password

```bash
aws cognito-idp admin-set-user-password \
  --user-pool-id <ExternalUserPoolId> \
  --username testuser@example.com \
  --password "TestPass123!" \
  --permanent \
  --region eu-west-1
```

### 2. Get User Access Token

```bash
aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id <ExternalUserPoolClientId> \
  --auth-parameters USERNAME=testuser@example.com,PASSWORD="TestPass123!" \
  --region eu-west-1 \
  --query 'AuthenticationResult.AccessToken' \
  --output text
```

### 3. Get Service Client Credentials

```bash
# Get credentials from SSM
aws ssm get-parameter \
  --name /TokenExchangeStack/service-client-secret \
  --region eu-west-1 \
  --query 'Parameter.Value' \
  --output text | jq .

# Output:
# {
#   "clientId": "abcdef1234567890",
#   "clientSecret": "secret123..."
# }
```

### 4. Perform Token Exchange

```bash
# Set variables
USER_TOKEN="<access_token_from_step_2>"
CLIENT_ID="<clientId_from_step_3>"
CLIENT_SECRET="<clientSecret_from_step_3>"
ENDPOINT="<TokenExchangeEndpoint_from_deployment>"

# Create Basic Auth header
AUTH_HEADER=$(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)

# Make token exchange request
curl -X POST "$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $AUTH_HEADER" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$USER_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token"
```

### 5. Decode Delegated Token

```bash
# Install jwt-cli if needed: cargo install jwt-cli

# Decode the new token
echo "<access_token_from_response>" | jwt decode -

# You should see delegation claims:
# {
#   "sub": "service@tokenexchange.local",
#   "custom:original_sub": "user123",
#   "custom:original_username": "testuser@example.com",
#   "custom:service_identity": "service@tokenexchange.local",
#   "custom:token_exchange": "true",
#   ...
# }
```

## CDK Commands

```bash
# List all stacks
cdk list

# Synthesize CloudFormation template
cdk synth

# Compare deployed stack with current state
cdk diff

# Deploy stack
cdk deploy

# Destroy stack
cdk destroy

# View CloudFormation template
cdk synth > template.yaml
```

## Project Structure

```
cdk/
├── bin/
│   └── app.ts                    # CDK app entry point
├── lib/
│   └── token-exchange-stack.ts   # Main stack definition
├── lambda-layers/
│   └── jwt-verify/               # JWT verification layer
├── cdk.json                      # CDK configuration
├── package.json                  # Node.js dependencies
├── tsconfig.json                 # TypeScript configuration
└── README.md                     # This file
```

## Key Features

### 1. SSM Parameter Store Integration

- **1000 TPS** vs 15 RPS (Cognito API limit)
- **5-minute cache** in Authorizer Lambda
- **Automatic secret storage** via Custom Resource
- **No manual secret management**

### 2. Delegation Pattern

The solution implements true OAuth 2.0 delegation:

```typescript
// Service acts as itself, on behalf of user
{
  "sub": "service@tokenexchange.local",        // Service identity
  "custom:original_sub": "user123",            // Original user
  "custom:service_identity": "service@...",    // Service context
  "custom:token_exchange": "true"              // Delegation flag
}
```

### 3. RFC 8693 Compliance

Follows OAuth 2.0 Token Exchange specification:
- Proper grant type validation
- Subject token verification
- Issued token type response
- Error handling per spec

## Customization

### Change Stack Name

Edit `bin/app.ts`:

```typescript
new TokenExchangeStack(app, 'MyCustomStackName', {
  // ...
});
```

### Change Region

Edit `bin/app.ts`:

```typescript
new TokenExchangeStack(app, 'TokenExchangeStack', {
  env: {
    region: 'us-east-1', // Change region
  },
});
```

### Add Custom Scopes

Edit `lib/token-exchange-stack.ts` in the PreTokenGeneration Lambda:

```typescript
const serviceScopes = [
  'read:user-profile',
  'read:user-permissions',
  'write:audit-logs',
  'access:downstream-apis',
  'custom:my-scope',  // Add your scopes
];
```

### Adjust Cache TTL

Edit the Authorizer Lambda in `lib/token-exchange-stack.ts`:

```typescript
const CACHE_TTL = 600000; // 10 minutes instead of 5
```

## Monitoring

### CloudWatch Logs

```bash
# Authorizer logs
aws logs tail /aws/lambda/TokenExchangeStack-Authorizer --follow

# Token Exchange logs
aws logs tail /aws/lambda/TokenExchangeStack-TokenExchange --follow

# Custom Resource logs
aws logs tail /aws/lambda/TokenExchangeStack-StoreClientSecret --follow
```

### CloudWatch Metrics

View metrics in AWS Console:
- Lambda invocations, errors, duration
- API Gateway requests, latency, 4xx/5xx errors
- SSM Parameter Store API calls

## Troubleshooting

### Issue: Layer not found

**Error**: `Layer version arn:aws:lambda:...:layer:jwt-verify-layer:1 does not exist`

**Solution**: Create the JWT Verify layer (see Setup section)

### Issue: Custom Resource fails

**Error**: `Custom Resource failed to create`

**Solution**: Check CloudWatch logs for StoreClientSecret Lambda

```bash
aws logs tail /aws/lambda/TokenExchangeStack-StoreClientSecret --follow
```

### Issue: Authorizer returns 403

**Error**: `User is not authorized to access this resource`

**Solution**: Verify SSM parameter is populated

```bash
aws ssm get-parameter --name /TokenExchangeStack/service-client-secret
```

### Issue: Token verification fails

**Error**: `Token verification failed`

**Solution**: Ensure user token is from the External User Pool, not Token Exchange pool

## Cost Estimation

### Monthly Cost (1M requests)

| Service | Usage | Cost |
|---------|-------|------|
| Lambda | 1M invocations, 512MB, 1s avg | ~$20 |
| API Gateway | 1M requests | ~$3.50 |
| Cognito | User pool + auth | Free tier |
| SSM | ~10K API calls (99% cache hit) | ~$0.05 |
| CloudWatch Logs | 10GB | ~$5 |
| **Total** | | **~$28.55/month** |

## Cleanup

```bash
# Destroy the stack
cdk destroy

# Confirm deletion
# This will delete all resources except:
# - CloudWatch Logs (retained for 7 days)
# - SSM Parameter (deleted with stack)
```

## Comparison: CDK vs CloudFormation

| Aspect | CDK | CloudFormation |
|--------|-----|----------------|
| **Language** | TypeScript | YAML |
| **Lines of Code** | ~600 | ~1000 |
| **Type Safety** | ✅ Yes | ❌ No |
| **IDE Support** | ✅ Excellent | ⚠️ Limited |
| **Reusability** | ✅ High (constructs) | ⚠️ Medium |
| **Learning Curve** | ⚠️ Steeper | ✅ Gentler |
| **Deployment** | `cdk deploy` | `aws cloudformation deploy` |

## References

- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Amazon Cognito Custom Auth Flow](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-challenge.html)
- [SSM Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)

## License

MIT
