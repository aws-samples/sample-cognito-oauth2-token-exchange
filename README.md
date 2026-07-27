# OAuth 2.0 Token Exchange with Amazon Cognito

This sample demonstrates how to implement [RFC 8693 OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) using Amazon Cognito with a true delegation pattern. The solution enables services to act on behalf of users while maintaining distinct service identities and implementing the principle of least privilege.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Deployment Options](#deployment-options)
- [Getting Started](#getting-started)
- [Testing](#testing)
- [Security](#security)
- [Cost](#cost)
- [Cleanup](#cleanup)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Overview

This solution implements OAuth 2.0 Token Exchange (RFC 8693) to enable secure delegation in microservices architectures. When a service needs to act on behalf of a user, it exchanges the user's access token for a new service token that contains both the service's identity and the original user's context.

### Key Concepts

**Delegation vs. Impersonation**

- **Delegation** (this solution): Service acts as itself, on behalf of the user
  - Token contains: `sub: "service@example.com"` + `custom:original_sub: "user123"`
  - Clear audit trail showing service → user relationship
  - Service-specific permissions (least privilege)

- **Impersonation**: Service acts as the user
  - Token contains: `sub: "user123"`
  - Appears as direct user action
  - Full user privileges (security risk)

### Use Cases

1. **Microservices Architecture**: Backend services need to call other services on behalf of users
2. **Third-Party Integration**: Your application calls external APIs with user context
3. **Audit & Compliance**: Track which service performed actions for which users
4. **Least Privilege**: Services get only the permissions they need, not full user access

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  OAuth 2.0 Token Exchange Flow                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  1. User authenticates with External IDP                         │
│     ↓                                                             │
│     User Token: { sub: "user123", client_id: "app" }            │
│                                                                   │
│  2. Service exchanges user token for service token               │
│     ↓                                                             │
│     POST /token-exchange                                          │
│     Authorization: Basic base64(service_id:secret)               │
│     subject_token=<user_token>                                   │
│                                                                   │
│  3. Service receives delegated token                             │
│     ↓                                                             │
│     Service Token: {                                             │
│       sub: "service@tokenexchange.local",                        │
│       custom:original_sub: "user123",                            │
│       custom:service_identity: "service@...",                    │
│       custom:token_exchange: "true"                              │
│     }                                                             │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Components

- **External IDP User Pool**: Simulates an external identity provider (represents your existing user authentication)
- **Token Exchange User Pool**: Target user pool where service tokens are issued
- **Custom Auth Lambda Functions**: Implement the token exchange logic
  - Define Auth Challenge
  - Create Auth Challenge
  - Verify Auth Challenge (validates user token)
  - Pre-Token Generation (adds delegation claims)
- **Token Exchange Lambda**: Handles RFC 8693 token exchange requests
- **API Gateway Authorizer**: Validates service client credentials via SSM Parameter Store
- **SSM Parameter Store**: Stores service client credentials (1000 TPS vs 15 RPS Cognito API limit)

### Why SSM Parameter Store?

The API Gateway Authorizer needs to validate service client credentials on every request. We use AWS Systems Manager (SSM) Parameter Store instead of calling Cognito's `DescribeUserPoolClient` API directly because:

**Performance**: 
- Cognito API: 15 requests per second (hard limit)
- SSM Parameter Store: 1,000 transactions per second (standard), up to 10,000 TPS (higher throughput)

**Efficiency**:
- 5-minute cache in the Authorizer Lambda reduces SSM calls by ~99%
- Typical cache hit rate means only 3-5 SSM calls per 1,000 requests

**Cost**:
- SSM: ~$0.05 per month for 1M requests (with caching)
- Eliminates Cognito API throttling issues

**Implementation**:
- Custom Resource automatically fetches the Cognito client secret during deployment
- Stores it in SSM Parameter Store (one-time operation)
- Authorizer reads from SSM with local caching
- No manual secret management required

This design ensures high performance and scalability while maintaining security best practices.

## Features

✅ **RFC 8693 Compliant**: Full OAuth 2.0 Token Exchange specification  
✅ **True Delegation**: Service identity + user context in tokens  
✅ **High Performance**: SSM Parameter Store (1000 TPS vs 15 RPS)  
✅ **Automatic Secret Management**: Custom Resource populates SSM  
✅ **Least Privilege**: Service-specific scopes, not full user access  
✅ **Audit Trail**: Clear delegation metadata in tokens  
✅ **Two Deployment Options**: CloudFormation (YAML) or CDK (TypeScript)  
✅ **Production Ready**: Comprehensive logging, monitoring, error handling  

## Deployment Options

> **Important**: This package includes two deployment options that create identical infrastructure. **You only need to deploy one of them.** Choose whichever fits your team's workflow.

| | Option A: CloudFormation | Option B: CDK (TypeScript) |
|---|---|---|
| **Deploy command** | `./deploy-cloudformation.sh` | `cd cdk && npm install && ./deploy.sh` |
| **Best for** | Ops teams, simple deployments | Dev teams, type safety, customization |
| **Prerequisites** | AWS CLI only | AWS CLI + Node.js 18+ + CDK CLI |
| **Customization** | Edit YAML template | Edit TypeScript, full IDE support |
| **Build step** | None | `npm run build` (handled by deploy script) |

### Option A: AWS CloudFormation (YAML)

```bash
./deploy-cloudformation.sh
```

### Option B: AWS CDK (TypeScript)

```bash
cd cdk
npm install
./deploy.sh
```

After deploying with either option, test with:

```bash
./test-token-exchange.sh TokenExchangeStack eu-west-1
```

### Disabling Delegation Claims

By default, the PreTokenGeneration Lambda enriches exchanged tokens with the original user's identity claims and service-specific scopes. If you only need the token exchange without claim enrichment, you can disable this:

CDK:
```bash
cd cdk && cdk deploy -c enableDelegationClaims=false
```

CloudFormation:
```bash
aws cloudformation deploy \
  --template-file cloudformation-template.yaml \
  --stack-name TokenExchangeStack \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides EnableDelegationClaims=false
```

When disabled, the exchanged token is a standard Cognito token without `custom:original_sub`, `custom:original_iss`, or service scopes.

## Getting Started

### Prerequisites

- AWS CLI configured with appropriate credentials
- Node.js 18+ (for CDK deployment)
- AWS CDK CLI (for CDK deployment): `npm install -g aws-cdk`
- jq (for testing scripts)

### Quick Start (CloudFormation)

1. **Create JWT Verify Lambda Layer**

```bash
# Create layer directory
mkdir -p lambda-layers/jwt-verify/nodejs
cd lambda-layers/jwt-verify/nodejs

# Install aws-jwt-verify
npm init -y
npm install aws-jwt-verify

# Create and publish layer
cd ..
zip -r jwt-verify.zip nodejs

aws lambda publish-layer-version \
  --layer-name jwt-verify-layer \
  --description "AWS JWT Verify library" \
  --zip-file fileb://jwt-verify.zip \
  --compatible-runtimes nodejs22.x \
  --region eu-west-1
```

2. **Update the CloudFormation template** with your layer ARN (line ~95)

3. **Deploy the stack**

```bash
./deploy-cloudformation.sh
```

4. **Note the outputs** - you'll need these for testing

### Quick Start (CDK)

See [cdk/QUICKSTART.md](cdk/QUICKSTART.md) for detailed CDK setup.

## Visual Demo

A single-file HTML demo is included for customer walkthroughs. It calls the deployed endpoint directly from the browser and shows the tokens side-by-side with their decoded claims.

```bash
# Print the stack values you'll need
./demo/load-config.sh TokenExchangeStack eu-west-1

# Open the demo in your default browser
open demo/index.html      # macOS
xdg-open demo/index.html  # Linux
```

The demo walks through 4 steps:

1. Authenticate with the Country/External IdP
2. Exchange for a global identity token (RFC 8693)
3. Inspect and compare the before/after tokens with delegation claims highlighted
4. Verification extensibility — how to plug in non-standard IdPs

Fill in the config fields at the top once and click Authenticate. No build step, no dependencies.

## Testing

### 1. Set Test User Password

```bash
aws cognito-idp admin-set-user-password \
  --user-pool-id <ExternalUserPoolId from outputs> \
  --username testuser@example.com \
  --password "TestPass123!" \
  --permanent \
  --region eu-west-1
```

### 2. Get User Access Token

```bash
USER_TOKEN=$(aws cognito-idp initiate-auth \
  --auth-flow USER_PASSWORD_AUTH \
  --client-id <ExternalUserPoolClientId from outputs> \
  --auth-parameters USERNAME=testuser@example.com,PASSWORD="TestPass123!" \
  --region eu-west-1 \
  --query 'AuthenticationResult.AccessToken' \
  --output text)
```

### 3. Get Service Client Credentials

```bash
aws ssm get-parameter \
  --name /TokenExchangeStack/service-client-secret \
  --region eu-west-1 \
  --query 'Parameter.Value' \
  --output text | jq .
```

### 4. Exchange Token

```bash
CLIENT_ID="<from step 3>"
CLIENT_SECRET="<from step 3>"
ENDPOINT="<TokenExchangeEndpoint from outputs>"

curl -X POST "$ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n "$CLIENT_ID:$CLIENT_SECRET" | base64)" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$USER_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token"
```

### 5. Verify Delegation Claims

Decode the returned access token to see delegation claims:

```bash
echo "<access_token>" | jwt decode -
```

Expected claims:
```json
{
  "sub": "service@tokenexchange.local",
  "custom:original_sub": "...",
  "custom:original_username": "testuser@example.com",
  "custom:service_identity": "service@tokenexchange.local",
  "custom:token_exchange": "true",
  "custom:service_scopes": "read:user-profile write:audit-logs"
}
```

## Security

### Authentication & Authorization

- **Service Authentication**: Basic Auth with client credentials stored in SSM
- **Token Validation**: JWT signature verification using aws-jwt-verify
- **Credential Management**: Automatic secret storage via Custom Resource
- **IAM Least Privilege**: Minimal permissions for all Lambda functions

### Audit & Compliance

- **CloudWatch Logs**: All Lambda functions log to CloudWatch (7-day retention)
- **Delegation Metadata**: Tokens contain original user context for audit trails
- **CloudTrail Integration**: All API calls logged for compliance

### Best Practices

- ✅ Secrets stored in SSM Parameter Store, not environment variables
- ✅ 5-minute cache reduces API calls and improves performance
- ✅ Service-specific scopes enforce least privilege
- ✅ Clear separation between user identity and service identity

## Cost

Estimated monthly cost for 1 million requests:

| Service | Usage | Cost |
|---------|-------|------|
| AWS Lambda | 1M invocations, 512MB, 1s avg | ~$20 |
| Amazon API Gateway | 1M requests | ~$3.50 |
| Amazon Cognito | User pool + auth | Free tier |
| AWS Systems Manager | ~10K API calls (99% cache hit) | ~$0.05 |
| Amazon CloudWatch Logs | 10GB | ~$5 |
| **Total** | | **~$28.55/month** |

## Cleanup

### CloudFormation

The deploy script creates an S3 bucket for the Lambda layer that is not part of the stack. Delete both:

```bash
aws cloudformation delete-stack --stack-name TokenExchangeStack --region eu-west-1
aws s3 rb s3://tokenexchangestack-lambda-layers --force --region eu-west-1
```

(The bucket name is derived from the stack name, lowercased, with `-lambda-layers` appended.)

### CDK

The CDK deployment bundles the Lambda layer into the stack itself, so no orphaned resources:

```bash
cd cdk
cdk destroy
```

## Documentation

- **[CDK README](cdk/README.md)** - Full CDK documentation
- **[CDK Quick Start](cdk/QUICKSTART.md)** - 10-minute CDK setup
- **[Implementation Guide](docs/IMPLEMENTATION_GUIDE.md)** - Detailed implementation documentation

## Performance

| Metric | Value |
|--------|-------|
| **Throughput** | 1000 TPS (vs 15 RPS Cognito API) |
| **Cache Hit Rate** | ~99% |
| **Latency (cached)** | ~5ms |
| **Latency (uncached)** | ~30ms |
| **Scalability** | Can increase to 10,000 TPS |

## Troubleshooting

### Issue: 403 Forbidden from API Gateway

**Cause**: SSM parameter not populated or incorrect credentials

**Solution**:
```bash
aws ssm get-parameter --name /TokenExchangeStack/service-client-secret
```

### Issue: Token verification failed

**Cause**: Token is from wrong user pool or expired

**Solution**: Ensure token is from External User Pool, not Token Exchange pool

### Issue: Custom Resource failed during deployment

**Cause**: Lambda can't access Cognito or SSM

**Solution**: Check CloudWatch logs
```bash
aws logs tail /aws/lambda/TokenExchangeStack-StoreClientSecret --follow
```

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

## Security considerations

This sample implements the following controls by default:

- **Secrets in SSM as `SecureString`.** The service client secret is stored encrypted (AWS-managed `alias/aws/ssm` key) and read with decryption. IAM for the authorizer and the store-secret custom resource is scoped to the exact parameter ARN, with `kms:*` constrained to SSM via the `kms:ViaService` condition.
- **Token verification is pinned.** Inbound tokens are verified with `aws-jwt-verify`, pinned to the external user pool, client ID, and `tokenUse` (there is no issuer-only "generic" fallback). `clientMetadata` is re-verified inside the pre-token trigger because Cognito does not validate it. Verification failures fail closed (no token is issued).
- **Least-privilege delegated scopes.** The exchanged token carries the *service's* scopes, bounded by a fixed ceiling. A caller may request a subset via the RFC 8693 `scope` parameter; anything beyond the ceiling is rejected, so the exchange can never escalate past the service's own grant. Per-user authorization is enforced downstream (see below).
- **No secrets in logs.** Lambdas do not log raw events, tokens, or claims (only non-sensitive identifiers), and API Gateway data-trace logging is disabled.
- **Constant-time credential comparison** in the authorizer (`crypto.timingSafeEqual`).

For production deployments, also apply:

- **Restrict CORS** to your application's origin. With the CDK: `cdk deploy -c corsAllowOrigin=https://your-app.example.com`. With CloudFormation, pass the `CorsAllowOrigin` parameter. Either way the origin applies to the preflight response and to the token-exchange responses.
- **Keep the confidential client secret server-side.** The browser demo holds it client-side only to illustrate the request; perform the exchange from a backend in production.
- **Restrict the token audience/resource** (RFC 8693 `audience`/`resource`) so exchanged tokens cannot be replayed against other downstreams, and enforce fine-grained, per-user authorization at the resource (for example with [Amazon Verified Permissions](https://aws.amazon.com/verified-permissions/)).
- **Harden the front door**: rotate the Basic-auth client secret regularly (or move to mTLS / OAuth client-credentials), associate a **WAFv2** web ACL and explicit usage plans with the API stage, enable **MFA** on the user pools, and set Lambda **reserved concurrency**.

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Amazon Cognito Custom Authentication Flow](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-challenge.html)
- [AWS Systems Manager Parameter Store](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html)
- [Amazon Cognito API Rate Limits](https://docs.aws.amazon.com/cognito/latest/developerguide/limits.html)

## Acknowledgments

This sample demonstrates advanced Amazon Cognito patterns for implementing OAuth 2.0 Token Exchange with true delegation semantics, suitable for microservices architectures requiring secure service-to-service communication with user context preservation.
