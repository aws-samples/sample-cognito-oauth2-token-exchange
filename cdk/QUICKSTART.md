# CDK Quick Start Guide

Get your OAuth 2.0 Token Exchange infrastructure running in 10 minutes.

## Prerequisites

```bash
# Install Node.js 18+ (if not installed)
node --version  # Should be 18+

# Install AWS CDK globally
npm install -g aws-cdk

# Verify installation
cdk --version

# Docker (optional — used to bundle the JWT verify layer when npm is unavailable)
docker --version
```

## Step 1: Install Dependencies (2 minutes)

```bash
cd cdk
npm install
```

## Step 2: Deploy (5 minutes)

```bash
./deploy.sh
```

The deploy script will:
1. Bootstrap CDK if needed
2. Synthesize the CloudFormation template
3. Build the `aws-jwt-verify` Lambda layer inside a Node.js container (via CDK bundling)
4. Deploy the stack

No manual `aws lambda publish-layer-version` step, no hardcoded ARNs. The layer is bundled automatically from `lambda-layers/jwt-verify/nodejs/package.json`.

## Step 3: Test (2 minutes)

Once deployed, run the end-to-end demo script:

```bash
cd ..
./test-token-exchange.sh TokenExchangeStack eu-west-1
```

You should see a successful RFC 8693 token exchange with an exchanged JWT containing delegation claims.

## Optional: Disable Delegation Claims

By default, the PreTokenGeneration Lambda enriches exchanged tokens with the original user identity and service scopes. To deploy without this enrichment:

```bash
cdk deploy -c enableDelegationClaims=false
```

## Cleanup

```bash
cdk destroy
```

This removes all stack resources. The Lambda layer is part of the stack, so nothing is orphaned.

## Troubleshooting

### Error: "Cannot find module 'aws-jwt-verify'"

The layer was staged without its dependencies. The layer asset is bundled at synth
time, which runs `npm ci` in `lambda-layers/jwt-verify/nodejs` on the host and falls
back to a Docker image if npm is unavailable. Re-run `cdk deploy`; if the host has no
npm, verify Docker is running (`docker ps`).

### Error: "Custom Resource failed"

Check CloudWatch logs:
```bash
aws logs tail /aws/lambda/TokenExchangeStack-StoreClientSecret --follow
```

### Error: "403 Forbidden" when calling the endpoint

Verify the SSM parameter was populated:
```bash
aws ssm get-parameter --name /TokenExchangeStack/service-client-secret --region eu-west-1
```

## Next Steps

- Read the main [README](../README.md) for architecture and security details
- Customize service scopes in `lib/token-exchange-stack.ts` (search for `serviceScopes`)
- Swap `VerifyAuthChallenge` Lambda for custom IdP verification logic
