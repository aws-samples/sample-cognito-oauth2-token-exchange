# OAuth 2.0 Token Exchange Implementation Guide

This guide provides detailed implementation instructions for the RFC 8693-compliant OAuth 2.0 Token Exchange using Amazon Cognito.

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Step-by-Step Implementation](#step-by-step-implementation)
4. [Configuration Details](#configuration-details)
5. [Testing & Validation](#testing--validation)
6. [Troubleshooting](#troubleshooting)
7. [Production Considerations](#production-considerations)

## 🏗️ Architecture Overview

### Core Components

The implementation consists of several key components working together:

1. **External IDP User Pool**: Where users authenticate
2. **TokenExchange User Pool**: Where service tokens are issued
3. **Service Client Identity**: Represents the service in token exchange
4. **Lambda Functions**: Handle custom authentication and token generation
5. **API Gateway**: Exposes the token exchange endpoint

### Token Flow

```
User Token (External) → Token Exchange Request → Service Token (Enhanced)
```

The service token contains:
- **Service Identity**: Token subject is the service client
- **Original User Claims**: Complete user context preserved
- **Service Scopes**: Custom scopes for downstream access

## 📋 Prerequisites

### AWS Account Setup
- AWS CLI configured with appropriate permissions
- IAM permissions for Cognito, Lambda, API Gateway, and CloudFormation
- Node.js 18+ and npm installed

### Required Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeploySampleResources",
      "Effect": "Allow",
      "Action": [
        "cognito-idp:*",
        "lambda:*",
        "apigateway:*",
        "cloudformation:*",
        "ssm:*",
        "logs:*",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:TagRole",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PassExecutionRoleToLambdaOnly",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::*:role/<your-stack-name>-*",
      "Condition": {
        "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" }
      }
    }
  ]
}
```

> These are broad deployment permissions provided for convenience. In production, scope each `Resource` to specific ARNs and tighten the service actions further. Note that `iam:*` is avoided and `iam:PassRole` is restricted to the Lambda service via the `iam:PassedToService` condition, so no role can be passed to an unintended service.

## 🚀 Step-by-Step Implementation

### Step 1: Deploy the Infrastructure

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd cognito-token-exchange
   ```

2. **Deploy CloudFormation Stack**
   ```bash
   ./deploy-cloudformation.sh
   ```

   This creates:
   - External IDP User Pool (for user authentication)
   - TokenExchange User Pool (for service tokens)
   - Lambda functions for custom auth flow
   - API Gateway for token exchange endpoint
   - Service client identity user

### Step 2: Understand the Lambda Functions

#### TokenExchange Lambda
**Purpose**: Handles RFC 8693 token exchange requests

**Key Functions**:
- Validates client credentials
- Initiates custom auth flow
- Passes original user token via ClientMetadata

```javascript
// Key code snippet
const challengeCommand = new AdminRespondToAuthChallengeCommand({
  ChallengeName: authResponse.ChallengeName,
  ClientId: process.env.ADMIN_CLIENT_ID,
  UserPoolId: process.env.USER_POOL_ID,
  Session: authResponse.Session,
  ChallengeResponses: {
    USERNAME: serviceUsername,
    ANSWER: body.subject_token
  },
  ClientMetadata: {
    OriginalUserToken: body.subject_token,
    TokenExchange: 'true'
  }
});
```

#### VerifyAuthChallenge Lambda
**Purpose**: Validates user tokens using aws-jwt-verify

**Key Functions**:
- Receives user token as challenge answer
- Validates token cryptographically
- Sets `answerCorrect = true` if valid

```javascript
// Key code snippet
const verifier = CognitoJwtVerifier.create({
  userPoolId: process.env.EXTERNAL_USER_POOL_ID,
  tokenUse: "access",
  clientId: process.env.EXTERNAL_CLIENT_ID,
});

const payload = await verifier.verify(userToken);
event.response.answerCorrect = true;
```

#### PreTokenGeneration Lambda (V2_0)
**Purpose**: Adds user claims and service scopes to the exchanged token

**Key Functions**:
- Verifies the original user token with `aws-jwt-verify`, then extracts its claims
- Adds service-specific scopes
- Suppresses default Cognito scopes

```javascript
// Key code snippet — verify before trusting claims.
// clientMetadata is caller-supplied and is NOT validated by Cognito, so the
// token is cryptographically verified with aws-jwt-verify (fail closed on error).
const payload = await verifier.verify(originalToken);

event.response.claimsAndScopeOverrideDetails = {
  accessTokenGeneration: {
    claimsToAddOrOverride: {
      'custom:original_sub': payload.sub,
      'custom:original_username': payload.username || payload.sub,
      'custom:token_exchange': 'true',
      'custom:service_identity': 'service@tokenexchange.local'
    },
    scopesToAdd: serviceScopes,
    scopesToSuppress: ['aws.cognito.signin.user.admin']
  }
};
```

### Step 3: Configure Service Scopes

Edit the PreTokenGeneration Lambda to customize service scopes:

```javascript
const serviceScopes = [
  'read:user-profile',
  'read:user-permissions', 
  'write:audit-logs',
  'access:downstream-apis',
  // Add your custom scopes here
  'custom:your-scope'
];
```

### Step 4: Test the Implementation

1. **Follow Manual Testing Steps**
   
   See [README.md Testing Section](../README.md#testing) for detailed step-by-step instructions.

2. **Manual Testing**
   ```bash
   # Get user token first
   USER_TOKEN=$(aws cognito-idp admin-initiate-auth \
     --user-pool-id eu-west-1_xxxxxxxxx \
     --client-id REPLACE_WITH_EXTERNAL_CLIENT_ID \
     --auth-flow ADMIN_NO_SRP_AUTH \
     --auth-parameters USERNAME=testuser@example.com,PASSWORD=YourPassword123! \
     --query 'AuthenticationResult.AccessToken' --output text)

   # Exchange token
   curl -X POST https://your-api-gateway-url/v1/token-exchange \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Authorization: Basic $(echo -n 'client_id:client_secret' | base64)" \
     -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" \
     -d "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token" \
     -d "subject_token=$USER_TOKEN"
   ```

## 🔧 Configuration Details

### Environment Variables

The Lambda functions use these environment variables:

```yaml
EXTERNAL_USER_POOL_ID: eu-west-1_xxxxxxxxx
EXTERNAL_CLIENT_ID: REPLACE_WITH_EXTERNAL_CLIENT_ID
USER_POOL_ID: eu-west-1_yyyyyyyyy
ADMIN_CLIENT_ID: REPLACE_WITH_ADMIN_CLIENT_ID
```

### User Pool Configuration

#### External IDP User Pool
- **Purpose**: User authentication
- **Auth Flows**: ADMIN_NO_SRP_AUTH, ALLOW_USER_PASSWORD_AUTH
- **Clients**: External client with secret

#### TokenExchange User Pool
- **Purpose**: Service token issuance
- **Auth Flows**: ALLOW_CUSTOM_AUTH only
- **Clients**: Admin client without secret
- **Triggers**: All custom auth triggers + V2_0 pre-token generation

### Service Client Identity

The service client identity is a special user in the TokenExchange User Pool:

```yaml
Username: 42151424-00c1-7000-7d55-d8412a7482d5 (UUID)
Email: service@tokenexchange.local
Status: CONFIRMED
Purpose: Represents the service in token exchange
```

## 🧪 Testing & Validation

### Unit Tests

Create unit tests for each Lambda function:

```javascript
// Example test for VerifyAuthChallenge
describe('VerifyAuthChallenge', () => {
  it('should validate correct token', async () => {
    const event = {
      request: {
        challengeAnswer: validUserToken
      },
      response: {}
    };
    
    const result = await handler(event);
    expect(result.response.answerCorrect).toBe(true);
  });
});
```

### Integration Tests

Test the complete flow:

```bash
#!/bin/bash
# integration-test.sh

# 1. Get user token
USER_TOKEN=$(get_user_token)

# 2. Exchange token
RESPONSE=$(exchange_token "$USER_TOKEN")

# 3. Validate response
validate_response "$RESPONSE"

# 4. Decode and validate claims
validate_claims "$RESPONSE"
```

### Load Testing

Use tools like Artillery or JMeter:

```yaml
# artillery-config.yml
config:
  target: 'https://your-api-gateway-url'
  phases:
    - duration: 60
      arrivalRate: 10
scenarios:
  - name: "Token Exchange"
    requests:
      - post:
          url: "/v1/token-exchange"
          headers:
            Content-Type: "application/x-www-form-urlencoded"
            Authorization: "Basic {{ $randomString() }}"
          form:
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange"
            subject_token_type: "urn:ietf:params:oauth:token-type:access_token"
            subject_token: "{{ userToken }}"
```

## 🔍 Troubleshooting

### Common Issues

#### 1. "User does not exist" Error
**Cause**: Service client identity not created properly
**Solution**: Check if service user exists in TokenExchange User Pool

```bash
aws cognito-idp admin-get-user \
  --user-pool-id eu-west-1_yyyyyyyyy \
  --username "service@tokenexchange.local"
```

#### 2. "Invalid token" Error
**Cause**: Token validation failing in VerifyAuthChallenge
**Solution**: Check CloudWatch logs for VerifyAuthChallenge Lambda

#### 3. "Missing claims" in Response
**Cause**: PreTokenGeneration not receiving ClientMetadata
**Solution**: Ensure ClientMetadata is passed in AdminRespondToAuthChallenge

#### 4. "Invalid client credentials" Error
**Cause**: Client credentials not retrieved properly
**Solution**: Check if client secret is being fetched correctly

### Debugging Steps

1. **Check CloudWatch Logs**
   ```bash
   aws logs tail /aws/lambda/TokenExchangeStack-TokenExchange --follow
   ```

2. **Validate Token Manually**
   ```bash
   # Decode JWT payload
   echo "JWT_PAYLOAD" | base64 -d | jq .
   ```

3. **Test Individual Components**
   ```bash
   # Test custom auth flow directly
   aws cognito-idp admin-initiate-auth \
     --user-pool-id eu-west-1_yyyyyyyyy \
     --client-id REPLACE_WITH_ADMIN_CLIENT_ID \
     --auth-flow CUSTOM_AUTH \
     --auth-parameters USERNAME=service@tokenexchange.local
   ```

## 🏭 Production Considerations

### Security Hardening

1. **Client Credentials Management**
   - Use AWS Secrets Manager for client secrets
   - Rotate credentials regularly
   - Monitor credential usage

2. **Network Security**
   - Use VPC endpoints for Lambda functions
   - Implement WAF rules for API Gateway
   - Enable CloudTrail logging

3. **Token Security**
   - Implement token revocation
   - Use short token lifetimes
   - Monitor for token abuse

### Monitoring & Alerting

1. **CloudWatch Metrics**
   ```javascript
   // Custom metrics in Lambda
   const AWS = require('aws-sdk');
   const cloudwatch = new AWS.CloudWatch();
   
   await cloudwatch.putMetricData({
     Namespace: 'TokenExchange',
     MetricData: [{
       MetricName: 'TokenExchangeSuccess',
       Value: 1,
       Unit: 'Count'
     }]
   }).promise();
   ```

2. **Alarms**
   - High error rates
   - Unusual token exchange patterns
   - Client authentication failures

### Performance Optimization

1. **Lambda Optimization**
   - Use provisioned concurrency for consistent performance
   - Optimize memory allocation
   - Implement connection pooling

2. **Caching**
   - Cache client credentials
   - Cache JWT verification keys
   - Use API Gateway caching

### Compliance & Auditing

1. **Audit Logging**
   ```javascript
   // Enhanced audit logging
   const auditLog = {
     timestamp: new Date().toISOString(),
     event: 'token_exchange',
     originalUser: payload.sub,
     serviceClient: clientId,
     success: true,
     ipAddress: event.requestContext.identity.sourceIp
   };
   
   console.log('AUDIT:', JSON.stringify(auditLog));
   ```

2. **Compliance Checks**
   - Regular security assessments
   - Token usage audits
   - Access pattern analysis

## 📚 Additional Resources

- [RFC 8693 Specification](https://datatracker.ietf.org/doc/html/rfc8693)
- [AWS Cognito Documentation](https://docs.aws.amazon.com/cognito/)
- [aws-jwt-verify Library](https://github.com/awslabs/aws-jwt-verify)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

## 🤝 Support

For implementation support:
1. Check the troubleshooting section
2. Review CloudWatch logs
3. Create an issue in the repository
4. Consult AWS documentation
