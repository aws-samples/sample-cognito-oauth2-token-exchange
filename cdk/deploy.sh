#!/bin/bash

# OAuth 2.0 Token Exchange CDK Deployment Script

set -e

echo "🚀 OAuth 2.0 Token Exchange - CDK Deployment"
echo "=============================================="
echo ""

# Check if CDK is installed
if ! command -v cdk &> /dev/null; then
    echo "❌ AWS CDK CLI not found. Installing..."
    npm install -g aws-cdk
fi

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Build TypeScript
echo "🔨 Building TypeScript..."
npm run build

# Bootstrap CDK (if needed)
echo "🏗️  Checking CDK bootstrap..."
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=${AWS_REGION:-eu-west-1}

if ! aws cloudformation describe-stacks --stack-name CDKToolkit --region "$REGION" &> /dev/null; then
    echo "📦 Bootstrapping CDK for account $ACCOUNT in region $REGION..."
    cdk bootstrap "aws://$ACCOUNT/$REGION"
else
    echo "✅ CDK already bootstrapped"
fi

# Synthesize CloudFormation template
echo "📝 Synthesizing CloudFormation template..."
cdk synth

# Show diff
echo ""
echo "📊 Showing changes..."
cdk diff || true

# Confirm deployment
echo ""
read -p "🤔 Do you want to deploy these changes? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 Deploying stack..."
    cdk deploy --require-approval never
    
    echo ""
    echo "✅ Deployment complete!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Set test user password:"
    echo "   aws cognito-idp admin-set-user-password \\"
    echo "     --user-pool-id <ExternalUserPoolId> \\"
    echo "     --username testuser@example.com \\"
    echo "     --password 'TestPass123!' \\"
    echo "     --permanent"
    echo ""
    echo "2. Get service client credentials:"
    echo "   aws ssm get-parameter \\"
    echo "     --name /TokenExchangeStack/service-client-secret \\"
    echo "     --region $REGION | jq -r '.Parameter.Value' | jq ."
    echo ""
    echo "3. Test token exchange using the endpoint from outputs"
else
    echo "❌ Deployment cancelled"
    exit 1
fi
