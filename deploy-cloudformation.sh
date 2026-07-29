#!/bin/bash

# OAuth 2.0 Token Exchange CloudFormation Deployment Script
# Leaves the source template untouched. Writes the rendered template to a temp file.

set -e

STACK_NAME="${1:-TokenExchangeStack}"
REGION="${2:-eu-west-1}"
TEMPLATE_FILE="cloudformation-template.yaml"

# Bucket name must be deterministic (derived from stack name) so cleanup is predictable
# and so re-deployments reuse the same bucket instead of orphaning old ones.
BUCKET_NAME="$(echo "$STACK_NAME" | tr '[:upper:]' '[:lower:]')-lambda-layers"

echo "🚀 Deploying OAuth 2.0 Token Exchange CloudFormation Stack..."
echo "   Stack:  $STACK_NAME"
echo "   Region: $REGION"
echo "   Bucket: $BUCKET_NAME"
echo ""

# Create S3 bucket for Lambda layers if it doesn't exist
if aws s3api head-bucket --bucket "$BUCKET_NAME" --region "$REGION" 2>/dev/null; then
  echo "📦 S3 bucket already exists: $BUCKET_NAME"
else
  echo "📦 Creating S3 bucket for Lambda layers: $BUCKET_NAME"
  aws s3 mb "s3://$BUCKET_NAME" --region "$REGION"
fi

# Create Lambda layer with real aws-jwt-verify library
echo "📦 Building Lambda layer with aws-jwt-verify..."
rm -rf lambda-layer-build
mkdir -p lambda-layer-build/nodejs

# Reuse the manifest and lockfile the CDK path uses, so both deployment options
# install the same aws-jwt-verify version. Writing a fresh package.json here and
# running `npm install` without a lockfile resolved to whatever 5.x was current
# at deploy time.
LAYER_SRC="cdk/lambda-layers/jwt-verify/nodejs"
if [ ! -f "$LAYER_SRC/package-lock.json" ]; then
  echo "Missing $LAYER_SRC/package-lock.json; cannot pin the layer dependency" >&2
  exit 1
fi
cp "$LAYER_SRC/package.json" "$LAYER_SRC/package-lock.json" lambda-layer-build/nodejs/

(cd lambda-layer-build/nodejs && npm ci --omit=dev --silent)

# Create the layer zip
(cd lambda-layer-build && zip -rq ../jwt-verify.zip .)

# Upload Lambda layer to S3
echo "📤 Uploading Lambda layer to S3..."
aws s3 cp jwt-verify.zip "s3://$BUCKET_NAME/jwt-verify.zip" --region "$REGION"

# Render the template to a temp file — do NOT modify the source template
RENDERED_TEMPLATE="$(mktemp -t token-exchange-template.XXXXXX.yaml)"
# Substitute the bucket name placeholder. The template uses !Sub '${AWS::StackName}-lambda-layers'
# which resolves to the deterministic bucket name above at stack deploy time.
# But because CLI v1 has a 51,200 byte inline limit, we also use --s3-bucket for template upload.
cp "$TEMPLATE_FILE" "$RENDERED_TEMPLATE"

# Deploy CloudFormation stack, uploading the template via S3 to support AWS CLI v1
echo "🚀 Deploying CloudFormation stack..."
aws cloudformation deploy \
  --template-file "$RENDERED_TEMPLATE" \
  --stack-name "$STACK_NAME" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
  --region "$REGION" \
  --s3-bucket "$BUCKET_NAME" \
  --s3-prefix cfn-templates \
  --parameter-overrides "LambdaLayerBucket=$BUCKET_NAME"

# Cleanup temporary files (but leave the S3 bucket — the layer still needs it)
rm -rf lambda-layer-build jwt-verify.zip "$RENDERED_TEMPLATE"

# Get stack outputs
echo ""
echo "📋 Stack outputs:"
aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
  --output table

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🔗 Token Exchange Endpoint:"
aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query 'Stacks[0].Outputs[?OutputKey==`TokenExchangeEndpoint`].OutputValue' \
  --output text

echo ""
echo "🧪 Test with:  ./test-token-exchange.sh $STACK_NAME $REGION"
echo ""
echo "🧹 Cleanup:    aws cloudformation delete-stack --stack-name $STACK_NAME --region $REGION"
echo "               aws s3 rb s3://$BUCKET_NAME --force --region $REGION"
