#!/bin/bash
# Generates a config snippet for the demo UI from the deployed stack
# Usage: ./load-config.sh [stack-name] [region]

STACK_NAME="${1:-TokenExchangeStack}"
REGION="${2:-eu-west-1}"

OUTPUTS=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --query 'Stacks[0].Outputs' \
  --output json 2>&1)

if [[ $? -ne 0 ]]; then
  echo "❌ Failed to get stack outputs"
  exit 1
fi

get_output() {
  echo "$OUTPUTS" | jq -r ".[] | select(.OutputKey==\"$1\") | .OutputValue"
}

SSM_PARAM=$(get_output "SSMParameterName")
CREDS=$(aws ssm get-parameter --name "$SSM_PARAM" --region "$REGION" --query 'Parameter.Value' --output text)

cat << EOF
Open demo/index.html in your browser and fill in:

  Region:                 $REGION
  Token Exchange Endpoint: $(get_output "TokenExchangeEndpoint")
  Country IdP Client ID:  $(get_output "ExternalUserPoolClientId")
  Country IdP User Pool:  $(get_output "ExternalUserPoolId")
  Service Client ID:      $(echo "$CREDS" | jq -r '.clientId')
  Service Client Secret:  $(echo "$CREDS" | jq -r '.clientSecret')

Test user: testuser@example.com / TestPass123!
EOF
