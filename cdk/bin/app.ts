#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { Aspects } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { TokenExchangeStack } from '../lib/token-exchange-stack';

const app = new cdk.App();

const stack = new TokenExchangeStack(app, 'TokenExchangeStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'eu-west-1',
  },
  description: 'OAuth 2.0 Token Exchange implementation using Cognito with SSM Parameter Store',
});

// Add cdk-nag checks
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

app.synth();
