import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as cr from 'aws-cdk-lib/custom-resources';
import { NagSuppressions } from 'cdk-nag';

export class TokenExchangeStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ========================================
    // Configuration: Toggle delegation claims
    // ========================================
    // Set to false if you only need token exchange without
    // enriching the new token with original user claims.
    // Usage: cdk deploy -c enableDelegationClaims=false
    const enableDelegationClaims = this.node.tryGetContext('enableDelegationClaims') !== 'false';

    // Suppress cdk-nag findings for optional paid features and design decisions
    NagSuppressions.addStackSuppressions(this, [
      {
        id: 'AwsSolutions-COG3',
        reason: 'AdvancedSecurityMode is a paid Cognito feature - optional for this sample',
      },
      {
        id: 'AwsSolutions-COG4',
        reason: 'This solution intentionally uses a custom Lambda authorizer instead of Cognito authorizer - the custom authorizer validates service client credentials for the token exchange flow',
      },
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AWSLambdaBasicExecutionRole is required for Lambda functions to write logs to CloudWatch - this is the minimum permission set for Lambda execution',
        appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
      },
      {
        id: 'AwsSolutions-L1',
        reason: 'NODEJS_22_X is the latest Node.js LTS runtime (released Oct 2024). cdk-nag rule has not been updated to recognize it - see https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html',
      },
      {
        id: 'AwsSolutions-IAM5',
        reason: 'CDK Provider framework requires lambda:InvokeFunction permission with :* suffix to support Lambda versioning/aliases. This is standard CDK behavior for custom resources.',
        appliesTo: [
          'Resource::<CreateServiceIdentities571DBA9A.Arn>:*',
          'Resource::<StoreClientSecret52339365.Arn>:*',
        ],
      },
    ]);

    // ========================================
    // KMS Key for CloudWatch Logs encryption
    // ========================================
    const logsKmsKey = new kms.Key(this, 'LogsKmsKey', {
      description: 'KMS key for CloudWatch Logs encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Grant CloudWatch Logs permission to use the key
    logsKmsKey.addToResourcePolicy(
      new iam.PolicyStatement({
        actions: [
          'kms:Encrypt*',
          'kms:Decrypt*',
          'kms:ReEncrypt*',
          'kms:GenerateDataKey*',
          'kms:Describe*',
        ],
        principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
        resources: ['*'],
        conditions: {
          ArnLike: {
            'kms:EncryptionContext:aws:logs:arn': `arn:aws:logs:${this.region}:${this.account}:*`,
          },
        },
      })
    );

    // ========================================
    // Shared CloudWatch Log Group for all Lambda functions
    // ========================================
    // Using a single log group simplifies querying across the token exchange flow
    // and reduces IAM complexity. Log streams include function name for filtering.
    const sharedLogGroup = new logs.LogGroup(this, 'TokenExchangeLogGroup', {
      logGroupName: `/aws/lambda/${this.stackName}`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryptionKey: logsKmsKey,
    });

    // Separate log group for API Gateway access logs
    const apiAccessLogGroup = new logs.LogGroup(this, 'ApiAccessLogGroup', {
      logGroupName: `/aws/apigateway/${this.stackName}-access-logs`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryptionKey: logsKmsKey,
    });

    // ========================================
    // External IDP User Pool (represents different identity provider)
    // ========================================
    const externalIdpUserPool = new cognito.UserPool(this, 'ExternalIdpUserPool', {
      userPoolName: 'external-idp-user-pool',
      selfSignUpEnabled: false,
      signInAliases: {
        email: true,
      },
      autoVerify: {
        email: true,
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      standardAttributes: {
        email: {
          required: true,
          mutable: true,
        },
        givenName: {
          required: false,
          mutable: true,
        },
        familyName: {
          required: false,
          mutable: true,
        },
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // External IDP Client - Users authenticate with this client
    const externalIdpClient = externalIdpUserPool.addClient('ExternalIdpClient', {
      userPoolClientName: 'external-idp-client',
      generateSecret: false, // Public client for user authentication
      authFlows: {
        userSrp: true,
        userPassword: true,
      },
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(30),
      preventUserExistenceErrors: true,
      readAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({
          email: true,
          givenName: true,
          familyName: true,
        }),
      writeAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({
          email: true,
          givenName: true,
          familyName: true,
        }),
    });

    // Create test user in external IDP
    new cognito.CfnUserPoolUser(this, 'ExternalIdpTestUser', {
      userPoolId: externalIdpUserPool.userPoolId,
      username: 'testuser@example.com',
      userAttributes: [
        { name: 'email', value: 'testuser@example.com' },
        { name: 'email_verified', value: 'true' },
        { name: 'given_name', value: 'Test' },
        { name: 'family_name', value: 'User' },
      ],
      messageAction: 'SUPPRESS',
    });

    // ========================================
    // Lambda Layer for JWT Verification
    // ========================================
    // Bundle the layer at synth time — installs aws-jwt-verify into nodejs/node_modules
    // so the layer zip is self-contained. Avoids shipping node_modules in the source tree.
    const jwtVerifyLayer = new lambda.LayerVersion(this, 'JwtVerifyLayer', {
      layerVersionName: 'jwt-verify-layer',
      description: 'AWS JWT Verify library for token validation',
      compatibleRuntimes: [lambda.Runtime.NODEJS_22_X, lambda.Runtime.NODEJS_20_X],
      code: lambda.Code.fromAsset('lambda-layers/jwt-verify'),
    });

    // ========================================
    // Custom Auth Lambda Functions
    // ========================================

    // Define Auth Challenge Lambda
    const defineAuthChallengeFunction = new lambda.Function(this, 'DefineAuthChallenge', {
      functionName: `${this.stackName}-DefineAuthChallenge`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
        exports.handler = async (event, context) => {
          console.log('Define Auth Challenge event:', JSON.stringify(event, null, 2));
          
          if (event.request.session.length === 0) {
            // First challenge - set custom challenge
            event.response.challengeName = 'CUSTOM_CHALLENGE';
            event.response.issueTokens = false;
          } else if (event.request.session.length === 1 && 
                     event.request.session[0].challengeName === 'CUSTOM_CHALLENGE' &&
                     event.request.session[0].challengeResult === true) {
            // Challenge passed - issue tokens
            event.response.issueTokens = true;
          } else {
            // Challenge failed
            event.response.issueTokens = false;
          }
          
          return event;
        };
      `),
      timeout: cdk.Duration.seconds(30),
      logGroup: sharedLogGroup,
    });

    // Create Auth Challenge Lambda
    const createAuthChallengeFunction = new lambda.Function(this, 'CreateAuthChallenge', {
      functionName: `${this.stackName}-CreateAuthChallenge`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
        exports.handler = async (event, context) => {
          console.log('Create Auth Challenge event:', JSON.stringify(event, null, 2));
          
          if (event.request.challengeName === 'CUSTOM_CHALLENGE') {
            // Create a challenge that expects an access token
            event.response.publicChallengeParameters = {
              challenge: 'Provide your access token for verification'
            };
            event.response.privateChallengeParameters = {
              expectedAnswer: 'ACCESS_TOKEN'
            };
          }
          
          return event;
        };
      `),
      timeout: cdk.Duration.seconds(30),
      logGroup: sharedLogGroup,
    });

    // Verify Auth Challenge Lambda (will be updated after user pool creation)
    const verifyAuthChallengeFunction = new lambda.Function(this, 'VerifyAuthChallenge', {
      functionName: `${this.stackName}-VerifyAuthChallenge`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
        const { CognitoJwtVerifier } = require('aws-jwt-verify');
        const { JwtRsaVerifier } = require('aws-jwt-verify');
        
        // Verifier for Cognito access tokens (original behavior)
        const accessVerifier = CognitoJwtVerifier.create({
          userPoolId: process.env.EXTERNAL_USER_POOL_ID,
          tokenUse: "access",
          clientId: process.env.EXTERNAL_CLIENT_ID,
        });
        
        // Verifier for Cognito ID tokens (for AgentCore Identity OBO flow)
        const idVerifier = CognitoJwtVerifier.create({
          userPoolId: process.env.EXTERNAL_USER_POOL_ID,
          tokenUse: "id",
          clientId: process.env.EXTERNAL_CLIENT_ID,
        });
        
        // Generic JWKS verifier for JWTs from the same issuer (fallback)
        const issuer = \`https://cognito-idp.\${process.env.AWS_REGION}.amazonaws.com/\${process.env.EXTERNAL_USER_POOL_ID}\`;
        const genericVerifier = JwtRsaVerifier.create({
          issuer: issuer,
          jwksUri: \`\${issuer}/.well-known/jwks.json\`,
        });
        
        exports.handler = async (event, context) => {
          console.log('Verify Auth Challenge event:', JSON.stringify(event, null, 2));
          
          try {
            const userToken = event.request.challengeAnswer;
            console.log('Attempting to verify user token...');
            
            let payload;
            
            // Try access token first (original behavior)
            try {
              payload = await accessVerifier.verify(userToken);
              console.log('Verified as Cognito access token');
            } catch (accessErr) {
              console.log('Not a valid access token, trying ID token...');
              
              // Try ID token (needed for AgentCore Identity OBO which sends ID tokens)
              try {
                payload = await idVerifier.verify(userToken);
                console.log('Verified as Cognito ID token');
              } catch (idErr) {
                console.log('Not a valid ID token, trying generic JWT...');
                
                // Try generic JWT verification (just check signature + issuer)
                try {
                  payload = await genericVerifier.verify(userToken);
                  console.log('Verified as generic JWT from trusted issuer');
                } catch (genericErr) {
                  console.error('All verification methods failed');
                  console.error('Access token error:', accessErr.message);
                  console.error('ID token error:', idErr.message);
                  console.error('Generic JWT error:', genericErr.message);
                  throw new Error('Token verification failed: ' + genericErr.message);
                }
              }
            }
            
            console.log('Token verified successfully. Claims:', JSON.stringify(payload, null, 2));
            event.response.answerCorrect = true;
            console.log('Set answerCorrect = true');
            
          } catch (error) {
            console.error('Token verification failed:', error);
            event.response.answerCorrect = false;
            console.log('Set answerCorrect = false due to verification failure');
          }
          
          console.log('Returning event with answerCorrect =', event.response.answerCorrect);
          return event;
        };
      `),
      layers: [jwtVerifyLayer],
      environment: {
        EXTERNAL_USER_POOL_ID: externalIdpUserPool.userPoolId,
        EXTERNAL_CLIENT_ID: externalIdpClient.userPoolClientId,
      },
      timeout: cdk.Duration.seconds(30),
      logGroup: sharedLogGroup,
    });

    // Pre-Token Generation Lambda (will be updated after user pool creation)
    const preTokenGenerationFunction = new lambda.Function(this, 'PreTokenGeneration', {
      functionName: `${this.stackName}-PreTokenGeneration`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      logGroup: sharedLogGroup,
      code: lambda.Code.fromInline(`
        exports.handler = async (event, context) => {
          console.log('Pre-token generation V2_0 event:', JSON.stringify(event, null, 2));
          
          // Skip claim enrichment if delegation claims are disabled
          if (process.env.ENABLE_DELEGATION_CLAIMS === 'false') {
            console.log('Delegation claims disabled - passing through without modification');
            return event;
          }
          
          try {
            if (event.request.clientMetadata && 
                event.request.clientMetadata.TokenExchange === 'true' && 
                event.request.clientMetadata.OriginalUserToken) {
              
              console.log('Token exchange detected - extracting claims from original user token');
              
              const originalToken = event.request.clientMetadata.OriginalUserToken;
              const tokenParts = originalToken.split('.');
              
              if (tokenParts.length !== 3) {
                throw new Error('Invalid JWT token format');
              }
              
              const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
              console.log('Extracted user claims from original token:', JSON.stringify(payload, null, 2));
              
              const serviceScopes = [
                'read:user-profile',
                'read:user-permissions', 
                'write:audit-logs',
                'access:downstream-apis'
              ];
              
              event.response.claimsAndScopeOverrideDetails = {
                accessTokenGeneration: {
                  claimsToAddOrOverride: {
                    'custom:original_sub': payload.sub,
                    'custom:original_username': payload.username || payload.sub,
                    'custom:original_client_id': payload.client_id,
                    'custom:original_iss': payload.iss,
                    'custom:original_scope': payload.scope,
                    'custom:original_auth_time': payload.auth_time?.toString(),
                    'custom:token_exchange': 'true',
                    'custom:service_identity': event.userName, // Use the actual service identity user
                    'custom:service_scopes': serviceScopes.join(' ')
                  },
                  scopesToAdd: serviceScopes,
                  scopesToSuppress: ['aws.cognito.signin.user.admin']
                }
              };
              
              console.log('Claims and scope override details:', JSON.stringify(event.response.claimsAndScopeOverrideDetails, null, 2));
            } else {
              console.log('Not a token exchange request - no modifications applied');
            }
            
          } catch (error) {
            console.error('Pre-token generation error:', error);
          }
          
          console.log('Pre-token generation V2_0 completed');
          return event;
        };
      `),
      environment: {
        ENABLE_DELEGATION_CLAIMS: enableDelegationClaims ? 'true' : 'false',
      },
      timeout: cdk.Duration.seconds(30),
    });

    // ========================================
    // Token Exchange User Pool
    // ========================================
    const tokenExchangeUserPool = new cognito.UserPool(this, 'TokenExchangeUserPool', {
      userPoolName: 'oauth2-token-exchange-pool',
      selfSignUpEnabled: false,
      signInAliases: {
        email: true,
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      lambdaTriggers: {
        defineAuthChallenge: defineAuthChallengeFunction,
        createAuthChallenge: createAuthChallengeFunction,
        verifyAuthChallengeResponse: verifyAuthChallengeFunction,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Add PreTokenGeneration trigger with V2_0 version (required for access token customization)
    // Only attached when delegation claims are enabled
    if (enableDelegationClaims) {
      tokenExchangeUserPool.addTrigger(
        cognito.UserPoolOperation.PRE_TOKEN_GENERATION_CONFIG,
        preTokenGenerationFunction,
        cognito.LambdaVersion.V2_0
      );
    }

    // Service Client (with secret) - Used for API Gateway authentication
    const serviceClientWithSecret = tokenExchangeUserPool.addClient('ServiceClientWithSecret', {
      userPoolClientName: 'service-client-with-secret',
      generateSecret: true,
      authFlows: {
        custom: true,
        userSrp: true,
        userPassword: true,
        adminUserPassword: true,
      },
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(30),
      preventUserExistenceErrors: true,
    });

    // Admin Client (without secret) - Used by Lambda for AdminInitiateAuth
    const adminClientWithoutSecret = tokenExchangeUserPool.addClient('AdminClientWithoutSecret', {
      userPoolClientName: 'admin-client-without-secret',
      generateSecret: false,
      authFlows: {
        custom: true,
      },
      preventUserExistenceErrors: true,
    });

    // ========================================
    // Create 24 Service Identity Users for Load Distribution
    // ========================================
    // 24 identities × 5 TPS per user = 120 TPS capacity
    const createServiceIdentitiesFunction = new lambda.Function(this, 'CreateServiceIdentities', {
      functionName: `${this.stackName}-CreateServiceIdentities`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      timeout: cdk.Duration.seconds(300),
      logGroup: sharedLogGroup,
      code: lambda.Code.fromInline(`
        const { CognitoIdentityProviderClient, AdminCreateUserCommand, AdminSetUserPasswordCommand, AdminGetUserCommand } = require('@aws-sdk/client-cognito-identity-provider');
        const https = require('https');
        const url = require('url');
        
        const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });
        
        exports.handler = async (event, context) => {
          console.log('Creating service identity users:', JSON.stringify(event, null, 2));
          
          if (event.RequestType === 'Delete') {
            console.log('Delete request - returning success');
            await sendResponse(event, context, 'SUCCESS', 'Delete completed');
            return;
          }
          
          try {
            const userPoolId = event.ResourceProperties.UserPoolId;
            const numIdentities = 24;
            
            console.log(\`Creating \${numIdentities} service identity users...\`);
            
            for (let i = 1; i <= numIdentities; i++) {
              const username = \`service-\${i}@tokenexchange.local\`;
              const tempPassword = \`TempPass\${i}!\${Math.random().toString(36).substring(7)}\`;
              
              try {
                await cognitoClient.send(new AdminGetUserCommand({
                  UserPoolId: userPoolId,
                  Username: username
                }));
                console.log(\`User \${username} already exists, skipping creation\`);
              } catch (error) {
                if (error.name === 'UserNotFoundException') {
                  console.log(\`Creating user \${username}...\`);
                  await cognitoClient.send(new AdminCreateUserCommand({
                    UserPoolId: userPoolId,
                    Username: username,
                    UserAttributes: [
                      { Name: 'email', Value: username },
                      { Name: 'email_verified', Value: 'true' }
                    ],
                    TemporaryPassword: tempPassword,
                    MessageAction: 'SUPPRESS'
                  }));
                  
                  const permanentPassword = \`ServicePass\${i}!\${Math.random().toString(36).substring(7)}\`;
                  await cognitoClient.send(new AdminSetUserPasswordCommand({
                    UserPoolId: userPoolId,
                    Username: username,
                    Password: permanentPassword,
                    Permanent: true
                  }));
                  console.log(\`Created user \${username}\`);
                } else {
                  throw error;
                }
              }
            }
            
            console.log(\`Successfully created/verified \${numIdentities} service identity users\`);
            await sendResponse(event, context, 'SUCCESS', \`Created \${numIdentities} service identities\`);
            
          } catch (error) {
            console.error('Error creating service identities:', error);
            await sendResponse(event, context, 'FAILED', error.message);
          }
        };
        
        async function sendResponse(event, context, status, reason) {
          const responseBody = JSON.stringify({
            Status: status,
            Reason: reason || 'See CloudWatch logs',
            PhysicalResourceId: context.logStreamName,
            StackId: event.StackId,
            RequestId: event.RequestId,
            LogicalResourceId: event.LogicalResourceId,
            Data: { Message: reason }
          });
          
          const parsedUrl = url.parse(event.ResponseURL);
          const options = {
            hostname: parsedUrl.hostname,
            port: 443,
            path: parsedUrl.path,
            method: 'PUT',
            headers: {
              'content-type': '',
              'content-length': responseBody.length
            }
          };
          
          return new Promise((resolve, reject) => {
            const request = https.request(options, () => resolve());
            request.on('error', reject);
            request.write(responseBody);
            request.end();
          });
        }
      `),
    });

    // Grant Cognito permissions to create service identities
    createServiceIdentitiesFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'cognito-idp:AdminCreateUser',
          'cognito-idp:AdminSetUserPassword',
          'cognito-idp:AdminGetUser',
        ],
        resources: [tokenExchangeUserPool.userPoolArn],
      })
    );

    // Custom resource to create service identities
    const createServiceIdentitiesProvider = new cr.Provider(this, 'CreateServiceIdentitiesProvider', {
      onEventHandler: createServiceIdentitiesFunction,
    });

    new cdk.CustomResource(this, 'CreateServiceIdentitiesCustomResource', {
      serviceToken: createServiceIdentitiesProvider.serviceToken,
      properties: {
        UserPoolId: tokenExchangeUserPool.userPoolId,
      },
    });

    // ========================================
    // SSM Parameter Store for Client Secret
    // ========================================
    const clientSecretParameter = new ssm.StringParameter(this, 'ServiceClientSecretParameter', {
      parameterName: `/${this.stackName}/service-client-secret`,
      description: 'Service Client credentials for token exchange',
      stringValue: JSON.stringify({
        clientId: 'placeholder',
        clientSecret: 'placeholder',
      }),
      tier: ssm.ParameterTier.STANDARD,
    });

    // Custom Resource to fetch and store client secret
    const storeClientSecretFunction = new lambda.Function(this, 'StoreClientSecret', {
      functionName: `${this.stackName}-StoreClientSecret`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      logGroup: sharedLogGroup,
      code: lambda.Code.fromInline(`
        const { CognitoIdentityProviderClient, DescribeUserPoolClientCommand } = require('@aws-sdk/client-cognito-identity-provider');
        const { SSMClient, PutParameterCommand } = require('@aws-sdk/client-ssm');
        
        exports.handler = async (event, context) => {
          console.log('Custom Resource event:', JSON.stringify(event, null, 2));
          
          if (event.RequestType === 'Delete') {
            console.log('Delete request - returning success');
            await sendResponse(event, context, 'SUCCESS', 'Delete completed');
            return;
          }
          
          try {
            const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });
            const ssmClient = new SSMClient({ region: process.env.AWS_REGION });
            
            console.log('Fetching client secret from Cognito...');
            const describeCommand = new DescribeUserPoolClientCommand({
              UserPoolId: event.ResourceProperties.UserPoolId,
              ClientId: event.ResourceProperties.ClientId
            });
            const cognitoResponse = await cognitoClient.send(describeCommand);
            
            if (!cognitoResponse.UserPoolClient.ClientSecret) {
              throw new Error('Client secret not found');
            }
            
            console.log('Client secret retrieved successfully');
            
            const secretValue = JSON.stringify({
              clientId: cognitoResponse.UserPoolClient.ClientId,
              clientSecret: cognitoResponse.UserPoolClient.ClientSecret
            });
            
            console.log('Storing credentials in SSM Parameter Store...');
            const putCommand = new PutParameterCommand({
              Name: event.ResourceProperties.ParameterName,
              Value: secretValue,
              Type: 'String',
              Overwrite: true,
              Description: 'Service client credentials for OAuth 2.0 token exchange'
            });
            await ssmClient.send(putCommand);
            
            console.log('Credentials stored successfully in SSM');
            await sendResponse(event, context, 'SUCCESS', 'Client secret stored in SSM');
            
          } catch (error) {
            console.error('Error storing client secret:', error);
            await sendResponse(event, context, 'FAILED', error.message);
          }
        };
        
        async function sendResponse(event, context, status, reason) {
          const https = require('https');
          const url = require('url');
          
          const responseBody = JSON.stringify({
            Status: status,
            Reason: reason || 'See CloudWatch logs',
            PhysicalResourceId: context.logStreamName,
            StackId: event.StackId,
            RequestId: event.RequestId,
            LogicalResourceId: event.LogicalResourceId,
            Data: { Message: reason }
          });
          
          const parsedUrl = url.parse(event.ResponseURL);
          const options = {
            hostname: parsedUrl.hostname,
            port: 443,
            path: parsedUrl.path,
            method: 'PUT',
            headers: {
              'content-type': '',
              'content-length': responseBody.length
            }
          };
          
          return new Promise((resolve, reject) => {
            const request = https.request(options, () => resolve());
            request.on('error', reject);
            request.write(responseBody);
            request.end();
          });
        }
      `),
      timeout: cdk.Duration.seconds(60),
    });

    // Grant permissions to the custom resource Lambda
    storeClientSecretFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cognito-idp:DescribeUserPoolClient'],
        resources: [tokenExchangeUserPool.userPoolArn],
      })
    );

    clientSecretParameter.grantWrite(storeClientSecretFunction);

    // Create custom resource provider
    const storeClientSecretProvider = new cr.Provider(this, 'StoreClientSecretProvider', {
      onEventHandler: storeClientSecretFunction,
    });

    // Trigger custom resource
    new cdk.CustomResource(this, 'StoreClientSecretCustomResource', {
      serviceToken: storeClientSecretProvider.serviceToken,
      properties: {
        UserPoolId: tokenExchangeUserPool.userPoolId,
        ClientId: serviceClientWithSecret.userPoolClientId,
        ParameterName: clientSecretParameter.parameterName,
      },
    });

    // ========================================
    // Authorizer Lambda (uses SSM Parameter Store)
    // ========================================
    const authorizerFunction = new lambda.Function(this, 'Authorizer', {
      functionName: `${this.stackName}-Authorizer`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      logGroup: sharedLogGroup,
      code: lambda.Code.fromInline(`
        const { SSMClient, GetParameterCommand } = require('@aws-sdk/client-ssm');
        
        const ssmClient = new SSMClient({ region: process.env.AWS_REGION });
        
        let clientCredentials = null;
        let cacheExpiry = 0;
        const CACHE_TTL = 300000; // 5 minutes
        
        async function getClientCredentials() {
          const now = Date.now();
          
          if (clientCredentials && now < cacheExpiry) {
            console.log('Using cached credentials (TTL remaining:', Math.floor((cacheExpiry - now) / 1000), 'seconds)');
            return clientCredentials;
          }
          
          try {
            console.log('Fetching credentials from SSM Parameter Store');
            const command = new GetParameterCommand({
              Name: process.env.CLIENT_SECRET_PARAMETER
            });
            const response = await ssmClient.send(command);
            
            clientCredentials = JSON.parse(response.Parameter.Value);
            cacheExpiry = now + CACHE_TTL;
            
            console.log('Credentials fetched and cached for 5 minutes');
            return clientCredentials;
          } catch (error) {
            console.error('Failed to retrieve client credentials from SSM:', error);
            throw error;
          }
        }
        
        exports.handler = async (event, context) => {
          console.log('Authorizer event:', JSON.stringify(event, null, 2));
          
          // Helper to get header case-insensitively (API Gateway may lowercase headers)
          const getHeader = (name) => {
            const lower = name.toLowerCase();
            for (const key of Object.keys(event.headers || {})) {
              if (key.toLowerCase() === lower) return event.headers[key];
            }
            return null;
          };
          
          try {
            const contentType = getHeader('Content-Type');
            if (event.httpMethod !== "POST" || 
                !contentType || 
                contentType !== "application/x-www-form-urlencoded") {
              console.log('Method or content type check failed');
              console.log('Content-Type:', contentType);
              return generatePolicy('user', 'Deny', event.methodArn);
            }
            
            const authHeaderValue = getHeader('Authorization');
            if (!authHeaderValue || !authHeaderValue.startsWith("Basic ")) {
              console.log('Authorization header check failed');
              return generatePolicy('user', 'Deny', event.methodArn);
            }
            
            const authHeader = authHeaderValue.substring(6);
            const credentials = Buffer.from(authHeader, 'base64').toString('utf-8');
            const [clientId, clientSecret] = credentials.split(':');
            
            console.log('Extracted clientId:', clientId);
            
            const realCredentials = await getClientCredentials();
            console.log('Expected clientId from SSM:', realCredentials.clientId);
            
            if (clientId === realCredentials.clientId && clientSecret === realCredentials.clientSecret) {
              console.log('Authorization successful - delegation enabled');
              return generatePolicy(clientId, 'Allow', event.methodArn);
            } else {
              console.log('Credential validation failed');
              return generatePolicy('user', 'Deny', event.methodArn);
            }
            
          } catch (error) {
            console.error('Authorizer error:', error);
            return generatePolicy('user', 'Deny', event.methodArn);
          }
        };
        
        function generatePolicy(principalId, effect, resource) {
          return {
            principalId: principalId,
            policyDocument: {
              Version: '2012-10-17',
              Statement: [{
                Action: 'execute-api:Invoke',
                Effect: effect,
                Resource: resource
              }]
            }
          };
        }
      `),
      environment: {
        CLIENT_SECRET_PARAMETER: clientSecretParameter.parameterName,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant SSM read permission to authorizer
    clientSecretParameter.grantRead(authorizerFunction);

    // ========================================
    // Token Exchange Lambda
    // ========================================
    const tokenExchangeFunction = new lambda.Function(this, 'TokenExchange', {
      functionName: `${this.stackName}-TokenExchange`,
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      layers: [jwtVerifyLayer],
      logGroup: sharedLogGroup,
      code: lambda.Code.fromInline(`
        const { CognitoIdentityProviderClient, AdminInitiateAuthCommand, AdminRespondToAuthChallengeCommand } = require('@aws-sdk/client-cognito-identity-provider');
        const { CognitoJwtVerifier } = require('aws-jwt-verify');
        
        const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION });
        
        // Verifier for Cognito access tokens (original)
        const accessVerifier = CognitoJwtVerifier.create({
          userPoolId: process.env.EXTERNAL_USER_POOL_ID,
          tokenUse: "access",
          clientId: process.env.EXTERNAL_CLIENT_ID,
        });
        
        // Verifier for Cognito ID tokens (for AgentCore Identity OBO flow)
        const idVerifier = CognitoJwtVerifier.create({
          userPoolId: process.env.EXTERNAL_USER_POOL_ID,
          tokenUse: "id",
          clientId: process.env.EXTERNAL_CLIENT_ID,
        });
        
        // Accepted subject_token_types (RFC 8693)
        const ACCEPTED_TOKEN_TYPES = [
          "urn:ietf:params:oauth:token-type:access_token",
          "urn:ietf:params:oauth:token-type:jwt",
        ];
        
        function parseFormBody(body) {
          const params = new URLSearchParams(body);
          const result = {};
          for (const [key, value] of params) {
            result[key] = value;
          }
          return result;
        }
        
        exports.handler = async (event) => {
          console.log('Token exchange event:', JSON.stringify(event, null, 2));
          
          try {
            const body = parseFormBody(event.body);
            
            // Validate grant type
            if (body.grant_type !== "urn:ietf:params:oauth:grant-type:token-exchange") {
              return {
                statusCode: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
                body: JSON.stringify({
                  error: 'unsupported_grant_type',
                  error_description: 'Only token exchange grant type is supported'
                }),
              };
            }
            
            // Validate subject_token_type (accept both access_token and jwt)
            if (!ACCEPTED_TOKEN_TYPES.includes(body.subject_token_type)) {
              return {
                statusCode: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
                body: JSON.stringify({
                  error: 'invalid_request',
                  error_description: 'Unsupported subject_token_type: ' + body.subject_token_type + '. Accepted: ' + ACCEPTED_TOKEN_TYPES.join(', ')
                }),
              };
            }
            
            // Verify the subject token — try access token first, then ID token
            let payload;
            try {
              payload = await accessVerifier.verify(body.subject_token);
              console.log('Verified as access token');
            } catch (accessErr) {
              console.log('Not an access token, trying ID token verification...');
              try {
                payload = await idVerifier.verify(body.subject_token);
                console.log('Verified as ID token');
              } catch (idErr) {
                console.error('Token verification failed for both types:', accessErr.message, idErr.message);
                return {
                  statusCode: 401,
                  headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
                  body: JSON.stringify({
                    error: 'invalid_grant',
                    error_description: 'The provided subject token is invalid or expired'
                  }),
                };
              }
            }
            
            // Use round-robin across 24 service identities to support 120 TPS
            // (24 identities × 5 TPS per user = 120 TPS)
            const serviceIdentityIndex = Math.floor(Math.random() * 24);
            const serviceUsername = 'service-' + (serviceIdentityIndex + 1) + '@tokenexchange.local';
            
            console.log('Using service identity: ' + serviceUsername);
            
            const authCommand = new AdminInitiateAuthCommand({
              AuthFlow: 'CUSTOM_AUTH',
              ClientId: process.env.ADMIN_CLIENT_ID,
              UserPoolId: process.env.USER_POOL_ID,
              AuthParameters: {
                USERNAME: serviceUsername,
              },
              ClientMetadata: {
                Step: 'AT_CHALLENGE',
                UserClaims: JSON.stringify({
                  sub: payload.sub,
                  username: payload['cognito:username'] || payload.username || payload.sub,
                  client_id: payload.client_id || payload.aud,
                  iss: payload.iss,
                  email: payload.email,
                })
              }
            });
            
            const authResponse = await cognitoClient.send(authCommand);
            
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
            
            const challengeResponse = await cognitoClient.send(challengeCommand);
            
            return {
              statusCode: 200,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
              },
              body: JSON.stringify({
                access_token: challengeResponse.AuthenticationResult.AccessToken,
                token_type: 'Bearer',
                expires_in: challengeResponse.AuthenticationResult.ExpiresIn,
                issued_token_type: 'urn:ietf:params:oauth:token-type:access_token'
              }),
            };
            
          } catch (error) {
            console.error('Token exchange error:', error);
            return {
              statusCode: 500,
              headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
              },
              body: JSON.stringify({
                error: 'server_error',
                error_description: 'Internal server error during token exchange'
              }),
            };
          }
        };
      `),
      environment: {
        EXTERNAL_USER_POOL_ID: externalIdpUserPool.userPoolId,
        EXTERNAL_CLIENT_ID: externalIdpClient.userPoolClientId,
        USER_POOL_ID: tokenExchangeUserPool.userPoolId,
        ADMIN_CLIENT_ID: adminClientWithoutSecret.userPoolClientId,
      },
      timeout: cdk.Duration.seconds(30),
    });

    // Grant Cognito permissions to token exchange Lambda
    tokenExchangeFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'cognito-idp:AdminInitiateAuth',
          'cognito-idp:AdminRespondToAuthChallenge',
        ],
        resources: [tokenExchangeUserPool.userPoolArn],
      })
    );

    // ========================================
    // API Gateway
    // ========================================
    const api = new apigateway.RestApi(this, 'TokenExchangeApi', {
      restApiName: 'OAuth2 Token Exchange API',
      description: 'API for OAuth 2.0 token exchange using Cognito',
      deployOptions: {
        stageName: 'v1',
        throttlingRateLimit: 100,
        throttlingBurstLimit: 200,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: true,
        metricsEnabled: true,
        accessLogDestination: new apigateway.LogGroupLogDestination(apiAccessLogGroup),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields({
          caller: true,
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          user: true,
        }),
      },
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization'],
      },
    });
    
    // Add request validator for the API
    const requestValidator = new apigateway.RequestValidator(this, 'TokenExchangeRequestValidator', {
      restApi: api,
      requestValidatorName: 'token-exchange-validator',
      validateRequestBody: true,
      validateRequestParameters: true,
    });

    // Create custom authorizer
    const authorizer = new apigateway.RequestAuthorizer(this, 'TokenExchangeAuthorizer', {
      handler: authorizerFunction,
      identitySources: [apigateway.IdentitySource.header('Authorization')],
      resultsCacheTtl: cdk.Duration.minutes(5),
    });

    // Token exchange resource
    const tokenExchangeResource = api.root.addResource('token-exchange');

    // POST method with custom authorizer and request validation
    tokenExchangeResource.addMethod(
      'POST',
      new apigateway.LambdaIntegration(tokenExchangeFunction),
      {
        authorizer: authorizer,
        authorizationType: apigateway.AuthorizationType.CUSTOM,
        requestValidator: requestValidator,
      }
    );

    // ========================================
    // Outputs
    // ========================================
    new cdk.CfnOutput(this, 'ExternalUserPoolId', {
      value: externalIdpUserPool.userPoolId,
      description: 'External IDP User Pool ID for token generation',
      exportName: `${this.stackName}-ExternalUserPoolId`,
    });

    new cdk.CfnOutput(this, 'ExternalUserPoolClientId', {
      value: externalIdpClient.userPoolClientId,
      description: 'External IDP User Pool Client ID for token generation',
      exportName: `${this.stackName}-ExternalUserPoolClientId`,
    });

    new cdk.CfnOutput(this, 'TokenExchangeUserPoolId', {
      value: tokenExchangeUserPool.userPoolId,
      description: 'Token Exchange User Pool ID',
      exportName: `${this.stackName}-UserPoolId`,
    });

    new cdk.CfnOutput(this, 'ServiceClientId', {
      value: serviceClientWithSecret.userPoolClientId,
      description: 'Service Client ID (with secret) for API Gateway authentication',
      exportName: `${this.stackName}-ServiceClientId`,
    });

    new cdk.CfnOutput(this, 'ApiGatewayUrl', {
      value: api.url,
      description: 'API Gateway URL for token exchange',
      exportName: `${this.stackName}-ApiGatewayUrl`,
    });

    new cdk.CfnOutput(this, 'TokenExchangeEndpoint', {
      value: `${api.url}token-exchange`,
      description: 'Token exchange endpoint URL',
      exportName: `${this.stackName}-TokenExchangeEndpoint`,
    });

    new cdk.CfnOutput(this, 'SSMParameterName', {
      value: clientSecretParameter.parameterName,
      description: 'SSM Parameter Store path containing service client credentials',
      exportName: `${this.stackName}-SSMParameterName`,
    });

    new cdk.CfnOutput(this, 'SSMParameterCommand', {
      value: `aws ssm get-parameter --name ${clientSecretParameter.parameterName} --region ${this.region}`,
      description: 'Command to view stored credentials',
    });

    new cdk.CfnOutput(this, 'TestUserCredentials', {
      value: 'Username: testuser@example.com, Password: Set via Cognito Console',
      description: 'Test user credentials for the external User Pool',
    });
  }
}
