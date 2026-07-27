# Threat Model — sample-cognito-oauth2-token-exchange (STRIDE)

**Scope:** The OAuth 2.0 Token Exchange (RFC 8693) reference implementation on Amazon Cognito — API Gateway + Lambda authorizer + TokenExchange Lambda + custom-auth challenge Lambdas + PreTokenGeneration trigger + two Cognito user pools + SSM Parameter Store.
**Status:** Reflects the hardened publication tree after the external security review. Findings P0 (SSM SecureString, log redaction, verifier pinning) and P1 (constant-time compare, scope-ceiling enforcement, demo-secret warning) resolved 2026-07-09, plus the ID-token consistency note. **Verified live end-to-end** (deployed stack, happy + non-happy matrix — see Verification status). See "Security review resolution" below.
**Methodology:** STRIDE per element + data-flow trust-boundary analysis.

## Architecture & data flow

```
[User] --auth--> External IdP (Cognito Pool A) --user access token (subject_token)-->
[Client/Agent] --POST /v1/token-exchange  (Basic client_id:secret + subject_token)-->
[API Gateway] --> [Lambda Authorizer] (validate client creds vs SSM SecureString, constant-time)
             --> [TokenExchange Lambda] (aws-jwt-verify subject_token vs Pool A, pinned;
                                          reject out-of-ceiling requested scope -> 400 invalid_scope)
                     --> AdminInitiateAuth CUSTOM_AUTH on Service IdP (Cognito Pool B)
                         --> Define/Create/VerifyAuthChallenge (aws-jwt-verify again, pinned)
                         --> PreTokenGeneration (verify token, attach custom:original_* claims, bound scopes to service ceiling)
             <-- exchanged access token (sub=service identity, custom:original_sub=user)
[Client] --Bearer exchanged token--> [Downstream API / MCP server]
```

## Trust boundaries
- **TB1 Internet → API Gateway** — untrusted callers; gated by client credentials (Basic auth) at the Lambda authorizer (constant-time comparison).
- **TB2 API Gateway → TokenExchange Lambda** — request carries the caller's `subject_token`.
- **TB3 clientMetadata → PreTokenGeneration** — `OriginalUserToken` is caller-influenced passthrough; **Cognito does not validate it** → re-verified cryptographically in the trigger.
- **TB4 Lambda → Cognito (AdminInitiateAuth)** — uses the Lambda task role (admin API).
- **TB5 Lambda → SSM Parameter Store** — SecureString retrieval, IAM-scoped to the exact ARN + KMS via `kms:ViaService`.
- **TB6 Lambda → External IdP JWKS** — `aws-jwt-verify` fetches public keys over TLS.

## Assets
- A1 User access tokens (subject tokens) · A2 Exchanged service/delegated tokens · A3 Service client secret (SSM **SecureString**, AWS-managed key) · A4 Service-identity Cognito user credentials · A5 Cognito signing keys (AWS-managed) · A6 Delegation/audit claims (`custom:original_*`).

## STRIDE analysis

### Spoofing
| ID | Threat | Existing mitigation | Residual risk / recommendation |
|---|---|---|---|
| S1 | Attacker forges/replays a `subject_token` to obtain a delegated token | `aws-jwt-verify` validates signature/expiry/audience at TokenExchange Lambda **and** VerifyAuthChallenge **and** PreTokenGeneration (fail-closed). Every verifier is **pinned** to the External IdP pool + client ID + `tokenUse`; the issuer-only "generic" fallback has been **removed** | Short token TTLs. Low residual. (Proven live: invalid token → 401.) |
| S2 | Unauthorized client calls the exchange endpoint | Lambda authorizer validates `client_id:client_secret` (Basic) against SSM before the Lambda runs, using a **constant-time** comparison | Basic-auth secret is long-lived — rotate regularly; consider mTLS/OAuth client-credentials for the front door in production. (Proven live: bad secret → 403.) |
| S3 | Forged `clientMetadata.OriginalUserToken` to inject a different user (TB3) | PreTokenGeneration **cryptographically verifies** the token before trusting claims (fail-closed) — closes the VerifyAuth-vs-PreTokenGen coupling gap | If a **public** (non-admin) `InitiateAuth` path to Pool B exists, an attacker could drive the flow directly; keep the exchange path admin-only. Verify Pool B app clients don't expose `ALLOW_CUSTOM_AUTH` to unauthenticated `InitiateAuth`. |

### Tampering
| ID | Threat | Existing mitigation | Residual risk / recommendation |
|---|---|---|---|
| T1 | Modify token in transit | TLS on API Gateway + Cognito; JWT signature verification | Enforce HTTPS-only; low residual. |
| T2 | Tamper with exchanged token claims | Token signed by Cognito Pool B; downstream verifies signature | Downstream **must** verify the signature and issuer, not just decode. Documented for consumers. |
| T3 | Tamper with / read the service client secret in SSM | Stored as **SecureString**; `ssm:GetParameter`/`PutParameter`/`DeleteParameter` scoped to the exact parameter ARN; `kms:*` constrained to SSM via `kms:ViaService` | Audit access; rotate on a schedule. Low residual. (Proven live: parameter `Type=SecureString`.) |

### Repudiation
| ID | Threat | Existing mitigation | Residual risk / recommendation |
|---|---|---|---|
| R1 | A service denies acting for a user | Delegation claims (`custom:original_sub`, `custom:original_client_id`, service `sub`) preserve who authorized + what executed | Log every exchange to CloudWatch + enable CloudTrail. Logs capture caller client_id + original_sub (never the token). |

### Information disclosure
| ID | Threat | Existing mitigation | Residual risk / recommendation |
|---|---|---|---|
| I1 | Leaked client secret | Stored in SSM **SecureString**; **rotated** after the earlier repo-history exposure; scrubbed from source; the browser demo carries an explicit "confidential secret is backend-only" warning | Rotate on a schedule; never log the secret; consider Secrets Manager with rotation. |
| I2 | Over-scoped exchanged token exposes downstream APIs | PreTokenGeneration grants only scopes within the service ceiling and **suppresses** `aws.cognito.signin.user.admin` | Add `aud`/resource restriction so tokens can't be replayed against other services (production hardening). |
| I3 | Sensitive claims/tokens in logs | Lambdas do **not** log raw events, tokens, or claims (only non-sensitive identifiers such as `sub`); API Gateway **data-trace logging disabled** | Low residual. Keep any added logging free of token material. |
| I4 | Env vars expose config | Only non-secret pool/client IDs in env; secrets in SSM SecureString (checkov CKV_AWS_173 justified) | Accepted for sample; use CMK-encrypted env in high-assurance deployments. |

### Denial of service
| ID | Threat | Existing mitigation | Residual risk / recommendation |
|---|---|---|---|
| D1 | Flood the exchange endpoint | API Gateway throttling | Set explicit throttling/usage plans; add WAFv2 (cdk-nag APIG3 — suppressed as sample simplicity) in production. |
| D2 | JWKS fetch amplification / IdP dependency | `aws-jwt-verify` caches JWKS | Bounded; monitor External IdP availability. |
| D3 | No per-function concurrency cap (checkov CKV_AWS_115, justified) | — | Set reserved concurrency in production to contain cost/DoS. |

### Elevation of privilege
| ID | Threat | Existing mitigation | Residual risk / recommendation |
|---|---|---|---|
| E1 | Exchange yields **more** privilege than intended | Granted scopes are bounded by a fixed **service scope ceiling**, enforced in **two places**: the TokenExchange Lambda rejects any out-of-ceiling requested scope up front with **`400 invalid_scope`**, and PreTokenGeneration independently rejects it (fail-closed, defense-in-depth). A caller may request a subset via the RFC 8693 `scope` parameter; the exchange can never escalate past the service's own grant | By design the delegated token carries the *service's* scopes exercised on the user's behalf (delegation), not a copy of the user's scopes. Enforce **per-user** authorization at the resource (e.g. Amazon Verified Permissions on `custom:original_sub`). (Proven live: over-request → 400 invalid_scope; valid subset → only that scope.) |
| E2 | Lambda task role over-privileged (esp. `iam:PassRole`) | Deploy-doc IAM example scoped: no `iam:*`, `PassRole` limited to stack roles + `iam:PassedToService=lambda` (ACAT fix); runtime roles scoped to the exact SSM param ARN + `AdminInitiateAuth`/`AdminRespondToAuthChallenge` on Pool B; KMS constrained via `kms:ViaService`; cdk-nag/checkov clean | Verify no wildcard grants in the deployed roles. |
| E3 | Service-identity credential guessing | Passwords generated with `crypto.randomBytes` (was `Math.random`) | Consider not persisting standing service-user passwords at all; rotate. |

## Key assumptions
- The External IdP and Service IdP are Cognito user pools under the deployer's control.
- The exchange endpoint is reachable only by clients holding valid credentials; the custom-auth mint path is admin-only (`AdminInitiateAuth` from the Lambda), not exposed to anonymous `InitiateAuth`.
- Downstream resource servers independently verify the exchanged token's signature, issuer, audience, and scopes, and enforce per-user authorization.
- Deployers run on the Essentials/Plus Cognito feature plan (required for access-token customization).

## Subject-token type note
Both stacks accept **access** and **ID** subject tokens (MCP 3LO and AgentCore OBO respectively); every verifier pins client ID + `tokenUse`, and PreTokenGeneration verifies whichever type arrived, so the delegated-claims path works end-to-end for both (resolves the review's ID-token inconsistency).

## Security review resolution (2026-07-09)
External security review findings addressed in code:
- **P0-1 SecureString:** service-client secret now stored/read as SSM `SecureString`; the custom resource creates it as SecureString (CFN/SSM cannot create one via `AWS::SSM::Parameter`), reads use `WithDecryption`, IAM scoped to the exact ARN + `kms:ViaService`.
- **P0-2 Log redaction:** removed all raw-event / token / claims logging across the Lambdas; `dataTraceEnabled`/`DataTraceEnabled` set to `false`.
- **P0-3 Verifier pinning:** removed the issuer-only generic verifier; all verification is pinned to client ID + `tokenUse`.
- **P1-5 Constant-time compare:** authorizer uses `crypto.timingSafeEqual` (length-guarded) for client id + secret.
- **P1-6 Scope enforcement:** delegated scopes bounded by the service ceiling; the TokenExchange Lambda returns **`400 invalid_scope`** for out-of-ceiling requested scopes, with PreTokenGeneration enforcing the same as defense-in-depth (fail-closed).
- **P1-7 Demo secret:** prominent backend-only warning added to the demo; CORS origin made configurable (`-c corsAllowOrigin=...`).
- **Note (ID-token path):** fixed by verifying access **and** ID subject tokens consistently (CDK).

## Accepted residual risks (sample simplicity — documented)
- No WAF on the API (cdk-nag `APIG3`), no MFA on pools (`COG2`), not on Plus tier / advanced threat protection (`COG8`), no Lambda DLQ (`CKV_AWS_116`), no reserved concurrency (`CKV_AWS_115`), Lambdas not in a VPC (`CKV_AWS_117` — triggers need public JWKS egress), env vars not CMK-encrypted (`CKV_AWS_173`). Each is justified in-code for a demonstration sample and should be revisited for production (see the README "Security considerations" section).

## Verification status
- **Static analysis clean:** cfn-lint 0/0, checkov 0 failed/32 skipped (justified), cdk-nag 0/0, npm audit 0 vulns, inline Lambda JS `node --check` clean (16/16).
- **Mandated ACAT code scan:** 0 findings (after the IAM `PassRole` fix).
- **External security review:** P0 + P1 resolved 2026-07-09; P2 items documented as production hardening.
- **Live end-to-end verification (2026-07-09):** the CDK stack was deployed to AWS and exercised through the complete RFC 8693 flow (real Cognito authentication + real HTTPS exchange + real JWT decode) via `e2e-test-matrix.sh` — **24/24 assertions passed**:
  - *Happy path:* default exchange → 200 with delegation claims (`sub`=service, `custom:original_sub`=user, `custom:token_exchange=true`, full ceiling scopes); single- and multi-scope down-scoping honoured (only requested scopes present).
  - *Non-happy path:* out-of-ceiling scope → 400 `invalid_scope`; partially-invalid scope → 400 `invalid_scope`; invalid/garbage subject token → 401 `invalid_grant` (fail-closed); bad grant_type → 400; bad client secret → 403; missing Authorization header → 401 (API Gateway, pre-authorizer).
  - SSM parameter confirmed `Type=SecureString` against the live deployment.
  - The `e2e-test-matrix.sh` script is committed to the repo and is CI-runnable for regression.
