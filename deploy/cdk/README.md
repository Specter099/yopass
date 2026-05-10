# Serverless deployment for Yopass on AWS

This CDK stack provisions a complete Yopass install on AWS using only serverless
services. No EC2, no ECS, no containers to operate.

## Architecture

```
Route 53 (optional) ──► CloudFront ──┬─► S3 bucket (private, OAC)   ← SPA
                                     └─► API Gateway ──► Lambda    ← Go server
                                                            │
                                                            ▼
                                                        DynamoDB
```

| Component | Service | Notes |
|-----------|---------|-------|
| Frontend (SPA) | S3 + CloudFront | Private bucket, served through Origin Access Control. A CloudFront Function rewrites extension-less paths to `/index.html` for direct navigation to SPA routes. |
| API | API Gateway REST + Lambda | Regional API Gateway behind CloudFront. Lambda runs the Go binary on `provided.al2`/`arm64`. |
| Storage | DynamoDB | On-demand billing, native TTL for expiration, item-per-secret. |
| TLS | ACM (us-east-1) | DNS-validated through Route 53 when a `hostedZoneName` is provided; manual otherwise. |
| DNS | Route 53 (optional) | Set `hostedZoneName` and the stack adds an A-record alias. |

## Prerequisites

- AWS account, AWS CLI configured
- Node 24+, Go 1.21+
- A registered domain
- The stack **must** deploy in `us-east-1` because CloudFront requires its
  certificate to live there

## Deploy

```sh
# 1. Build the website (run from repo root, not deploy/cdk).
cd ../../website && yarn install && yarn build && cd -

# 2. Build the Lambda binary and bundle it as deployment.zip.
npm install
npm run build       # tsc + GOOS=linux GOARCH=arm64 go build + zip

# 3. Deploy. Replace the placeholders with your real values.
npx cdk deploy \
    -c domainName=yopass.example.com \
    -c hostedZoneName=example.com
```

`hostedZoneName` is optional. Without it, the stack still creates the
certificate and the distribution; you'll need to:

1. Add the DNS validation CNAME shown in the ACM console (or in the CDK
   deploy output) to your DNS provider.
2. After validation, point `yopass.example.com` at the CloudFront
   `DistributionDomainName` from the stack output (CNAME if not at the
   apex, ALIAS / ANAME otherwise).

## Outputs

```
AppURL                  https://yopass.example.com
DistributionDomainName  d111111abcdef8.cloudfront.net
ApiGatewayURL           https://abc123.execute-api.us-east-1.amazonaws.com/prod/
```

## Cost (back-of-envelope, us-east-1)

At ~10k requests/day and ~1 GB/month egress: roughly **$2–5/month**. AWS free
tier covers most of it at small scale.

- Lambda: ~$0 (covered by free tier at this volume)
- API Gateway REST: $3.50 per 1M requests + $0.09/GB egress
- DynamoDB on-demand: $1.25/1M writes, $0.25/1M reads, $0.25/GB-month storage
- CloudFront: $0.085/GB egress (US/EU) + $0.0100/10k requests; free tier
  includes 1 TB egress + 10M requests
- S3: pennies for ~100 MB of SPA assets
- Route 53 hosted zone: $0.50/month

The dominant cost at scale is CloudFront egress on the SPA bundle (~700 KB
gzipped at the time of writing). At 1M page loads/month, expect ~$60/month
CloudFront.

## Useful commands

| Command | What it does |
|---------|--------------|
| `npm run build` | Compile TS, cross-compile Go for Lambda, build deployment.zip |
| `npm test` | Run Jest tests against the synthesized template |
| `npx cdk diff -c domainName=…` | Show diff vs deployed stack |
| `npx cdk synth -c domainName=…` | Emit CloudFormation template |
| `npx cdk destroy` | Tear down (note: DynamoDB and S3 bucket retain by default) |

## Limitations

- **`MAX_FILE_SIZE: 128KB`** is hard-coded in the Lambda environment because
  files are base64'd into DynamoDB items (max 400 KB). For larger files,
  switch the file store to S3 — that requires changes in `main.go` (use
  `server.NewS3FileStore` instead of `server.NewDatabaseFileStore`) plus an
  S3 bucket in this stack.
- **Client IP logging** is not faithful in this deployment. The Lambda sees
  the CloudFront/API-Gateway hop, not the real client IP. yopass-server's
  `--trusted-proxies` mechanism can't help here because the trusted peer
  set is operationally infeasible to enumerate. Audit logging is also not
  enabled in this build, so this only affects access logs.
- **OIDC authentication** is not wired up in this build. The Lambda's
  `main.go` constructs a minimal `server.Server` without an `OIDCProvider`.
  If you need OIDC, extend `main.go` to call `server.NewOIDCProvider` and
  add the relevant env vars to this stack (plus a license key — OIDC is a
  premium feature).
