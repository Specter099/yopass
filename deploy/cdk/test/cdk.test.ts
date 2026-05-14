import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import * as Cdk from "../lib/cdk-stack";

// Use a deterministic asset path that exists (and isn't huge) so
// BucketDeployment can hash a folder.
const TEST_ASSET_PATH = __dirname;
const TEST_DOMAIN = "yopass.example.com";

function makeTemplate(): Template {
  const app = new cdk.App();
  const stack = new Cdk.CdkStack(app, "TestStack", {
    env: { account: "111111111111", region: "us-east-1" },
    domainName: TEST_DOMAIN,
    // No hostedZoneName: fromLookup would require live AWS context. Operators
    // who don't have Route 53 will point DNS at the CloudFront output manually.
    assetPath: TEST_ASSET_PATH,
  });
  return Template.fromStack(stack);
}

describe("Yopass CDK Stack", () => {
  let template: Template;

  beforeAll(() => {
    template = makeTemplate();
  });

  describe("DynamoDB Table", () => {
    test("is on-demand (PAY_PER_REQUEST) so bursts don't get throttled", () => {
      template.hasResourceProperties("AWS::DynamoDB::Table", {
        TableName: "yopass",
        BillingMode: "PAY_PER_REQUEST",
        AttributeDefinitions: [{ AttributeName: "id", AttributeType: "S" }],
        KeySchema: [{ AttributeName: "id", KeyType: "HASH" }],
        TimeToLiveSpecification: { AttributeName: "ttl", Enabled: true },
      });
    });

    test("does NOT have provisioned throughput", () => {
      // PAY_PER_REQUEST tables must omit ProvisionedThroughput entirely.
      const tables = template.findResources("AWS::DynamoDB::Table");
      for (const t of Object.values(tables)) {
        expect((t as any).Properties.ProvisionedThroughput).toBeUndefined();
      }
    });

    test("retains on stack deletion", () => {
      template.hasResource("AWS::DynamoDB::Table", {
        UpdateReplacePolicy: "Retain",
        DeletionPolicy: "Retain",
      });
    });
  });

  describe("Lambda Function", () => {
    test("has correct runtime, architecture, and env vars", () => {
      template.hasResourceProperties("AWS::Lambda::Function", {
        Runtime: "provided.al2",
        Handler: "bootstrap",
        MemorySize: 128,
        Architectures: ["arm64"],
        Timeout: 29,
        Environment: {
          Variables: {
            TABLE_NAME: "yopass",
            MAX_LENGTH: "10000",
            MAX_FILE_SIZE: "128KB",
          },
        },
      });
    });

    test("has DynamoDB read/write permissions", () => {
      template.hasResourceProperties("AWS::IAM::Policy", {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: Match.arrayWith([Match.stringLikeRegexp("dynamodb:.*")]),
              Effect: "Allow",
            }),
          ]),
        },
      });
    });
  });

  describe("S3 SPA bucket", () => {
    test("blocks all public access, encrypts at rest, requires TLS", () => {
      template.hasResourceProperties("AWS::S3::Bucket", {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
        BucketEncryption: {
          ServerSideEncryptionConfiguration: Match.arrayWith([
            Match.objectLike({
              ServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" },
            }),
          ]),
        },
      });
    });

    test("has a bucket policy that requires TLS-only access", () => {
      template.hasResourceProperties("AWS::S3::BucketPolicy", {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Effect: "Deny",
              Condition: {
                Bool: { "aws:SecureTransport": "false" },
              },
            }),
          ]),
        },
      });
    });
  });

  describe("CloudFront distribution", () => {
    test("serves the configured custom domain over TLS 1.2+", () => {
      template.hasResourceProperties("AWS::CloudFront::Distribution", {
        DistributionConfig: Match.objectLike({
          Aliases: [TEST_DOMAIN],
          ViewerCertificate: Match.objectLike({
            MinimumProtocolVersion: "TLSv1.2_2021",
            SslSupportMethod: "sni-only",
          }),
        }),
      });
    });

    test("routes API paths to API Gateway and everything else to S3", () => {
      template.hasResourceProperties("AWS::CloudFront::Distribution", {
        DistributionConfig: Match.objectLike({
          DefaultRootObject: "index.html",
          CacheBehaviors: Match.arrayWith([
            Match.objectLike({ PathPattern: "/create/*" }),
            Match.objectLike({ PathPattern: "/secret/*" }),
            Match.objectLike({ PathPattern: "/file/*" }),
            Match.objectLike({ PathPattern: "/auth/*" }),
            Match.objectLike({ PathPattern: "/config" }),
            Match.objectLike({ PathPattern: "/version" }),
            Match.objectLike({ PathPattern: "/health" }),
            Match.objectLike({ PathPattern: "/ready" }),
          ]),
        }),
      });
    });

    test("has an Origin Access Control attached to the S3 origin", () => {
      template.hasResourceProperties("AWS::CloudFront::OriginAccessControl", {
        OriginAccessControlConfig: Match.objectLike({
          OriginAccessControlOriginType: "s3",
          SigningBehavior: "always",
          SigningProtocol: "sigv4",
        }),
      });
    });

    test("has a CloudFront Function for SPA path rewrites", () => {
      template.hasResourceProperties("AWS::CloudFront::Function", {
        FunctionConfig: Match.objectLike({ Runtime: "cloudfront-js-2.0" }),
      });
    });

    test("API cache policy forwards X-Requested-With and X-Yopass-* headers", () => {
      template.hasResourceProperties("AWS::CloudFront::CachePolicy", {
        CachePolicyConfig: Match.objectLike({
          ParametersInCacheKeyAndForwardedToOrigin: Match.objectLike({
            HeadersConfig: Match.objectLike({
              HeaderBehavior: "whitelist",
              Headers: Match.arrayWith([
                "X-Requested-With",
                "X-Yopass-Expiration",
                "X-Yopass-OneTime",
                "X-Yopass-RequireAuth",
              ]),
            }),
          }),
        }),
      });
    });
  });

  describe("ACM Certificate", () => {
    test("is for the configured domain, DNS-validated", () => {
      template.hasResourceProperties("AWS::CertificateManager::Certificate", {
        DomainName: TEST_DOMAIN,
        ValidationMethod: "DNS",
      });
    });
  });

  describe("API Gateway", () => {
    test("is a regional endpoint (CloudFront origin)", () => {
      template.hasResourceProperties("AWS::ApiGateway::RestApi", {
        Name: "yopass",
        EndpointConfiguration: { Types: ["REGIONAL"] },
      });
    });

    test("has Lambda proxy integration", () => {
      template.hasResourceProperties("AWS::ApiGateway::Method", {
        AuthorizationType: "NONE",
        HttpMethod: "ANY",
        Integration: { IntegrationHttpMethod: "POST", Type: "AWS_PROXY" },
      });
    });

    test("declares application/octet-stream as a binary type for file streaming", () => {
      template.hasResourceProperties("AWS::ApiGateway::RestApi", {
        BinaryMediaTypes: ["application/octet-stream"],
      });
    });

    test("has a usage plan with daily quota and per-second throttling", () => {
      template.hasResourceProperties("AWS::ApiGateway::UsagePlan", {
        Quota: { Limit: 10000, Period: "DAY" },
        Throttle: { BurstLimit: 25, RateLimit: 50 },
      });
    });

    test("does NOT create its own custom domain (CloudFront fronts everything)", () => {
      const domains = template.findResources("AWS::ApiGateway::DomainName");
      expect(Object.keys(domains)).toHaveLength(0);
    });
  });

  describe("Outputs", () => {
    test("emits AppURL, DistributionDomainName, and ApiGatewayURL", () => {
      const outputs = template.toJSON().Outputs;
      const keys = Object.keys(outputs);
      expect(keys.some((k) => k.startsWith("AppURL"))).toBe(true);
      expect(keys.some((k) => k.startsWith("DistributionDomainName"))).toBe(true);
      expect(keys.some((k) => k.startsWith("ApiGatewayURL"))).toBe(true);
    });
  });

  describe("Resource counts", () => {
    test("provisions exactly one Lambda, one DynamoDB table, one CloudFront distribution, one S3 SPA bucket", () => {
      const resources = template.toJSON().Resources;
      const counts: Record<string, number> = {};
      for (const r of Object.values(resources)) {
        const t = (r as any).Type;
        counts[t] = (counts[t] ?? 0) + 1;
      }

      expect(counts["AWS::DynamoDB::Table"]).toBe(1);
      expect(counts["AWS::Lambda::Function"]).toBeGreaterThanOrEqual(1); // includes BucketDeployment helper lambda
      expect(counts["AWS::ApiGateway::RestApi"]).toBe(1);
      expect(counts["AWS::CloudFront::Distribution"]).toBe(1);
      expect(counts["AWS::CertificateManager::Certificate"]).toBe(1);
      // SPA bucket + BucketDeployment helper bucket — count at least 1.
      expect(counts["AWS::S3::Bucket"]).toBeGreaterThanOrEqual(1);
    });
  });
});
