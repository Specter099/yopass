import * as cdk from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as apigw from "aws-cdk-lib/aws-apigateway";
import * as dynamo from "aws-cdk-lib/aws-dynamodb";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as cf from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as targets from "aws-cdk-lib/aws-route53-targets";
import { Construct } from "constructs";

export interface CdkStackProps extends cdk.StackProps {
  /** Public hostname for the deployed Yopass instance (e.g. yopass.example.com). */
  domainName: string;

  /**
   * Route 53 hosted zone name (e.g. "example.com"). When provided, the stack
   * creates an ACM certificate via DNS validation in this zone and adds an
   * A-record alias to the CloudFront distribution. When omitted the operator
   * must validate the certificate and point DNS manually (CloudFront domain
   * is in the stack output).
   *
   * Requires the stack `env.account` and `env.region` to be set so `fromLookup`
   * can resolve the zone.
   */
  hostedZoneName?: string;

  /** Path to the built SPA (defaults to ../../website/dist relative to cdk.json). */
  assetPath?: string;
}

/**
 * Single-stack serverless deployment of Yopass.
 *
 *   Route 53 (optional) ──► CloudFront ──┬─► S3 bucket (private, OAC)   ← SPA
 *                                        └─► API Gateway ──► Lambda    ← Go server
 *                                                              │
 *                                                              ▼
 *                                                          DynamoDB
 *
 * IMPORTANT: deploy this stack in **us-east-1**. CloudFront requires its ACM
 * certificate to live in us-east-1 and this stack provisions everything in a
 * single region. If you need regional locality for the Lambda/DynamoDB (e.g.
 * eu-west-1), split the certificate into a separate us-east-1 stack and use
 * cross-region references — that's a one-line edit to bin/cdk.ts.
 */
export class CdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: CdkStackProps) {
    super(scope, id, props);

    const { domainName, hostedZoneName, assetPath = "../../website/dist" } = props;
    const hostedZone = hostedZoneName
      ? route53.HostedZone.fromLookup(this, "HostedZone", { domainName: hostedZoneName })
      : undefined;

    // DynamoDB
    //
    // Pay-per-request: Yopass traffic is bursty (one access per shared secret,
    // often within seconds of creation). Provisioned capacity would either
    // throttle bursts or sit idle. On-demand also removes a tuning surface.
    const table = new dynamo.Table(this, "YopassTable", {
      tableName: "yopass",
      partitionKey: { name: "id", type: dynamo.AttributeType.STRING },
      timeToLiveAttribute: "ttl",
      billingMode: dynamo.BillingMode.PAY_PER_REQUEST,
      // Destroy on stack deletion. Secrets in this DB are short-lived (TTL),
      // so there's nothing worth retaining; RETAIN orphans the table on a
      // failed first-deploy and blocks subsequent attempts.
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Lambda (Go binary built into deployment.zip via npm run build)
    const serverLambda = new lambda.Function(this, "Yopass", {
      runtime: lambda.Runtime.PROVIDED_AL2,
      handler: "bootstrap",
      code: lambda.Code.fromAsset("deployment.zip"),
      memorySize: 128,
      architecture: lambda.Architecture.ARM_64,
      timeout: cdk.Duration.seconds(29), // just under API Gateway's 30s hard cap
      environment: {
        TABLE_NAME: "yopass",
        MAX_LENGTH: "10000",
        // Files are base64'd into DynamoDB items (max 400 KB). 128 KB raw
        // ≈ 170 KB base64 — well under the limit.
        MAX_FILE_SIZE: "128KB",
      },
    });
    table.grantReadWriteData(serverLambda);

    // API Gateway (regional, no custom domain — CloudFront fronts everything)
    const gateway = new apigw.LambdaRestApi(this, "Gateway", {
      handler: serverLambda,
      restApiName: "yopass",
      binaryMediaTypes: ["application/octet-stream"],
      endpointConfiguration: { types: [apigw.EndpointType.REGIONAL] },
      deployOptions: {
        // Backstop throttle in case CloudFront caching is bypassed.
        throttlingRateLimit: 200,
        throttlingBurstLimit: 100,
      },
    });
    gateway.addUsagePlan("yopass-usage-plan", {
      quota: { limit: 10000, period: apigw.Period.DAY },
      throttle: { rateLimit: 50, burstLimit: 25 },
    });

    // S3 bucket for SPA assets. Private; CloudFront reads via Origin Access
    // Control. No public access, ever.
    //
    // Uses an S3 account-regional-namespace bucket: name must end with `-an`
    // and the CFN resource needs `BucketNamespace: account-regional`. The CDK
    // L2 doesn't expose BucketNamespace yet, so we set it via the L1 escape
    // hatch. Account-regional bucket names are reserved to this account, so
    // the same name works in any region without global-namespace contention.
    const bucketName = `yopass-spa-${this.account}-${this.region}-an`;
    const spaBucket = new s3.Bucket(this, "SPABucket", {
      bucketName,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      // SPA assets are reproduced from the build on every deploy, so there's
      // no value in retaining the bucket. autoDeleteObjects empties it before
      // CFN deletes the bucket itself.
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });
    (spaBucket.node.defaultChild as s3.CfnBucket).addPropertyOverride(
      "BucketNamespace",
      "account-regional",
    );

    // CloudFront-facing certificate (must be in us-east-1).
    const cert = new acm.Certificate(this, "Certificate", {
      domainName,
      validation: acm.CertificateValidation.fromDns(hostedZone),
    });

    // CloudFront Function: rewrite extension-less paths to /index.html so a
    // direct hit on /upload returns the SPA shell instead of S3's 404. The
    // SPA itself uses hash routing for everything except the top-level
    // entry pages, so this only needs to catch the entry pages.
    const spaRewrite = new cf.Function(this, "SpaRewrite", {
      runtime: cf.FunctionRuntime.JS_2_0,
      code: cf.FunctionCode.fromInline(`
function handler(event) {
  var req = event.request;
  // Pass through anything with a file extension (.css, .js, .svg, .ico, ...).
  if (req.uri.indexOf('.') !== -1) return req;
  req.uri = '/index.html';
  return req;
}
      `.trim()),
    });

    // Cache policy for API behaviors: never cache, but forward the headers
    // and cookies the server actually uses (incl. the new X-Requested-With
    // CSRF header and the X-Yopass-* upload headers).
    const apiCachePolicy = new cf.CachePolicy(this, "ApiCachePolicy", {
      cachePolicyName: cdk.Names.uniqueId(this).slice(0, 60) + "-api",
      defaultTtl: cdk.Duration.seconds(0),
      maxTtl: cdk.Duration.seconds(1),
      minTtl: cdk.Duration.seconds(0),
      headerBehavior: cf.CacheHeaderBehavior.allowList(
        "Accept",
        "Authorization",
        "Content-Type",
        "Origin",
        "X-Requested-With",
        "X-Yopass-Expiration",
        "X-Yopass-OneTime",
        "X-Yopass-RequireAuth",
      ),
      queryStringBehavior: cf.CacheQueryStringBehavior.all(),
      cookieBehavior: cf.CacheCookieBehavior.all(),
      enableAcceptEncodingGzip: true,
      enableAcceptEncodingBrotli: true,
    });

    const apiOrigin = new origins.RestApiOrigin(gateway);
    const apiBehavior: cf.BehaviorOptions = {
      origin: apiOrigin,
      viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      cachePolicy: apiCachePolicy,
      originRequestPolicy: cf.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
      allowedMethods: cf.AllowedMethods.ALLOW_ALL,
    };

    const distribution = new cf.Distribution(this, "Distribution", {
      domainNames: [domainName],
      certificate: cert,
      defaultRootObject: "index.html",
      priceClass: cf.PriceClass.PRICE_CLASS_100, // US + EU
      minimumProtocolVersion: cf.SecurityPolicyProtocol.TLS_V1_2_2021,
      httpVersion: cf.HttpVersion.HTTP2_AND_3,
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(spaBucket),
        viewerProtocolPolicy: cf.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cf.CachePolicy.CACHING_OPTIMIZED,
        functionAssociations: [
          { function: spaRewrite, eventType: cf.FunctionEventType.VIEWER_REQUEST },
        ],
      },
      // Route every server-side endpoint to API Gateway. The SPA never makes
      // requests to other paths, so the default S3 behaviour catches static
      // assets (and the rewrite function redirects /upload → /index.html).
      additionalBehaviors: {
        "/create/*": apiBehavior,
        "/secret/*": apiBehavior,
        "/file/*": apiBehavior,
        "/auth/*": apiBehavior,
        "/config": apiBehavior,
        "/version": apiBehavior,
        "/logo": apiBehavior,
        "/health": apiBehavior,
        "/ready": apiBehavior,
      },
    });

    // Upload the built SPA and invalidate the distribution on every deploy.
    new s3deploy.BucketDeployment(this, "SPADeployment", {
      sources: [s3deploy.Source.asset(assetPath)],
      destinationBucket: spaBucket,
      distribution,
      distributionPaths: ["/*"],
    });

    // Optional Route 53 alias.
    if (hostedZone) {
      new route53.ARecord(this, "AliasRecord", {
        zone: hostedZone,
        recordName: domainName,
        target: route53.RecordTarget.fromAlias(new targets.CloudFrontTarget(distribution)),
      });
    }

    new cdk.CfnOutput(this, "AppURL", {
      value: `https://${domainName}`,
      description: "Public Yopass URL",
    });
    new cdk.CfnOutput(this, "DistributionDomainName", {
      value: distribution.distributionDomainName,
      description: "CloudFront domain — point DNS here if no hostedZone was provided",
    });
    new cdk.CfnOutput(this, "ApiGatewayURL", {
      value: gateway.url,
      description: "API Gateway origin (CloudFront target — not for public consumption)",
    });
  }
}
