#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { CdkStack } from "../lib/cdk-stack";

/**
 * Configuration is read from CDK context (cdk.json or `-c name=value`) or
 * environment variables:
 *
 *   domainName       (required) — public hostname, e.g. yopass.example.com
 *   hostedZoneName   (optional) — Route 53 zone, e.g. example.com.
 *                                 When set, an A-record alias is created.
 *
 * The stack MUST deploy in us-east-1 because CloudFront's ACM certificate
 * lives there. Override via CDK_DEFAULT_REGION or pass --region accordingly.
 */
const app = new cdk.App();

const domainName =
  app.node.tryGetContext("domainName") ?? process.env.YOPASS_DOMAIN_NAME;
if (!domainName) {
  throw new Error(
    "domainName is required: set it in cdk.json context or pass -c domainName=yopass.example.com",
  );
}
const hostedZoneName =
  app.node.tryGetContext("hostedZoneName") ?? process.env.YOPASS_HOSTED_ZONE;

new CdkStack(app, "CdkStack", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
  },
  domainName,
  hostedZoneName,
});
