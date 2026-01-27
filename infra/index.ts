import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

const config = new pulumi.Config();
const domainName = config.require("domainName");

// TODO: Implement infrastructure
// - VPC with public subnet
// - EC2 spot instance (ASG size=1) with Stalwart
// - EBS volume for data persistence
// - Elastic IP
// - Security group (25, 465, 587, 143, 993, 443)
// - SES domain identity + DKIM
// - Route53 records (MX, SPF, DKIM, DMARC)
// - S3 bucket for backups
// - IAM role for EC2 (SES send, S3 backup)

export const domain = domainName;
