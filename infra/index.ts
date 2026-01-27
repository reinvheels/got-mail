import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

// Stack configuration
const stackName = pulumi.getStack();
const config = new pulumi.Config("got-mail");

// Configuration from Pulumi config
const domainName = config.require("domainName");
const instanceType = config.get("instanceType") || "t4g.micro";
const keyName = config.get("keyName");
const openSshPort = config.getBoolean("openSshPort") || false;

// Common tags for cost allocation and resource identification
const commonTags = {
    Project: "got-mail",
    Environment: stackName,
    ManagedBy: "pulumi",
};

// Get current AWS region
const currentRegion = aws.getRegion({});

// Find Route53 hosted zone by recursively searching domain parts
async function findHostedZone(domain: string): Promise<aws.route53.GetZoneResult> {
    const parts = domain.split(".");

    for (let i = 0; i < parts.length - 1; i++) {
        const zoneName = parts.slice(i).join(".");
        try {
            const zone = await aws.route53.getZone({ name: zoneName });
            return zone;
        } catch {
            continue;
        }
    }

    throw new Error(
        `No Route53 hosted zone found for domain "${domain}". ` +
        `Searched for: ${parts.map((_, i) => parts.slice(i).join(".")).slice(0, -1).join(", ")}`
    );
}

const hostedZone = findHostedZone(domainName);

// Get the base domain (for MX, SPF, DMARC records)
const baseDomain = pulumi.output(hostedZone).apply(z => z.name.replace(/\.$/, ""));

// =============================================================================
// S3 Bucket for backups
// =============================================================================

const backupBucket = new aws.s3.Bucket("got-mail-backup", {
    forceDestroy: false,
    tags: {
        ...commonTags,
        Name: "got-mail-backup",
    },
}, { retainOnDelete: true });

const backupBucketPublicAccessBlock = new aws.s3.BucketPublicAccessBlock("got-mail-backup-public-access", {
    bucket: backupBucket.id,
    blockPublicAcls: true,
    blockPublicPolicy: true,
    ignorePublicAcls: true,
    restrictPublicBuckets: true,
});

// =============================================================================
// SES Domain Identity + DKIM
// =============================================================================

const sesDomainIdentity = new aws.ses.DomainIdentity("got-mail-ses-domain", {
    domain: baseDomain,
});

const sesDkim = new aws.ses.DomainDkim("got-mail-ses-dkim", {
    domain: sesDomainIdentity.domain,
});

// Create DKIM verification records in Route53
const dkimRecords = sesDkim.dkimTokens.apply(tokens =>
    tokens.map((token, i) =>
        new aws.route53.Record(`got-mail-dkim-${i}`, {
            zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
            name: pulumi.interpolate`${token}._domainkey.${domainName}`,
            type: "CNAME",
            ttl: 600,
            records: [pulumi.interpolate`${token}.dkim.amazonses.com`],
        })
    )
);

// SES domain verification record
const sesVerificationRecord = new aws.route53.Record("got-mail-ses-verification", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`_amazonses.${domainName}`,
    type: "TXT",
    ttl: 600,
    records: [sesDomainIdentity.verificationToken],
});

// =============================================================================
// EC2 Infrastructure
// =============================================================================

// Get first available AZ for consistent placement of instance and volume
const dataAvailabilityZone = aws.getAvailabilityZones({
    state: "available",
}).then(azs => azs.names[0]);

// Create persistent EBS volume for Stalwart data
const dataVolume = new aws.ebs.Volume("got-mail-data-volume", {
    availabilityZone: dataAvailabilityZone,
    size: 10, // GB
    type: "gp3",
    tags: {
        ...commonTags,
        Name: "got-mail-data-volume",
    },
}, { retainOnDelete: true });

// Create an Elastic IP for stable addressing
const eip = new aws.ec2.Eip("got-mail-eip", {
    tags: {
        ...commonTags,
        Name: "got-mail-eip",
    },
});

// Get the latest Amazon Linux 2023 AMI (ARM64 for Graviton instances)
const ami = aws.ec2.getAmi({
    mostRecent: true,
    owners: ["amazon"],
    filters: [
        { name: "name", values: ["al2023-ami-*-arm64"] },
        { name: "architecture", values: ["arm64"] },
        { name: "virtualization-type", values: ["hvm"] },
    ],
});

// IAM role for EC2 instances
const instanceRole = new aws.iam.Role("got-mail-instance-role", {
    assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Principal: {
                Service: "ec2.amazonaws.com",
            },
        }],
    }),
    tags: {
        ...commonTags,
        Name: "got-mail-instance-role",
    },
});

// Policy allowing instance to attach EIP, EBS, send via SES, and backup to S3
const instancePolicy = new aws.iam.RolePolicy("got-mail-instance-policy", {
    role: instanceRole.id,
    policy: pulumi.all([eip.allocationId, dataVolume.id, backupBucket.arn, baseDomain]).apply(
        ([eipAllocationId, volumeId, bucketArn, domain]) => JSON.stringify({
            Version: "2012-10-17",
            Statement: [
                {
                    Sid: "AllowEIPAssociation",
                    Effect: "Allow",
                    Action: [
                        "ec2:AssociateAddress",
                        "ec2:DisassociateAddress",
                    ],
                    Resource: [
                        `arn:aws:ec2:*:*:elastic-ip/${eipAllocationId}`,
                        "arn:aws:ec2:*:*:instance/*",
                        "arn:aws:ec2:*:*:network-interface/*",
                    ],
                },
                {
                    Sid: "AllowVolumeAttachment",
                    Effect: "Allow",
                    Action: [
                        "ec2:AttachVolume",
                        "ec2:DetachVolume",
                    ],
                    Resource: [
                        `arn:aws:ec2:*:*:volume/${volumeId}`,
                        "arn:aws:ec2:*:*:instance/*",
                    ],
                },
                {
                    Sid: "AllowDescribe",
                    Effect: "Allow",
                    Action: [
                        "ec2:DescribeVolumes",
                        "ec2:DescribeInstances",
                        "ec2:DescribeAddresses",
                    ],
                    Resource: "*",
                },
                {
                    Sid: "AllowSESSend",
                    Effect: "Allow",
                    Action: [
                        "ses:SendRawEmail",
                        "ses:SendEmail",
                    ],
                    Resource: "*",
                    Condition: {
                        StringEquals: {
                            "ses:FromAddress": `*@${domain}`,
                        },
                    },
                },
                {
                    Sid: "AllowS3Backup",
                    Effect: "Allow",
                    Action: [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket",
                    ],
                    Resource: [
                        bucketArn,
                        `${bucketArn}/*`,
                    ],
                },
            ],
        })
    ),
});

// Instance profile to attach the role to EC2 instances
const instanceProfile = new aws.iam.InstanceProfile("got-mail-instance-profile", {
    role: instanceRole.name,
    tags: {
        ...commonTags,
        Name: "got-mail-instance-profile",
    },
});

// Security group for mail server
const securityGroup = new aws.ec2.SecurityGroup("got-mail-sg", {
    description: "Security group for Got Mail EC2 instance",
    ingress: [
        // SSH (optional)
        ...(openSshPort ? [{
            protocol: "tcp",
            fromPort: 22,
            toPort: 22,
            cidrBlocks: ["0.0.0.0/0"],
            description: "SSH access",
        }] : []),
        // SMTP inbound (from other mail servers)
        {
            protocol: "tcp",
            fromPort: 25,
            toPort: 25,
            cidrBlocks: ["0.0.0.0/0"],
            description: "SMTP inbound",
        },
        // HTTP (for ACME/Let's Encrypt)
        {
            protocol: "tcp",
            fromPort: 80,
            toPort: 80,
            cidrBlocks: ["0.0.0.0/0"],
            description: "HTTP (ACME)",
        },
        // IMAP (legacy, unencrypted)
        {
            protocol: "tcp",
            fromPort: 143,
            toPort: 143,
            cidrBlocks: ["0.0.0.0/0"],
            description: "IMAP",
        },
        // HTTPS (webmail)
        {
            protocol: "tcp",
            fromPort: 443,
            toPort: 443,
            cidrBlocks: ["0.0.0.0/0"],
            description: "HTTPS (webmail)",
        },
        // SMTPS (submission with implicit TLS)
        {
            protocol: "tcp",
            fromPort: 465,
            toPort: 465,
            cidrBlocks: ["0.0.0.0/0"],
            description: "SMTPS submission",
        },
        // SMTP submission (with STARTTLS)
        {
            protocol: "tcp",
            fromPort: 587,
            toPort: 587,
            cidrBlocks: ["0.0.0.0/0"],
            description: "SMTP submission",
        },
        // IMAPS (with implicit TLS)
        {
            protocol: "tcp",
            fromPort: 993,
            toPort: 993,
            cidrBlocks: ["0.0.0.0/0"],
            description: "IMAPS",
        },
        // Web admin
        {
            protocol: "tcp",
            fromPort: 8080,
            toPort: 8080,
            cidrBlocks: ["0.0.0.0/0"],
            description: "Web admin",
        },
    ],
    egress: [
        {
            protocol: "-1",
            fromPort: 0,
            toPort: 0,
            cidrBlocks: ["0.0.0.0/0"],
            description: "Allow all outbound traffic",
        },
    ],
    tags: {
        ...commonTags,
        Name: "got-mail-sg",
    },
});

// User data script to install Stalwart Mail Server
const userData = pulumi.all([
    domainName,
    baseDomain,
    currentRegion.then(r => r.name),
    eip.allocationId,
    dataVolume.id,
]).apply(([mailDomain, domain, region, eipAllocationId, dataVolumeId]) => `#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log) 2>&1

# Get instance metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AVAILABILITY_ZONE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=$(echo $AVAILABILITY_ZONE | sed 's/[a-z]$//')

echo "Instance ID: $INSTANCE_ID"
echo "Region: $REGION"

# Associate Elastic IP to this instance
echo "Associating Elastic IP..."
aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id ${eipAllocationId} --region $REGION || true

# Attach EBS data volume to this instance
echo "Attaching EBS data volume..."
CURRENT_ATTACHMENT=$(aws ec2 describe-volumes --volume-ids ${dataVolumeId} --region $REGION --query 'Volumes[0].Attachments[0].InstanceId' --output text)
if [ "$CURRENT_ATTACHMENT" != "None" ] && [ "$CURRENT_ATTACHMENT" != "$INSTANCE_ID" ]; then
    echo "Volume attached to $CURRENT_ATTACHMENT, detaching..."
    aws ec2 detach-volume --volume-id ${dataVolumeId} --region $REGION --force || true
    sleep 10
fi
aws ec2 attach-volume --volume-id ${dataVolumeId} --instance-id $INSTANCE_ID --device /dev/sdf --region $REGION || true

# Update system
dnf update -y

# Wait for EBS volume to be attached
echo "Waiting for EBS data volume..."
WAIT_COUNT=0
while true; do
    if [ -b /dev/nvme1n1 ]; then
        DATA_DEVICE=/dev/nvme1n1
        break
    elif [ -b /dev/sdf ]; then
        DATA_DEVICE=/dev/sdf
        break
    elif [ -b /dev/xvdf ]; then
        DATA_DEVICE=/dev/xvdf
        break
    fi
    WAIT_COUNT=$((WAIT_COUNT + 1))
    if [ $WAIT_COUNT -gt 60 ]; then
        echo "Timeout waiting for EBS volume"
        exit 1
    fi
    sleep 1
done
echo "Found data volume at $DATA_DEVICE"

# Create mount point
mkdir -p /opt/stalwart

# Try to mount the volume - if it fails, format it (first boot only)
if mount $DATA_DEVICE /opt/stalwart 2>/dev/null; then
    echo "Mounted existing data volume"
else
    echo "Mount failed - formatting new data volume..."
    mkfs.ext4 $DATA_DEVICE
    mount $DATA_DEVICE /opt/stalwart
    touch /opt/stalwart/.stalwart-volume
    echo "Created new Stalwart data volume"
fi

# Add to fstab for persistence across reboots
if ! grep -q "/opt/stalwart" /etc/fstab; then
    echo "$DATA_DEVICE /opt/stalwart ext4 defaults,nofail 0 2" >> /etc/fstab
fi

# Download and install Stalwart Mail Server
echo "Installing Stalwart Mail Server..."
cd /opt/stalwart
curl -sL https://get.stalw.art/install.sh | bash -s -- --component all-in-one --path /opt/stalwart

# Wait for installation to complete
sleep 5

# Stop Stalwart to reconfigure
systemctl stop stalwart || true

# Configure Stalwart for this domain
mkdir -p /opt/stalwart/etc /opt/stalwart/logs
cat > /opt/stalwart/etc/config.toml << CONFIGEOF
[server]
hostname = "${mailDomain}"

[server.listener.smtp]
bind = "[::]:25"
protocol = "smtp"

[server.listener.submission]
bind = "[::]:587"
protocol = "smtp"

[server.listener.submissions]
bind = "[::]:465"
protocol = "smtp"
tls.implicit = true

[server.listener.imap]
bind = "[::]:143"
protocol = "imap"

[server.listener.imaptls]
bind = "[::]:993"
protocol = "imap"
tls.implicit = true

[server.listener.http]
protocol = "http"
bind = "[::]:8080"

[storage]
data = "rocksdb"
fts = "rocksdb"
blob = "rocksdb"
lookup = "rocksdb"
directory = "internal"

[store.rocksdb]
type = "rocksdb"
path = "/opt/stalwart/data"
compression = "lz4"

[directory.internal]
type = "internal"
store = "rocksdb"

[tracer.log]
type = "log"
level = "info"
path = "/opt/stalwart/logs"
prefix = "stalwart.log"
rotate = "daily"
enable = true

[authentication.fallback-admin]
user = "admin"
secret = "changeme123"
CONFIGEOF

# Set permissions
chown -R stalwart:stalwart /opt/stalwart

# Enable and start Stalwart
systemctl enable stalwart
systemctl start stalwart

echo "Stalwart Mail Server deployment completed at $(date)"
`);

// Get default VPC for ASG
const defaultVpc = aws.ec2.getVpc({ default: true });

// Get subnet in the same AZ as our EBS volume
const asgSubnetId = pulumi.all([defaultVpc, dataAvailabilityZone]).apply(async ([vpc, az]) => {
    const subnet = await aws.ec2.getSubnet({
        filters: [
            { name: "vpc-id", values: [vpc.id] },
            { name: "availability-zone", values: [az] },
            { name: "default-for-az", values: ["true"] },
        ],
    });
    return subnet.id;
});

// Create Launch Template for ASG
const launchTemplate = new aws.ec2.LaunchTemplate("got-mail-launch-template", {
    imageId: ami.then(a => a.id),
    instanceType: instanceType,
    keyName: keyName,
    vpcSecurityGroupIds: [securityGroup.id],
    userData: userData.apply(ud => Buffer.from(ud).toString("base64")),
    iamInstanceProfile: {
        arn: instanceProfile.arn,
    },
    // Always use spot for mail server (cost savings)
    instanceMarketOptions: {
        marketType: "spot",
        spotOptions: {
            spotInstanceType: "one-time",
            instanceInterruptionBehavior: "terminate",
        },
    },
    blockDeviceMappings: [{
        deviceName: "/dev/xvda",
        ebs: {
            volumeSize: 8,
            volumeType: "gp3",
            deleteOnTermination: "true",
        },
    }],
    tagSpecifications: [
        {
            resourceType: "instance",
            tags: {
                ...commonTags,
                Name: "got-mail-instance",
            },
        },
        {
            resourceType: "volume",
            tags: {
                ...commonTags,
                Name: "got-mail-root-volume",
            },
        },
    ],
    tags: {
        ...commonTags,
        Name: "got-mail-launch-template",
    },
});

// Create Auto Scaling Group for automatic recovery
const asg = new aws.autoscaling.Group("got-mail-asg", {
    name: "got-mail-asg",
    minSize: 1,
    maxSize: 1,
    desiredCapacity: 1,
    vpcZoneIdentifiers: [asgSubnetId],
    launchTemplate: {
        id: launchTemplate.id,
        version: "$Latest",
    },
    healthCheckType: "EC2",
    healthCheckGracePeriod: 300,
    tags: [
        { key: "Name", value: "got-mail-instance", propagateAtLaunch: true },
        { key: "Project", value: "got-mail", propagateAtLaunch: true },
        { key: "Environment", value: stackName, propagateAtLaunch: true },
        { key: "ManagedBy", value: "pulumi", propagateAtLaunch: true },
    ],
    waitForCapacityTimeout: "10m",
});

// =============================================================================
// DNS Records
// =============================================================================

// A record for mail server
const mailARecord = new aws.route53.Record("got-mail-a", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: domainName,
    type: "A",
    ttl: 300,
    records: [eip.publicIp],
});

// MX record for the mail subdomain
const mxRecord = new aws.route53.Record("got-mail-mx", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: domainName,
    type: "MX",
    ttl: 300,
    records: [pulumi.interpolate`10 ${domainName}.`],
});

// SPF record for the mail subdomain
const spfRecord = new aws.route53.Record("got-mail-spf", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: domainName,
    type: "TXT",
    ttl: 300,
    records: ["v=spf1 include:amazonses.com ~all"],
});

// DMARC record for the mail subdomain
const dmarcRecord = new aws.route53.Record("got-mail-dmarc", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`_dmarc.${domainName}`,
    type: "TXT",
    ttl: 300,
    records: ["v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domainName],
});

// =============================================================================
// Exports
// =============================================================================

export const domain = domainName;
export const mailServerIp = eip.publicIp;
export const asgName = asg.name;
export const dataVolumeId = dataVolume.id;
export const backupBucketName = backupBucket.bucket;
export const sesVerificationStatus = sesDomainIdentity.verificationToken;
export const hostedZoneId = pulumi.output(hostedZone).apply(z => z.zoneId);
