import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as command from "@pulumi/command";
import * as random from "@pulumi/random";
import * as crypto from "crypto";
import { Domain as StalwartDomain, Account as StalwartAccount } from "./stalwart";

// SES SMTP password is derived from IAM secret key + region (SigV4 algorithm)
// See: https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
function computeSesSmtpPassword(secretAccessKey: string, region: string): string {
    function sign(key: Buffer, msg: string): Buffer {
        return crypto.createHmac("sha256", key).update(msg).digest();
    }
    let signature = sign(Buffer.from("AWS4" + secretAccessKey), "11111111");
    signature = sign(signature, region);
    signature = sign(signature, "ses");
    signature = sign(signature, "aws4_request");
    signature = sign(signature, "SendRawEmail");
    return Buffer.concat([Buffer.from([0x04]), signature]).toString("base64");
}

// Stack configuration
const stackName = pulumi.getStack();
const config = new pulumi.Config("got-mail");

// Configuration from Pulumi config
const domainName = config.require("domainName");
const instanceType = config.get("instanceType") || "t4g.micro";
const keyName = config.get("keyName");
const openSshPort = config.getBoolean("openSshPort") || false;
const stalwartVersion = config.get("stalwartVersion") || "latest";
const enableSnapshots = config.getBoolean("enableSnapshots") || false;
const snapshotRetentionDays = config.getNumber("snapshotRetentionDays") || 30;

interface MailAccountConfig {
    name: string;
    email: string;
    displayName?: string;
    roles?: string[];
}

const mailDomains = config.requireObject<string[]>("mailDomains");
const mailAccounts = config.requireObject<MailAccountConfig[]>("mailAccounts");

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
}, { retainOnDelete: false });

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
    domain: domainName,
});

const sesDkim = new aws.ses.DomainDkim("got-mail-ses-dkim", {
    domain: sesDomainIdentity.domain,
});

// SES in eu-west-1 (has production access — eu-central-1 is still sandbox)
const sesRegion = "eu-west-1";
const sesProvider = new aws.Provider("ses-eu-west-1", { region: sesRegion });

const sesDomainIdentityEuWest1 = new aws.ses.DomainIdentity("got-mail-ses-domain-eu-west-1", {
    domain: domainName,
}, { provider: sesProvider });

const sesDkimEuWest1 = new aws.ses.DomainDkim("got-mail-ses-dkim-eu-west-1", {
    domain: sesDomainIdentityEuWest1.domain,
}, { provider: sesProvider });

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

// DKIM verification records for eu-west-1
const dkimRecordsEuWest1 = sesDkimEuWest1.dkimTokens.apply(tokens =>
    tokens.map((token, i) =>
        new aws.route53.Record(`got-mail-dkim-eu-west-1-${i}`, {
            zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
            name: pulumi.interpolate`${token}._domainkey.${domainName}`,
            type: "CNAME",
            ttl: 600,
            records: [pulumi.interpolate`${token}.dkim.amazonses.com`],
        })
    )
);

// SES SMTP credentials (IAM user for Stalwart to relay through SES)
const sesSmtpUser = new aws.iam.User("got-mail-ses-smtp-user", {
    name: "got-mail-ses-smtp",
    tags: { ...commonTags, Name: "got-mail-ses-smtp" },
});

new aws.iam.UserPolicy("got-mail-ses-smtp-policy", {
    user: sesSmtpUser.name,
    policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Effect: "Allow",
            Action: ["ses:SendRawEmail", "ses:SendEmail"],
            Resource: "*",
        }],
    }),
});

const sesSmtpAccessKey = new aws.iam.AccessKey("got-mail-ses-smtp-key", {
    user: sesSmtpUser.name,
});

// Compute SES SMTP password for eu-west-1 (password derivation is region-specific)
const sesSmtpPasswordEuWest1 = sesSmtpAccessKey.secret.apply(
    secret => computeSesSmtpPassword(secret, sesRegion),
);

// SES domain verification records (both regions share the same TXT record name)
const sesVerificationRecord = new aws.route53.Record("got-mail-ses-verification", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`_amazonses.${domainName}`,
    type: "TXT",
    ttl: 600,
    records: [sesDomainIdentity.verificationToken, sesDomainIdentityEuWest1.verificationToken],
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

// Daily EBS snapshots via Data Lifecycle Manager
if (enableSnapshots) {
    const dlmRole = new aws.iam.Role("got-mail-dlm-role", {
        assumeRolePolicy: JSON.stringify({
            Version: "2012-10-17",
            Statement: [{
                Effect: "Allow",
                Principal: { Service: "dlm.amazonaws.com" },
                Action: "sts:AssumeRole",
            }],
        }),
        managedPolicyArns: ["arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"] as any,
        tags: commonTags,
    });

    new aws.dlm.LifecyclePolicy("got-mail-snapshot-policy", {
        description: "Daily snapshots of got-mail data volume",
        executionRoleArn: dlmRole.arn,
        state: "ENABLED",
        policyDetails: {
            resourceTypes: ["VOLUME"],
            targetTags: { Name: "got-mail-data-volume" },
            schedules: [{
                name: "daily",
                createRule: { interval: 24, intervalUnit: "HOURS", times: "03:00" },
                retainRule: { count: snapshotRetentionDays },
                tagsToAdd: { ...commonTags, Name: "got-mail-data-snapshot" },
                copyTags: true,
            }],
        },
        tags: commonTags,
    });
}

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

// =============================================================================
// Stalwart Admin Password (needed by AMI builder and API calls)
// =============================================================================

const ssmPrefix = `/got-mail/${stackName}`;

const adminPassword = new random.RandomPassword("stalwart-admin-password", {
    length: 32,
    special: true,
});

const adminPasswordSsm = new aws.ssm.Parameter("stalwart-admin-password-ssm", {
    name: `${ssmPrefix}/stalwart/admin-password`,
    type: aws.ssm.ParameterType.SecureString,
    value: adminPassword.result,
    tags: commonTags,
});

// =============================================================================
// AMI Builder (bakes Stalwart into a custom AMI)
// =============================================================================

// Builder security group - egress only (no inbound needed)
const builderSg = new aws.ec2.SecurityGroup("got-mail-builder-sg", {
    description: "Builder instance - egress only",
    egress: [{
        protocol: "-1",
        fromPort: 0,
        toPort: 0,
        cidrBlocks: ["0.0.0.0/0"],
        description: "Allow all outbound traffic",
    }],
    tags: { ...commonTags, Name: "got-mail-builder-sg" },
});

// Builder IAM role - needs ec2:CreateTags to signal build completion
const builderRole = new aws.iam.Role("got-mail-builder-role", {
    assumeRolePolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Action: "sts:AssumeRole",
            Effect: "Allow",
            Principal: { Service: "ec2.amazonaws.com" },
        }],
    }),
    tags: { ...commonTags, Name: "got-mail-builder-role" },
});

new aws.iam.RolePolicy("got-mail-builder-policy", {
    role: builderRole.id,
    policy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{
            Sid: "AllowCreateTags",
            Effect: "Allow",
            Action: "ec2:CreateTags",
            Resource: "arn:aws:ec2:*:*:instance/*",
        }],
    }),
});

const builderProfile = new aws.iam.InstanceProfile("got-mail-builder-profile", {
    role: builderRole.name,
    tags: { ...commonTags, Name: "got-mail-builder-profile" },
});

// Builder user data - installs Stalwart, writes config, and signals completion
const builderUserData = pulumi.all([
    domainName,
    baseDomain,
    sesSmtpAccessKey.id,
    sesSmtpPasswordEuWest1,
    adminPassword.result,
]).apply(([mailDomain, domain, smtpUser, smtpPassword, adminPass]) => `#!/bin/bash
set -ex
exec > >(tee /var/log/user-data.log) 2>&1

# Get instance metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AVAILABILITY_ZONE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
REGION=$(echo $AVAILABILITY_ZONE | sed 's/[a-z]$//')

echo "Builder instance: $INSTANCE_ID in $REGION"
echo "Building Stalwart version: ${stalwartVersion}"

# Update system packages
dnf update -y

# Download and install Stalwart Mail Server
# The install script creates: binary at /opt/stalwart/bin/stalwart,
# systemd unit (stalwart.service), and stalwart user/group
echo "Installing Stalwart Mail Server..."
curl -sL https://get.stalw.art/install.sh | bash -s -- /opt/stalwart

# Verify binary exists
if [ ! -f /opt/stalwart/bin/stalwart ]; then
    echo "ERROR: Stalwart binary not found at /opt/stalwart/bin/stalwart"
    aws ec2 create-tags --resources $INSTANCE_ID --tags Key=BuildStatus,Value=failed --region $REGION
    exit 1
fi

# Stop and disable Stalwart — it must NOT auto-start on boot.
# Runtime user data mounts the EBS data volume BEFORE starting Stalwart.
# If Stalwart starts before EBS is mounted, it uses an empty DB on the root volume.
systemctl stop stalwart 2>/dev/null || true
systemctl disable stalwart 2>/dev/null || true

# Write Stalwart configuration (overwrite install script defaults)
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

[server.listener.https]
protocol = "http"
bind = "[::]:443"
tls.implicit = true

[server.listener.http]
protocol = "http"
bind = "[::]:8080"

[server.listener.acme]
protocol = "http"
bind = "[::]:80"

[server.tls]
enable = true

[acme."letsencrypt"]
directory = "https://acme-v02.api.letsencrypt.org/directory"
contact = ["mailto:admin@${domain}"]
domains = ["${mailDomain}", "autoconfig.${mailDomain}", "autodiscover.${mailDomain}"]
default = true

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

[queue.route.ses]
type = "relay"
address = "email-smtp.eu-west-1.amazonaws.com"
port = 587
protocol = "smtp"

[queue.route.ses.tls]
implicit = false
allow-invalid-certs = false

[queue.route.ses.auth]
username = "${smtpUser}"
secret = "${smtpPassword}"

[queue.strategy]
route = [ { if = "is_local_domain('', rcpt_domain)", then = "'local'" }, { else = "'ses'" } ]

[authentication.fallback-admin]
user = "admin"
secret = "${adminPass}"
CONFIGEOF

chown -R stalwart:stalwart /opt/stalwart

echo "Build complete, signaling..."
aws ec2 create-tags --resources $INSTANCE_ID --tags Key=BuildStatus,Value=complete --region $REGION
echo "Builder finished at $(date)"
`);

// Build AMI via CLI: launch instance, wait for build, create AMI, terminate.
// Nothing lingers in Pulumi state — only the AMI ID output matters.
const buildAmi = new command.local.Command("build-stalwart-ami", {
    create: pulumi.all([
        ami.then(a => a.id),
        builderSg.id,
        builderProfile.name,
        builderUserData,
    ]).apply(([baseAmiId, sgId, profileName, userData]) => {
        const userDataB64 = Buffer.from(userData).toString("base64");
        const amiNamePrefix = `got-mail-stalwart-${stalwartVersion}`;
        // Shell script that outputs the AMI ID as the last line (captured by Pulumi)
        return `
set -e

echo "Launching builder instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id ${baseAmiId} \
    --instance-type ${instanceType} \
    --security-group-ids ${sgId} \
    --iam-instance-profile Name=${profileName} \
    --user-data ${userDataB64} \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=got-mail-ami-builder},{Key=Project,Value=got-mail},{Key=ManagedBy,Value=pulumi}]' \
    --query 'Instances[0].InstanceId' --output text)

echo "Builder instance: $INSTANCE_ID"

# Ensure cleanup on failure
cleanup() {
    echo "Terminating builder instance $INSTANCE_ID..." >&2
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Wait for build completion (up to 30 minutes)
echo "Waiting for build to complete..."
for i in $(seq 1 120); do
    STATUS=$(aws ec2 describe-tags \
        --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=BuildStatus" \
        --query "Tags[0].Value" --output text 2>/dev/null || echo "")
    if [ "$STATUS" = "complete" ]; then
        echo "Build completed successfully"
        break
    fi
    if [ "$STATUS" = "failed" ]; then
        echo "Build failed!" >&2
        exit 1
    fi
    if [ "$i" = "120" ]; then
        echo "Timeout waiting for builder" >&2
        exit 1
    fi
    sleep 15
done

# Stop instance before creating AMI (cleaner snapshot)
echo "Stopping builder instance..."
aws ec2 stop-instances --instance-ids "$INSTANCE_ID" > /dev/null
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID"

# Create AMI
echo "Creating AMI..."
AMI_NAME="${amiNamePrefix}-$(date +%s)"
AMI_ID=$(aws ec2 create-image \
    --instance-id "$INSTANCE_ID" \
    --name "$AMI_NAME" \
    --description "Got Mail - Stalwart ${stalwartVersion}" \
    --tag-specifications 'ResourceType=image,Tags=[{Key=Name,Value=got-mail-stalwart-ami},{Key=Project,Value=got-mail},{Key=StalwartVersion,Value=${stalwartVersion}}]' \
    --query 'ImageId' --output text)

echo "Waiting for AMI $AMI_ID to become available..."
aws ec2 wait image-available --image-ids "$AMI_ID"

# trap will terminate the builder instance
echo "$AMI_ID"
`;
    }),
    // On destroy: terminate any lingering builder instances attached to the builder SG
    delete: builderSg.id.apply(sgId => `
aws ec2 describe-instances \
    --filters "Name=network-interface.group-id,Values=${sgId}" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text \
| xargs -r aws ec2 terminate-instances --instance-ids || true
`),
    triggers: [stalwartVersion],
});

// Extract the AMI ID from the last line of command output
const customAmiId = buildAmi.stdout.apply(out => {
    const match = out.match(/^(ami-[a-z0-9]+)$/m);
    if (!match) throw new Error(`Could not extract AMI ID from build output: ${out}`);
    return match[1];
});

// =============================================================================
// Runtime User Data (simplified - Stalwart already baked into AMI)
// =============================================================================

// Runtime user data - only EIP/EBS attachment and starting Stalwart (binary + config baked in AMI)
const userData = pulumi.all([
    eip.allocationId,
    dataVolume.id,
]).apply(([eipAllocationId, dataVolumeId]) => `#!/bin/bash
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

# Mount EBS volume for Stalwart persistent data
# Config and binary are baked into the AMI at /opt/stalwart/{etc,logs}
# EBS holds RocksDB data that must survive instance replacements
mkdir -p /mnt/stalwart-ebs /opt/stalwart/data

if mount $DATA_DEVICE /mnt/stalwart-ebs 2>/dev/null; then
    echo "Mounted EBS volume"
    # Migration: if old layout (data/ is a subdirectory on EBS), bind-mount it
    if [ -d /mnt/stalwart-ebs/data ]; then
        echo "Found existing data directory on EBS volume"
        mount --bind /mnt/stalwart-ebs/data /opt/stalwart/data
    else
        # Fresh EBS or flat layout - use the whole volume as data dir
        umount /mnt/stalwart-ebs
        mount $DATA_DEVICE /opt/stalwart/data
    fi
else
    echo "Mount failed - formatting new data volume..."
    mkfs.ext4 $DATA_DEVICE
    mount $DATA_DEVICE /opt/stalwart/data
    echo "Created new Stalwart data volume"
fi

# Add to fstab for persistence across reboots
if ! grep -q "/opt/stalwart/data" /etc/fstab; then
    echo "$DATA_DEVICE /opt/stalwart/data ext4 defaults,nofail 0 2" >> /etc/fstab
fi

# Ensure correct ownership
chown -R stalwart:stalwart /opt/stalwart

# Enable and start Stalwart (disabled in AMI to prevent starting before EBS mount)
systemctl enable --now stalwart

echo "Stalwart Mail Server started at $(date)"
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
    imageId: customAmiId,
    keyName: keyName,
    vpcSecurityGroupIds: [securityGroup.id],
    userData: userData.apply(ud => Buffer.from(ud).toString("base64")),
    iamInstanceProfile: {
        arn: instanceProfile.arn,
    },
    blockDeviceMappings: [{
        deviceName: "/dev/xvda",
        ebs: {
            volumeSize: 30,
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
    minSize: 0,
    maxSize: 1,
    desiredCapacity: 1,
    vpcZoneIdentifiers: [asgSubnetId],
    mixedInstancesPolicy: {
        launchTemplate: {
            launchTemplateSpecification: {
                launchTemplateId: launchTemplate.id,
                version: "$Latest",
            },
            overrides: [
                { instanceType: "t4g.nano" },
                { instanceType: "t4g.micro" },
                { instanceType: "t4g.small" },
            ],
        },
        instancesDistribution: {
            onDemandBaseCapacity: 0,
            onDemandPercentageAboveBaseCapacity: 0,
            spotAllocationStrategy: "price-capacity-optimized",
        },
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

// Autoconfig/Autodiscover CNAME records (Thunderbird, Outlook)
new aws.route53.Record("got-mail-autoconfig", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`autoconfig.${domainName}`,
    type: "CNAME",
    ttl: 300,
    records: [domainName],
});

new aws.route53.Record("got-mail-autodiscover", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`autodiscover.${domainName}`,
    type: "CNAME",
    ttl: 300,
    records: [domainName],
});

// --- Per mail-domain DNS records ---
for (const md of mailDomains) {
    new aws.route53.Record(`got-mail-mx-${md}`, {
        zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
        name: md,
        type: "MX",
        ttl: 300,
        records: [pulumi.interpolate`10 ${domainName}.`],
    });

    new aws.route53.Record(`got-mail-spf-${md}`, {
        zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
        name: md,
        type: "TXT",
        ttl: 300,
        records: ["v=spf1 include:amazonses.com ~all"],
    });

    new aws.route53.Record(`got-mail-dmarc-${md}`, {
        zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
        name: `_dmarc.${md}`,
        type: "TXT",
        ttl: 300,
        records: [`v=DMARC1; p=quarantine; rua=mailto:dmarc@${md}`],
    });
}

// SRV records for mail client auto-setup (RFC 6186)
new aws.route53.Record("got-mail-srv-imaps", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`_imaps._tcp.${domainName}`,
    type: "SRV",
    ttl: 300,
    records: [pulumi.interpolate`0 1 993 ${domainName}.`],
});

new aws.route53.Record("got-mail-srv-submissions", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`_submissions._tcp.${domainName}`,
    type: "SRV",
    ttl: 300,
    records: [pulumi.interpolate`0 1 465 ${domainName}.`],
});

new aws.route53.Record("got-mail-srv-submission", {
    zoneId: pulumi.output(hostedZone).apply(z => z.zoneId),
    name: pulumi.interpolate`_submission._tcp.${domainName}`,
    type: "SRV",
    ttl: 300,
    records: [pulumi.interpolate`0 1 587 ${domainName}.`],
});

// =============================================================================
// Stalwart Mail Domains & Accounts
// =============================================================================

const stalwartBaseUrl = pulumi.interpolate`http://${eip.publicIp}:8080`;
const stalwartAuth = { baseUrl: stalwartBaseUrl, username: "admin", password: adminPassword.result };

// --- Domains ---
const stalwartDomains = mailDomains.map(domain => {
    return new StalwartDomain(`stalwart-domain-${domain}`, {
        ...stalwartAuth,
        domainName: domain,
    }, { dependsOn: [asg] });
});

// --- Accounts ---
for (const account of mailAccounts) {
    const password = new random.RandomPassword(`stalwart-password-${account.name}`, {
        length: 24,
        special: true,
    });

    new aws.ssm.Parameter(`stalwart-password-ssm-${account.name}`, {
        name: `${ssmPrefix}/stalwart/accounts/${account.name}/password`,
        type: aws.ssm.ParameterType.SecureString,
        value: password.result,
        tags: commonTags,
    });

    new StalwartAccount(`stalwart-account-${account.name}`, {
        ...stalwartAuth,
        accountName: account.name,
        description: account.displayName || "",
        accountPassword: password.result,
        emails: [account.email],
        roles: account.roles || ["user"],
    }, { dependsOn: stalwartDomains });
}

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
export const amiId = customAmiId;
export const stalwartVersionExport = stalwartVersion;
