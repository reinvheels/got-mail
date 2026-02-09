# Got Mail
Personal email service on AWS using EC2 spot instances and SES. Low cost (~$4-5/mo), full IMAP/SMTP client support.

## Features
- Send and receive emails using your own domain
- Full IMAP and SMTP client support (Outlook, Thunderbird, Apple Mail, mobile)
- No built-in webmail yet (planned for 2026); use Roundcube/SnappyMail or any IMAP client
- SPF, DKIM, DMARC authentication
- High deliverability via SES for outbound

## Mail Server: Stalwart
**Website:** https://stalw.art/

- Written in Rust - fast and memory-safe
- All-in-one: SMTP, IMAP, JMAP support
- Built-in spam filtering (Sieve)
- Low resource usage (~30-50MB RAM)
- Web admin console and REST API
- No webmail yet (planned 2026); web admin console only

## Architecture

Hybrid approach: EC2 for IMAP/receiving, SES for sending (deliverability).

```
                         OUTBOUND (via SES)
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Stalwart   │────►│     SES     │────►│  Internet   │
│ (SMTP relay)│     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
                    High deliverability, managed reputation

                         INBOUND (direct)
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Internet   │────►│  Route 53   │────►│  Stalwart   │
│             │     │  (MX record)│     │  (EC2 spot) │
└─────────────┘     └─────────────┘     └─────────────┘

                         CLIENTS
┌─────────────┐     ┌─────────────┐
│ Mail Client │────►│  Stalwart   │     IMAP (993) / SMTP (465)
│ (any)       │     │  (EC2 spot) │     + Admin UI (8080)
└─────────────┘     └─────────────┘
```

### Infrastructure

```
┌─────────────────┐
│   Route 53      │
│ MX, SPF, DKIM,  │
│ DMARC, A record │
└────────┬────────┘
         │
┌────────▼────────┐
│   Elastic IP    │  ◄── Static IP for DNS
└────────┬────────┘
         │
┌────────▼────────┐
│ Security Group  │  ◄── 25, 80, 143, 443, 465, 587, 993
└────────┬────────┘
         │
┌────────▼────────┐
│   EC2 Spot      │  ◄── t4g.nano/micro/small
│   (Stalwart)    │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
┌───▼───┐ ┌───▼───┐
│  EBS  │ │  S3   │
│ (data)│ │(backup│
└───────┘ └───────┘
```

### Why Hybrid?

| Concern | EC2 Only | Hybrid (EC2 + SES) |
|---------|----------|-------------------|
| Port 25 outbound | Blocked, must request | Not needed |
| IP reputation | Unknown/risky | SES managed |
| DKIM signing | Self-managed | SES handles |
| Blacklist removal | Your problem | AWS handles |
| Warmup period | Required | None |
| IMAP clients | ✓ | ✓ |
| SMTP clients | ✓ | ✓ |

### DNS Records

| Type | Name | Value |
|------|------|-------|
| MX | @ | 10 mail.example.com |
| A | mail | (Elastic IP) |
| TXT | @ | v=spf1 include:amazonses.com ~all |
| TXT | _dmarc | v=DMARC1; p=quarantine |
| CNAME | (SES DKIM) | (SES provides 3 CNAME records) |

### TLS Certificates

SES handles TLS for outbound delivery. Stalwart needs certificates for client connections:

| Service | Port | TLS |
|---------|------|-----|
| SMTP inbound | 25 | STARTTLS (optional) |
| SMTP submission | 465/587 | Required |
| IMAP | 993 | Required |
| Admin UI | 8080 | None (HTTP) |

**Solution: Stalwart built-in ACME**

Stalwart has native Let's Encrypt support - auto-obtains and renews certificates.

```toml
[acme."letsencrypt"]
directory = "https://acme-v02.api.letsencrypt.org/directory"
contact = ["mailto:admin@example.com"]
domains = ["mail.example.com"]
```

Stalwart uses TLS-ALPN-01 challenge via port 443. Port 80 is also open for ACME fallback. Certs are stored in RocksDB on EBS, so they persist across instance replacements.

### Spot Instance Strategy

ASG uses a mixed instances policy with `price-capacity-optimized` allocation across multiple instance types (t4g.nano, t4g.micro, t4g.small). This prefers the cheapest pool with available capacity.

A nightly recycle (00:00 UTC terminate, 00:02 UTC relaunch) ensures the ASG can switch to a cheaper pool when capacity returns.

**Spot interruption recovery:**

1. Spot interruption (2 min warning)
2. ASG launches new spot instance from cheapest available pool
3. EBS volume reattached
4. Elastic IP reassociated
5. Stalwart resumes (~1-2 min total downtime)

For personal email, this is acceptable - mail queues retry.

**Check instance type history (via CloudTrail, 90 days):**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "2026-01-01T00:00:00Z" \
  --query 'Events[*].CloudTrailEvent' --output json --region eu-central-1 \
  | jq -r '.[] | fromjson | select(.responseElements.instancesSet.items[]?.tagSet.items[]?.value == "got-mail-instance") | "\(.eventTime) \(.responseElements.instancesSet.items[0].instanceType)"'
```

### Cost Estimate

| Component | Monthly |
|-----------|---------|
| EC2 spot (t4g.nano/micro/small) | ~$0.90-5.00 |
| EBS 10GB gp3 | ~$0.80 |
| EBS snapshots (daily, 30d) | ~$0.10 |
| Elastic IP (public IPv4) | ~$3.60 |
| SES ($0.10/1000) | ~$0.10 |
| Data transfer | ~$0.50 |
| **Total** | **~$6-11/mo** |

## Implementation

Pulumi (TypeScript) in `infra/` directory. Package manager: pnpm.

### Stack Config (`puc` / SSM)

Stack config is managed via `puc` (pulumi-config) and stored in AWS SSM, not in git.

```bash
puc env           # print PULUMI_BACKEND_URL and PULUMI_CONFIG_PASSPHRASE
puc pull prod     # pull config to Pulumi.prod.yaml
puc push prod     # push config to SSM
```

Key config values:
- `got-mail:domainName` — mail server hostname (e.g. `mail.gothub.io`)
- `got-mail:mailDomains` — list of mail domains to create in Stalwart (MX/SPF/DMARC per domain)
- `got-mail:mailAccounts` — list of mailbox accounts (name, email, displayName, roles)
- `got-mail:keyName` — EC2 key pair name for SSH access
- `got-mail:openSshPort` — whether to open port 22
- `got-mail:enableSnapshots` — enable daily EBS snapshots via DLM (default: false)
- `got-mail:snapshotRetentionDays` — number of daily snapshots to retain (default: 30)
- `got-mail:instanceType` — EC2 instance type (default: t4g.micro)
- `got-mail:stalwartVersion` — Stalwart version to install (default: latest)

### Passwords & Secrets

All passwords are generated via `@pulumi/random` and stored in SSM:

```
/got-mail/{stack}/stalwart/admin-password           → Stalwart admin password (32 chars)
/got-mail/{stack}/stalwart/accounts/{name}/password  → account password (24 chars)
```

The admin password is also baked into the AMI config at build time.

### Components
- EC2 spot instance (ASG size=1) with Stalwart in default VPC
- Custom AMI baked via builder instance (Stalwart binary + config pre-installed)
- EBS volume for data persistence (retainOnDelete)
- Elastic IP
- Security group (25, 80, 143, 443, 465, 587, 993, 8080)
- SES domain identity + DKIM (eu-central-1 + eu-west-1 for production sending)
- IAM user with SMTP credentials for SES relay (eu-west-1)
- Route53 records (per-domain MX, SPF, DMARC; DKIM, autodiscover, autoconfig, SRV)
- S3 bucket for backups
- IAM role for EC2 (EIP association, EBS attach, S3 backup)
- DLM lifecycle policy for daily EBS snapshots (optional)
- Stalwart dynamic provider (`stalwart.ts`) — Pulumi CRUD for domains and accounts via REST API

### Files
- `index.ts` — main infrastructure (AWS resources, AMI builder, Stalwart resources)
- `stalwart.ts` — Pulumi dynamic provider for Stalwart Domain and Account resources
- `Pulumi.yaml` — project config
- `Pulumi.prod.yaml` — stack config (gitignored, managed via `puc`)
