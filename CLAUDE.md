# Got Mail
Personal email service on AWS using EC2 spot instances and SES. Low cost (~$4-5/mo), full IMAP/SMTP client support.

## Features
- Send and receive emails using your own domain
- Full IMAP and SMTP client support (Outlook, Thunderbird, Apple Mail, mobile)
- Webmail included (Stalwart webmail)
- SPF, DKIM, DMARC authentication
- High deliverability via SES for outbound

## Mail Server: Stalwart
**Website:** https://stalw.art/

- Written in Rust - fast and memory-safe
- All-in-one: SMTP, IMAP, JMAP support
- Built-in spam filtering (Sieve)
- Low resource usage (~30-50MB RAM)
- Web admin console and REST API
- Webmail client included

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
│ (any)       │     │  (EC2 spot) │     + Webmail (443)
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
│   EC2 Spot      │  ◄── t4g.micro (~$2.50/mo)
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
| Webmail | 443 | Required |

**Solution: Stalwart built-in ACME**

Stalwart has native Let's Encrypt support - auto-obtains and renews certificates.

```toml
[acme."letsencrypt"]
directory = "https://acme-v02.api.letsencrypt.org/directory"
contact = ["mailto:admin@example.com"]
domains = ["mail.example.com"]
```

Port 80 must be open temporarily for ACME HTTP-01 challenge during cert issuance/renewal.

### Spot Interruption Recovery

EC2 spot instances can be interrupted (~5% monthly). Recovery via ASG:

1. Spot interruption (2 min warning)
2. ASG launches new spot instance
3. EBS volume reattached
4. Elastic IP reassociated
5. Stalwart resumes (~1-2 min total downtime)

For personal email, this is acceptable - mail queues retry.

### Cost Estimate

| Component | Monthly |
|-----------|---------|
| EC2 t4g.micro spot | ~$2.50 |
| EBS 10GB gp3 | ~$0.80 |
| Elastic IP | Free (attached) |
| SES ($0.10/1000) | ~$0.10 |
| Data transfer | ~$0.50 |
| **Total** | **~$4-5/mo** |

## Implementation

Pulumi (TypeScript) in `infra/` directory. Package manager: pnpm.

### Components to create
- VPC with public subnet
- EC2 spot instance (ASG size=1) with Stalwart
- EBS volume for data persistence
- Elastic IP
- Security group (25, 80, 143, 443, 465, 587, 993)
- SES domain identity + DKIM
- Route53 records (MX, SPF, DKIM, DMARC)
- S3 bucket for backups
- IAM role for EC2 (SES send, S3 backup)
