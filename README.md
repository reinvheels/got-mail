# got-mail

Personal email service on AWS using EC2 spot instances and [Stalwart Mail Server](https://stalw.art/). Low cost (~$4-5/mo), full IMAP/SMTP client support.

## Features

- Send and receive emails using your own domain
- Full IMAP and SMTP client support (any mail client)
- SPF, DKIM, DMARC authentication
- High deliverability via SES for outbound (eu-west-1 production)
- Multi-domain support with per-domain MX, SPF, DMARC records
- Mail domains and accounts managed as Pulumi infrastructure code
- Auto-generated passwords stored in AWS SSM
- Daily EBS snapshots with configurable retention
- TLS via Let's Encrypt (ACME, auto-renewed)
- Spot interruption recovery (~1-2 min downtime)

## Architecture

Hybrid: EC2 spot for IMAP/receiving, SES for sending.

- **EC2 Spot**: Runs Stalwart via custom AMI (t4g.micro ~$2.50/mo)
- **SES**: Outbound relay via eu-west-1 (deliverability, reputation)
- **EBS**: Stalwart data persistence (RocksDB)
- **DLM**: Daily EBS snapshots (optional, 30-day retention)
- **Route 53**: DNS (MX, SPF, DKIM, DMARC, autodiscover, SRV)
- **S3**: Backups
- **SSM**: Password storage

## Quick Start

```bash
cd infra
pnpm install

# Load Pulumi backend + passphrase from SSM
eval "$(puc env)"

# Pull stack config
puc pull prod

# Deploy
pulumi up --stack prod
```

## Configuration

See `infra/Pulumi.sample.yaml` for all available options. Domains and mailboxes are defined in the Pulumi stack config (managed via `puc`, not committed to git):

```yaml
got-mail:domainName: mail.example.com
got-mail:mailDomains:
  - mail.example.com
  - example.com
got-mail:mailAccounts:
  - name: alice
    email: alice@example.com
    displayName: Alice
    roles:
      - user
```

Passwords are auto-generated and stored in SSM:

```bash
# Admin password
aws ssm get-parameter --name /got-mail/<stack>/stalwart/admin-password --with-decryption

# Account password
aws ssm get-parameter --name /got-mail/<stack>/stalwart/accounts/<name>/password --with-decryption
```

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation.
