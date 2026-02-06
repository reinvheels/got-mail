# got-mail

Personal email service on AWS using EC2 spot instances and [Stalwart Mail Server](https://stalw.art/). Low cost (~$4-5/mo), full IMAP/SMTP client support.

## Features

- Send and receive emails using your own domain
- Full IMAP and SMTP client support (any mail client)
- SPF, DKIM, DMARC authentication
- High deliverability via SES for outbound
- Mail domains and accounts managed as Pulumi infrastructure code
- Auto-generated passwords stored in AWS SSM

## Architecture

Hybrid: EC2 spot for IMAP/receiving, SES for sending.

- **EC2 Spot**: Runs Stalwart via custom AMI (t4g.micro ~$2.50/mo)
- **SES**: Outbound relay (deliverability, reputation)
- **EBS**: Stalwart data persistence
- **Route 53**: DNS (MX, SPF, DKIM, DMARC, autodiscover)
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

Domains and mailboxes are defined in the Pulumi stack config (managed via `puc`, not committed to git):

```yaml
got-mail:mailDomains:
  - example.com
got-mail:mailAccounts:
  - name: alice
    email: alice@example.com
    displayName: Alice
    roles:
      - user
```

Passwords are auto-generated and stored in SSM at `/got-mail/{stack}/stalwart/...`.

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation.
