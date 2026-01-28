# got-mail

Personal email service on AWS using EC2 spot instances and [Stalwart Mail Server](https://stalw.art/). Low cost (~$4-5/mo), full IMAP/SMTP client support.

## Features

- Send and receive emails using your own domain
- Full IMAP and SMTP client support (any mail client)
- SPF, DKIM, DMARC authentication
- High deliverability via SES for outbound

## Architecture

Hybrid: EC2 spot for IMAP/receiving, SES for sending.

- **EC2 Spot**: Runs Stalwart (t4g.micro ~$2.50/mo)
- **SES**: Outbound relay (deliverability, reputation)
- **EBS**: Stalwart data persistence
- **Route 53**: DNS (MX, SPF, DKIM, DMARC)
- **S3**: Backups

See [CLAUDE.md](CLAUDE.md) for detailed architecture documentation.
