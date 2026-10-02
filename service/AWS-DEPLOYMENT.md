# AWS deployment for the public Assay scorer

This deploys the scoring API separately from the website and from any other
workloads in the AWS account. The current account console is in
`ap-southeast-2` (Sydney). Do not reuse the `rovenin-bots` or `rovenin-rescue`
instances or their security groups.

## Instance settings

- Region: `ap-southeast-2`
- AMI: Ubuntu Server 24.04 LTS, 64-bit x86
- Size: `t3.small` (2 vCPU, 2 GiB RAM) with 2 GiB host swap; scoring is
  single-flight and the harness caps each scoring container at 768 MiB. This
  keeps the host small while leaving room for Docker and the API.
- Root disk: 30 GiB `gp3`, encrypted; keep the SQLite database under
  `/opt/assay-benchmark-data` so it is easy to back up independently
- Name and tag: `assay-benchmark-api`, with `Project=Assay`
- Public access: TCP 80 and 443 from the Internet; no public SSH rule
- Administration: attach an instance role with `AmazonSSMManagedInstanceCore`
  and a separate inline policy granting only `s3:PutObject` to the backup
  bucket's `daily/*` prefix; use Systems Manager Session Manager
- Public IPv4: dynamic is sufficient for the first setup; set DNS after launch

Use a dedicated security group with only those inbound rules. The API itself
binds to loopback port 8080 and Caddy provides HTTPS. Do not expose 8080 or
Docker's socket. Keep this host dedicated: the service user belongs to the
`docker` group and the public API runs untrusted submissions in Docker.

AWS currently lists `t3.small` among Free Tier eligible sizes for newer
accounts, but confirm the account plan and remaining credit in AWS Billing
before launch. Free-plan limits and paid-plan charges differ.

## Billing and credits

The account owner reports $100 in AWS signup credit. Check the remaining balance
and expiration in **Billing and Cost Management → Credits** before launch. Add an
AWS Budget notification for the `Project=Assay` cost tag after activating that
cost-allocation tag. Budgets notify; they do not prevent charges, and credits
can expire or exclude some services. Check the AWS calculator for the current
region-specific EC2, EBS, public IPv4, snapshot, and data-transfer rates before
launching. Do not create NAT gateways, load balancers, or paid support plans for
this single-host deployment.

## Durable results and feedback

The service stores score metadata and voluntary feedback in SQLite at
`/opt/assay-benchmark-data/results.db`. Submitted patches are never written to
the database. Feedback has a rating, optional comment, submission ID, and UTC
timestamp; client IPs are only used for an in-memory rate limit and are not
persisted. Back up this directory daily to a private, encrypted S3 bucket using
the provided systemd service, timer, and backup script. Enable bucket versioning
and block public access. The instance role may only add objects in `daily/*`;
it cannot read, delete, or make objects public. Keep the EBS root disk encrypted
as well. The script uses SQLite's online backup operation, so a score arriving
during a backup does not produce a partial database.

Inspect records over Session Manager:

```sh
sqlite3 /opt/assay-benchmark-data/results.db \
  'SELECT created_at, finding, tool, version, verdict FROM results ORDER BY created_at DESC;'
sqlite3 /opt/assay-benchmark-data/results.db \
  'SELECT created_at, result_id, rating, message FROM feedback ORDER BY created_at DESC;'
```

Feedback comments are retained until manually removed. They are limited to
1,000 characters; the form asks visitors not to include secrets or personal
information. Do not add contact details or raw patch content to this database.

## Go-live order

1. Create the isolated EC2 instance and security group above, with an SSM role.
2. Use Session Manager to follow `DEPLOY-CHECKLIST.md` from installing Docker.
3. Create a private S3 bucket with block-public-access, default encryption,
   versioning, and a 90-day lifecycle for old versions. Attach the restricted
   S3 put policy to the instance role. Install `sqlite3` and `awscli`, configure
   `/etc/assay-results-backup.env` with the bucket prefix, install the provided
   backup script and systemd units, and verify an object arrives before turning
   on public scoring.
4. Add `benchmark-api.assay.website` DNS to the instance IPv4 address and enable
   Caddy HTTPS.
5. Set `ASSAY_ALLOWED_ORIGINS=https://assay.website` and
   `ASSAY_TRUST_PROXY=1`; verify `/healthz` over HTTPS.
6. Configure Vercel production build variables
   `PUBLIC_BENCHMARK_API=https://benchmark-api.assay.website` and
   `PUBLIC_BENCHMARK_SCORING=1`, then redeploy the site.
7. Submit one real patch and confirm its result appears in `/leaderboard`; send
   one feedback entry and verify it appears in the `feedback` table.

The current AWS browser session is available, but creating the billable EC2
instance and public security group remains a deliberate final console action.
