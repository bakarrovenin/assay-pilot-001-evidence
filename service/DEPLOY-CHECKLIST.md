# Deployment checklist

Follow this top to bottom, once. Each step has the exact command to paste and a
line telling you how to know it worked before you move on. If a check does not
match, stop on that step rather than continuing.

For AWS, read `AWS-DEPLOYMENT.md` first: it has the account-specific region,
instance sizing, security-group, SSM, backup, and billing settings. Do not reuse
other EC2 instances or their security groups.

Two things to have ready before you start:

- a domain you control, so you can add a DNS record. This guide uses
  `benchmark-api.example.com`; replace it with your real subdomain everywhere it
  appears.
- the site's own domain, `assay.website`, which is already live.

You will be typing as `root` on a fresh server. Lines that start with `sudo` are
also fine to run as `root` (sudo just does nothing extra there).

---

### 1. Create the VM

In AWS `ap-southeast-2`, create a dedicated **Ubuntu 24.04** EC2 instance of
type **t3.small** (2 vCPU, 2 GB). Use an encrypted 30 GiB gp3 root disk, attach
an SSM role with `AmazonSSMManagedInstanceCore`, and create a new security group
with only TCP 80 and 443 open to the Internet. Do not add inbound SSH or expose
ports 8080/2375. Tag it `Project=Assay` and `Name=assay-benchmark-api`.

Write down the server's **public IP address**. You will use it twice.

**Worked when:** the provider shows the server as "Running" with an IP.

### 2. Log in

Use **EC2 → Connect → Session Manager**. In the session, become root:

    sudo -i

**Worked when:** the prompt changes to something ending in `#`. If Session
Manager is unavailable, stop and fix the instance role/SSM setup; do not open
SSH to the world as a workaround.

### 3. Install Docker

    curl -fsSL https://get.docker.com | sh

**Worked when:** this prints a version:

    docker --version

Add 2 GiB of host swap for the one-time image build and operating-system
headroom. This does not change the scorer container's separate memory/swap cap:

    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab

**Worked when:** `free -h` shows about 2 GiB of swap.

### 4. Make the service user and its data folder

The service runs as a non-root user that is allowed to use Docker. Its results
database lives in a folder that survives redeploys.

    useradd -m -G docker assay
    mkdir -p /opt/assay-benchmark-data
    chown assay:docker /opt/assay-benchmark-data

**Worked when:** this prints `assay ... docker`:

    id assay

### 5. Get the code

    git clone https://github.com/bakarrovenin/assay-pilot-001-evidence /opt/assay-pilot-001
    chown -R assay:docker /opt/assay-pilot-001

**Worked when:** the service folder is there:

    ls /opt/assay-pilot-001/service/app.py

### 6. Build the scoring container image

This is the sandbox each patch runs inside. It takes a few minutes.

    cd /opt/assay-pilot-001
    sudo -u assay docker build -t assay-pilot-001/scorer:1 -f container/Dockerfile .

**Worked when:** the last line is roughly `naming to ... assay-pilot-001/scorer:1`, and:

    docker image inspect assay-pilot-001/scorer:1 > /dev/null && echo OK

prints `OK`.

### 7. Install the service's Python packages

    sudo -u assay python3 -m venv /opt/assay-pilot-001/.venv-service
    sudo -u assay /opt/assay-pilot-001/.venv-service/bin/pip install -r /opt/assay-pilot-001/service/requirements.txt

**Worked when:** the last line says `Successfully installed fastapi ... uvicorn ...`.

### 8. Turn on the service

    cp /opt/assay-pilot-001/service/assay-benchmark.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now assay-benchmark

**Worked when:** this returns `{"ok": true, "scorer_image": true}`:

    sleep 3 && curl -s http://127.0.0.1:8080/healthz

If it does not, read the log with `journalctl -u assay-benchmark -n 40` and stop
here.

### 8a. Turn on durable database backups

Follow the bucket and restricted instance-role steps in `AWS-DEPLOYMENT.md`.
Then install the systemd units and configure the bucket prefix:

    apt install -y sqlite3 awscli
    install -m 0755 /opt/assay-pilot-001/service/backup-results-to-s3.sh /usr/local/bin/assay-results-backup
    install -m 0644 /opt/assay-pilot-001/service/assay-results-backup.service /etc/systemd/system/
    install -m 0644 /opt/assay-pilot-001/service/assay-results-backup.timer /etc/systemd/system/
    printf '%s\n' 'ASSAY_BACKUP_S3_URI=s3://YOUR-PRIVATE-BUCKET/daily' > /etc/assay-results-backup.env
    chmod 0644 /etc/assay-results-backup.env
    systemctl daemon-reload
    systemctl enable --now assay-results-backup.timer
    systemctl start assay-results-backup.service

**Worked when:** `systemctl status assay-results-backup.service` succeeds and
the bucket shows a new `daily/results-*.db` object. The bucket must block
public access and the instance role should have only `s3:PutObject` to this
prefix.

### 9. Point your domain at the server (DNS)

In your domain's DNS settings, add one record:

- Type **A**, Name **benchmark-api** (so the full name is
  `benchmark-api.example.com`), Value **YOUR.SERVER.IP**.

**Worked when:** after a minute or two, this prints your server's IP:

    dig +short benchmark-api.example.com

### 10. Put HTTPS in front (Caddy)

Caddy gets a certificate automatically. Install it:

    apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update && apt install -y caddy

Then write its config (replace the domain):

    cat > /etc/caddy/Caddyfile <<'CADDY'
    benchmark-api.example.com {
        reverse_proxy 127.0.0.1:8080
    }
    CADDY
    systemctl reload caddy

**Worked when:** from your laptop (not the server), this returns the health JSON
over HTTPS:

    curl -s https://benchmark-api.example.com/healthz

The first call may take a few seconds while Caddy fetches the certificate. If it
fails, check DNS (step 9) resolved first.

### 11. Lock the service to the site origin

The shipped `assay-benchmark.service` unit already sets both of these, so if you
used it unchanged in step 8 you can skip this step. Do it only if you need a
different origin (for example a staging domain). To confirm what is in effect:

    systemctl show assay-benchmark -p Environment | tr ' ' '\n' | grep ASSAY_

To override, tell the service to accept browser calls only from the real site,
and to read the visitor's address from Caddy:

    systemctl edit assay-benchmark

An editor opens. Add exactly these lines, save, and close:

    [Service]
    Environment=ASSAY_ALLOWED_ORIGINS=https://assay.website
    Environment=ASSAY_TRUST_PROXY=1

Then restart and re-check:

    systemctl restart assay-benchmark
    sleep 3 && curl -s http://127.0.0.1:8080/healthz

**Worked when:** health returns `{"ok": true, ...}` again.

### 12. Tell the site where the service is, and turn scoring on

The website needs **two** build variables. The first points its benchmark pages
at your service; the second flips the submit step from the "notify me when
scoring opens" waitlist to the live Score form. Both are needed: with only the
first, the leaderboard reads from your service but the page still shows the
waitlist.

In the site's Vercel project, under Settings, Environment Variables, add both:

- Name **PUBLIC_BENCHMARK_API**, Value **https://benchmark-api.example.com**
- Name **PUBLIC_BENCHMARK_SCORING**, Value **1**

Then redeploy the site (Vercel, Deployments, Redeploy). If you build the site by
hand instead, set both on the build command:

    PUBLIC_BENCHMARK_API=https://benchmark-api.example.com \
      PUBLIC_BENCHMARK_SCORING=1 npm run build

**Worked when:** open `https://assay.website/benchmark/`, pick a finding, paste a
patch, and click Score. After a few seconds you land on a result page with a
verdict. That means the browser reached your service, the service scored the
patch in a container, and the result came back. (If the page still shows a
waitlist button instead of a patch box, the redeploy has not picked up
`PUBLIC_BENCHMARK_SCORING=1` yet.)

---

## If something breaks later

- **Service logs:** `journalctl -u assay-benchmark -n 50`
- **Restart the service:** `systemctl restart assay-benchmark`
- **HTTPS logs:** `journalctl -u caddy -n 50`
- **Rotating to a new edition:** see ROTATION.md.

## What this costs

AWS charges vary by region and account credit eligibility. Check the current
calculator estimate for EC2, EBS, public IPv4, snapshots, and transfer before
launch. Nothing scales with traffic: heavy load queues behind the single
scoring slot and returns "busy", rather than creating more compute instances.
