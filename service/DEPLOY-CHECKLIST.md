# Deployment checklist

Follow this top to bottom, once. Each step has the exact command to paste and a
line telling you how to know it worked before you move on. If a check does not
match, stop on that step rather than continuing.

Two things to have ready before you start:

- a domain you control, so you can add a DNS record. This guide uses
  `benchmark-api.example.com`; replace it with your real subdomain everywhere it
  appears.
- the site's own domain, `assay.website`, which is already live.

You will be typing as `root` on a fresh server. Lines that start with `sudo` are
also fine to run as `root` (sudo just does nothing extra there).

---

### 1. Create the VM

On Hetzner Cloud (cheapest, ~5 USD/month): create a server, image **Ubuntu
24.04**, type **CX22** (2 vCPU, 4 GB). Add your SSH key when it asks. Any
provider works; you just need Ubuntu and 2 vCPU / 4 GB.

Write down the server's **public IP address**. You will use it twice.

**Worked when:** the provider shows the server as "Running" with an IP.

### 2. Log in

From your laptop terminal, replacing the IP:

    ssh root@YOUR.SERVER.IP

**Worked when:** the prompt changes to something ending in `#`.

### 3. Install Docker

    curl -fsSL https://get.docker.com | sh

**Worked when:** this prints a version:

    docker --version

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

Tell the service to accept browser calls only from the real site, and to read
the visitor's address from Caddy:

    systemctl edit assay-benchmark

An editor opens. Add exactly these lines, save, and close:

    [Service]
    Environment=ASSAY_ALLOWED_ORIGINS=https://assay.website
    Environment=ASSAY_TRUST_PROXY=1

Then restart and re-check:

    systemctl restart assay-benchmark
    sleep 3 && curl -s http://127.0.0.1:8080/healthz

**Worked when:** health returns `{"ok": true, ...}` again.

### 12. Tell the site where the service is

The website needs one build variable so its benchmark pages call your service.
In the site's Vercel project, under Settings, Environment Variables, add:

- Name **PUBLIC_BENCHMARK_API**, Value **https://benchmark-api.example.com**

Then redeploy the site (Vercel, Deployments, Redeploy). If you build the site by
hand instead, set it on the build command:

    PUBLIC_BENCHMARK_API=https://benchmark-api.example.com npm run build

**Worked when:** open `https://assay.website/benchmark/`, pick a finding, paste a
patch, and click Score. After a few seconds you land on a result page with a
verdict. That means the browser reached your service, the service scored the
patch in a container, and the result came back.

---

## If something breaks later

- **Service logs:** `journalctl -u assay-benchmark -n 50`
- **Restart the service:** `systemctl restart assay-benchmark`
- **HTTPS logs:** `journalctl -u caddy -n 50`
- **Rotating to a new edition:** see ROTATION.md.

## What this costs

About 5 USD a month for the VM on Hetzner (more on the US clouds; see README).
Nothing scales with traffic: heavy load queues behind the single scoring slot
and returns "busy", rather than costing more.
