# Benchmark scoring service

A small HTTP API that scores a submitted patch against the public benchmark
corpus and stores the verdict for the leaderboard. It reuses the pilot harness
exactly: the four checks, the no-egress container and the teardown are
`harness/container.py` and `harness/scoring.py`, unchanged. This service only
hands the harness a benchmark finding and a patch, under resource caps, and
translates the evidence artifact into the shape the front end renders.

    POST /score        {finding, patch, tool, version} -> verdict + checks
    POST /feedback     {result_id, rating, message} -> saved voluntary feedback
    GET  /leaderboard  server-side aggregate, recounted from stored rows
    GET  /result/{id}  one stored result
    GET  /healthz      liveness, and whether the scorer image is present

## How the untrusted code is contained

The patch runs only inside the scoring container the harness creates:

- `--network none`, no bind mounts, image pinned by digest, removed after the
  run (`harness/container.py`).
- memory 768m with swap disabled, 1.0 CPU, 256 pids, and a 150s hard timeout
  that kills and tears down a hung run (`scorer.LIMITS`; the caps are an
  additive, default-off parameter on `score_in_container`, so the pilot and its
  parity gates are unchanged).
- one untrusted run at a time process-wide, and the API admits at most
  `ASSAY_MAX_WAITERS` requests to the scoring stage before returning 429.
- per-IP rate limit (`ASSAY_RATE_PER_HOUR`, default 12/hour).
- input caps: 64 KB patch, finding allow-list, tool/version length.
- no secrets: the process needs no keys, tokens or credentials.
- nothing from the patch is persisted. The patch is written to a temp file only
  so the harness can tar it into the container, then deleted; the database
  stores the tool, version, verdict, failure class, the four checks and a
  timestamp, never the patch text.
- voluntary result ratings and optional comments are stored in the `feedback`
  table, linked to a score ID; comments are capped at 1,000 characters, and
  client IPs are used only by an in-memory rate limiter, never persisted.

## What infrastructure this needs

One small always-on Linux VM that can run Docker. That is the whole
requirement. The API process runs on the host as a non-root user in the
`docker` group and spawns one scoring container per request; the patched code
never executes in the API process, only inside the no-egress container.

Serverless (Lambda, Cloud Run) is a poor fit: the service needs to start
Docker containers with `--network none` and resource caps, which nested
container runtimes either forbid or make fragile. A plain VM with Docker is the
simplest thing that is not a laptop.

### Recommended: one dedicated AWS VM

| Provider | Instance | vCPU / RAM | Notes |
|---|---|---|---|
| **AWS EC2, ap-southeast-2** | t3.medium | 2 / 4 GB | Dedicated host, encrypted gp3 disk, Session Manager, Caddy HTTPS |

2 vCPU / 4 GB is comfortable: scoring is single-flight and a run uses under
768 MB and one core for a few seconds. 2 GB works; 4 GB gives headroom for the
scanner. Disk: 20-40 GB (the scorer image plus SQLite). Egress is negligible.

See `AWS-DEPLOYMENT.md` for the account-specific layout. AWS pricing depends on
region and credits; check EC2, EBS, IPv4, snapshot and transfer charges in the
AWS calculator before launch. Nothing scales with traffic except that heavy
load queues behind the single-flight lock and returns 429, rather than creating
extra instances.

## Deploy

DEPLOY-CHECKLIST.md is the step-by-step version to follow on the day, with a
success check after every step. The summary below is the same path in brief.
For AWS-specific access, billing, backup and instance settings, start with
`AWS-DEPLOYMENT.md`.

On a fresh Ubuntu VM (as root, then a service user):

    # 1. Docker
    curl -fsSL https://get.docker.com | sh

    # 2. a non-root service user in the docker group
    useradd -m -G docker assay
    mkdir -p /opt/assay-benchmark-data && chown assay:docker /opt/assay-benchmark-data

    # 3. the public evidence repo (harness + benchmark corpus, no secrets)
    git clone https://github.com/bakarrovenin/assay-pilot-001-evidence /opt/assay-pilot-001
    chown -R assay:docker /opt/assay-pilot-001

    # 4. as the assay user: build the pinned scorer image once, and the API venv
    su - assay
    cd /opt/assay-pilot-001
    docker build -t assay-pilot-001/scorer:1 -f container/Dockerfile .
    python3 -m venv .venv-service
    .venv-service/bin/pip install -r service/requirements.txt
    exit

    # 5. the service
    cp /opt/assay-pilot-001/service/assay-benchmark.service /etc/systemd/system/
    systemctl enable --now assay-benchmark

The unit binds to 127.0.0.1:8080. Put a TLS reverse proxy in front (Caddy is
one line, or nginx) terminating HTTPS on a subdomain such as
`YOUR-API-HOST`, and set `ASSAY_ALLOWED_ORIGINS=https://assay.website`
so only the site can call it from a browser. Point the front end at that URL
(`PUBLIC_BENCHMARK_API` at build time).

Smoke test:

    curl https://YOUR-API-HOST/healthz
    # {"ok": true, "scorer_image": true}

## Configuration (all env, no secrets)

| Variable | Default | Meaning |
|---|---|---|
| `ASSAY_MANIFEST` | `benchmark/edition-01/manifest.json` | which corpus to score; its `edition` is stamped on every stored result |
| `ASSAY_ALLOWED_ORIGINS` | `https://assay.website,http://localhost:4321` | CORS allow-list |
| `ASSAY_TRUST_PROXY` | unset | read client IP from `X-Forwarded-For` when behind a proxy |
| `ASSAY_RATE_PER_HOUR` | `12` | per-IP score limit |
| `ASSAY_FEEDBACK_RATE_PER_HOUR` | `5` | per-IP feedback limit |
| `ASSAY_MAX_WAITERS` | `3` | requests admitted to the scoring stage before 429 |
| `ASSAY_MAX_PATCH_BYTES` | `65536` | max patch size |
| `ASSAY_BENCHMARK_DB` | `service/results.db` | SQLite path |

Score metadata is in `results`; voluntary ratings/comments are in `feedback`.
To inspect feedback from the host, query the SQLite database directly; there is
no public feedback export endpoint.

## Rotating the corpus

Each edition is its own directory and manifest. Point `ASSAY_MANIFEST` at
`benchmark/edition-02/manifest.json` when it exists, restart, and the service
scores the new edition. Every result row already carries its edition, so the
leaderboard filters by edition and editions never merge; nothing needs
migrating. The full procedure, including when an image rebuild is and is not
needed, what happens to old results, and rollback, is in ROTATION.md.
