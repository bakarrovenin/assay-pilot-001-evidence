"""The benchmark scoring API.

    POST /score        {finding, patch, tool, version} -> verdict + checks
    GET  /leaderboard  server-side aggregate, recounted from stored rows
    GET  /result/{id}  one stored result
    GET  /healthz      liveness, and whether the scorer image is present

It executes untrusted code by design, so the defences are layered:

  - the patch runs only inside the harness container, no egress, torn down
    after (harness.container), under memory, CPU, pid and timeout caps (scorer)
  - one untrusted run at a time (scorer holds a process-wide lock); this API
    admits at most MAX_WAITERS requests to the scoring stage and returns 429
    beyond that, so a flood cannot pile up unbounded work
  - per-IP rate limiting
  - input caps: patch size, finding allow-list, tool and version length
  - no secrets: this process needs no keys, tokens or credentials to run
  - nothing from the patch is persisted; only the verdict and the checks are
"""

import os
import time
from typing import Optional
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import scorer
import store

# ---- configuration (all from env, no secrets) -----------------------------
ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "ASSAY_ALLOWED_ORIGINS",
        "https://assay.website,http://localhost:4321",
    ).split(",")
    if o.strip()
]
TRUST_PROXY = os.environ.get("ASSAY_TRUST_PROXY") == "1"
RATE_PER_HOUR = int(os.environ.get("ASSAY_RATE_PER_HOUR", "12"))
MAX_WAITERS = int(os.environ.get("ASSAY_MAX_WAITERS", "3"))
MAX_PATCH_BYTES = int(os.environ.get("ASSAY_MAX_PATCH_BYTES", str(64 * 1024)))

app = FastAPI(title="Assay benchmark scorer", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.on_event("startup")
def _startup():
    store.init()


# ---- per-IP rate limit, fixed 1h window, in memory -------------------------
_hits = defaultdict(deque)


def _client_ip(request: Request) -> str:
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_ok(ip: str) -> bool:
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= RATE_PER_HOUR:
        return False
    q.append(now)
    return True


# ---- admission control: at most MAX_WAITERS in the scoring stage -----------
import threading  # noqa: E402

_waiters = 0
_waiters_lock = threading.Lock()


class _Slot:
    def __enter__(self):
        global _waiters
        with _waiters_lock:
            if _waiters >= MAX_WAITERS:
                raise _Busy()
            _waiters += 1
        return self

    def __exit__(self, *exc):
        global _waiters
        with _waiters_lock:
            _waiters -= 1


class _Busy(Exception):
    pass


# ---- request model --------------------------------------------------------
class ScoreRequest(BaseModel):
    finding: str = Field(min_length=1, max_length=8)
    patch: str = Field(min_length=1)
    tool: str = Field(min_length=1, max_length=80)
    version: str = Field(min_length=1, max_length=80)


@app.get("/healthz")
def healthz():
    from harness import container

    image = container.image_exists(container.IMAGE)
    return {"ok": True, "scorer_image": image}


@app.get("/leaderboard")
def leaderboard(edition: Optional[int] = None):
    # The current edition by default, so a rotated corpus never merges with an
    # older one. An explicit ?edition= reads a past edition.
    return store.leaderboard(edition if edition is not None else scorer.EDITION)


@app.get("/result/{rid}")
def result(rid: str):
    row = store.get(rid)
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return row


@app.post("/score")
async def score(req: ScoreRequest, request: Request):
    ip = _client_ip(request)
    if not _rate_ok(ip):
        return JSONResponse(
            {"error": "rate limit: %d scores per hour" % RATE_PER_HOUR},
            status_code=429,
        )
    if req.finding not in scorer.FINDINGS:
        return JSONResponse({"error": "unknown finding"}, status_code=400)
    if len(req.patch.encode("utf-8")) > MAX_PATCH_BYTES:
        return JSONResponse(
            {"error": "patch exceeds %d bytes" % MAX_PATCH_BYTES}, status_code=413
        )

    import anyio

    try:
        with _Slot():
            # The scorer is blocking (it drives docker), so run it off the event
            # loop. scorer.score serialises untrusted runs internally.
            result = await anyio.to_thread.run_sync(
                scorer.score, req.finding, req.patch, req.tool, req.version
            )
    except _Busy:
        return JSONResponse(
            {"error": "the scorer is busy, try again shortly"}, status_code=429
        )
    except scorer.ScoringError as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    rid, created = store.save(result, scorer.EDITION)
    return {"id": rid, "created_at": created, "result": result}
