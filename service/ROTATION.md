# Rotating the benchmark to a new edition

The benchmark's corpus is public, so a fixer can tune to it. The defence is
rotation: each edition is a fresh corpus under its own directory and manifest
(`benchmark/edition-01/`, then `benchmark/edition-02/`, and so on). This is what
to do on the VM when a new edition ships. It assumes the service is already
deployed per DEPLOY-CHECKLIST.md.

## What an edition is

An edition is one directory, `benchmark/edition-NN/`, with its own
`manifest.json` carrying `"edition": NN`. The service scores whichever manifest
`ASSAY_MANIFEST` points at. Nothing about an edition is baked into the container
image: the repository is copied into a fresh scoring container at run time, so
switching editions is a matter of which files are on disk and which manifest the
service reads, not a rebuild.

## Steps to rotate

Run these as the `assay` user on the VM.

1. **Pull the new edition.**

       cd /opt/assay-pilot-001
       git pull --ff-only

   The new `benchmark/edition-02/` directory arrives with the pull. Confirm it
   is there:

       ls benchmark/edition-02/manifest.json

2. **Rebuild the scorer image only if the harness or its dependencies changed.**
   A corpus-only rotation does not need a rebuild, because the corpus is not in
   the image; it is copied in at run time. Rebuild if, and only if, this pull
   changed `container/Dockerfile`, `requirements.lock.txt`, or anything under
   `harness/`:

       git log --oneline -1 -- container/Dockerfile requirements.lock.txt harness/

   If that commit is new since your last build, rebuild:

       docker build -t assay-pilot-001/scorer:1 -f container/Dockerfile .

   Otherwise skip this step.

3. **The base image digest does not change on a rotation.** The Dockerfile pins
   its base by `sha256` digest, and `requirements.lock.txt` pins the scanner and
   Python packages. Rebuilding produces the same image unless you deliberately
   change one of those files. So a new edition never silently changes the
   interpreter, the scanner, or the libc the checks run on. If you do intend to
   move the base image, that is a deliberate edit to the `FROM` line in
   `container/Dockerfile`, reviewed on its own, not a side effect of a rotation.

4. **Point the service at the new edition and restart.**

       sudo systemctl edit assay-benchmark

   Set the manifest to the new edition:

       [Service]
       Environment=ASSAY_MANIFEST=benchmark/edition-02/manifest.json

   Then:

       sudo systemctl restart assay-benchmark
       curl -s http://127.0.0.1:8080/healthz

   Health should return `{"ok": true, "scorer_image": true}`.

5. **Rebuild the site with the same API host.** The front end's corpus (the
   modules and prompts it shows) belongs to the edition, so the site is rebuilt
   from the new edition's material and redeployed. The `PUBLIC_BENCHMARK_API`
   value does not change.

## What happens to results from the previous edition

They are kept, and they never merge with the new edition. Every result row
carries the edition it was scored under (`store.py`). The leaderboard is filtered
by edition: `GET /leaderboard` shows the current edition only, and
`GET /leaderboard?edition=1` reads a past one. So on the day you rotate to
edition 2, the public leaderboard shows edition 2 (empty at first, filling as
people submit), and edition 1's results stay queryable but do not dilute or
inflate the new numbers. Nothing is deleted and nothing is migrated. The edition
column was added while the table was empty precisely so this needs no migration
later.

## Rollback

If a new edition is wrong, roll back by pointing the service at the previous
manifest and restarting. Nothing else has to change, because the previous
edition's directory is still on disk and its results are still in the store under
their edition number.

    sudo systemctl edit assay-benchmark      # set ASSAY_MANIFEST back to edition-01
    sudo systemctl restart assay-benchmark
    curl -s http://127.0.0.1:8080/healthz

If the pull itself was the problem, undo it and restart:

    cd /opt/assay-pilot-001
    git log --oneline -3                     # find the commit before the pull
    git reset --hard <that-commit>
    sudo systemctl restart assay-benchmark

Rebuild the image only if you rebuilt it in step 2; otherwise the running image
was never touched and needs nothing. The results store is never rolled back: a
result scored under an edition stays a result of that edition regardless of which
manifest is live now.
