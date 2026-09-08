"""Assay Pilot 001 harness.

Stage 1 of the harness: the corpus structure that holds fifteen findings, and
the scoring core generalised off it. Finding 1 was scored by hand first
(protocol section 7); this package is that scorer with the finding-specific
constants lifted into corpus/manifest.json, and nothing else changed.

Modules:
  corpus   load and validate corpus/manifest.json, resolve held-out material
  oracle   decide whether a held-out attack response counts as a success
  scoring  the four protocol checks, the verdict, and the evidence artifact
"""
