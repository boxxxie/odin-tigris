# `odin/tigris` — Tigris S3 Object Storage & SHA-256 Asset Manifest Library for Odin

Standalone Odin (`dev-2026-09`) library for syncing static assets, computing/diffing SHA-256 manifests (`manifest.sha256`), and interacting with [Tigris](https://www.tigrisdata.com/) S3 object storage (`t3://`) via the `t3` / `tigris` CLI.

## Features

- **Native Odin SHA-256 Manifests (`build_local_manifest`, `format_manifest`, `parse_manifest`, `diff_manifests`):**
  - Walks local asset directories (`backgrounds`, `fonts`, `logos`, or arbitrary subdirectories), computes SHA-256 checksums via `core:crypto/hash`, and produces deterministic diff plans (`in_sync`, `modified`, `missing_locally`, `untracked_remote`).
- **Environment & `.env` Bucket Resolution (`resolve_bucket`):**
  - Resolves `TIGRIS_ASSETS_BUCKET` from explicit arguments, environment variables, `.env.local`, or `.env`.
- **Tigris CLI Operations (`run_assets`, `exec_t3`, `fetch_remote_manifest`):**
  - Supports incremental `sync`, `pull`, `push`, `status`, and `ls` with `--dry-run`, `--force`, and `--delete` pruning.

## Running Tests

```bash
odin check tigris -no-entry-point
odin test tests
```
